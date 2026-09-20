import base64
import json
import logging
import math
import os
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import azure.functions as func
import msal
import requests
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient, ContentSettings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

app = func.FunctionApp()

GRAPH_ROOT = "https://graph.microsoft.com"
HTTP_TIMEOUT = 30


def _env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _bool(name: str, default: bool = False) -> bool:
    return _env(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _csv(name: str) -> List[str]:
    return [x.strip().lower() for x in _env(name, "").split(",") if x.strip()]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def safe_key(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def get_blob_service() -> BlobServiceClient:
    account_url = _env("DATA_STORAGE_BLOB_URL")
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    return BlobServiceClient(account_url=account_url, credential=credential)


def get_container():
    return get_blob_service().get_container_client(_env("DATA_CONTAINER", "behavior-guard"))


def load_json_blob(path: str, default: Any = None) -> Any:
    try:
        raw = get_container().download_blob(path).readall()
        return json.loads(raw)
    except ResourceNotFoundError:
        return default


def save_json_blob(path: str, payload: Any, overwrite: bool = True) -> None:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    get_container().upload_blob(
        name=path,
        data=data,
        overwrite=overwrite,
        content_settings=ContentSettings(content_type="application/json"),
    )


def append_event_blob(prefix: str, payload: Dict[str, Any]) -> str:
    now = utcnow()
    name = f"{prefix}/{now:%Y/%m/%d/%H}/{now:%M%S}-{uuid.uuid4()}.json"
    save_json_blob(name, payload, overwrite=False)
    return name


def get_graph_credential() -> Dict[str, str]:
    vault_url = _env("KEY_VAULT_URL")
    secret_name = _env("GRAPH_CERT_SECRET_NAME")
    secret = SecretClient(
        vault_url=vault_url,
        credential=DefaultAzureCredential(exclude_interactive_browser_credential=True),
    ).get_secret(secret_name)

    value = secret.value or ""
    raw: bytes
    if "BEGIN" in value:
        raw = value.encode("utf-8")
    else:
        raw = base64.b64decode(value)

    private_key = cert = None
    try:
        private_key, cert, _ = pkcs12.load_key_and_certificates(raw, None)
    except ValueError:
        private_key = serialization.load_pem_private_key(raw, password=None)
        cert_blocks = raw.split(b"-----END CERTIFICATE-----")
        if cert_blocks and b"BEGIN CERTIFICATE" in cert_blocks[0]:
            cert_pem = cert_blocks[0] + b"-----END CERTIFICATE-----\n"
            cert = x509.load_pem_x509_certificate(cert_pem)

    if private_key is None or cert is None:
        raise RuntimeError("Key Vault certificate secret did not contain an exportable private key and certificate")

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    thumbprint = cert.fingerprint(hashes.SHA1()).hex()
    return {"private_key": private_pem, "thumbprint": thumbprint, "public_certificate": cert_pem}


def graph_token() -> str:
    cca = msal.ConfidentialClientApplication(
        client_id=_env("GRAPH_CLIENT_ID"),
        authority=f"https://login.microsoftonline.com/{_env('TENANT_ID')}",
        client_credential=get_graph_credential(),
    )
    result = cca.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        raise RuntimeError(f"Graph token acquisition failed: {result.get('error_description') or result}")
    return result["access_token"]


def graph_get_all(url: str, token: str, max_pages: int = 100) -> Iterable[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {token}", "Prefer": "include-unknown-enum-members"}
    pages = 0
    while url and pages < max_pages:
        response = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if response.status_code == 429:
            time.sleep(min(int(response.headers.get("Retry-After", "5")), 30))
            continue
        response.raise_for_status()
        body = response.json()
        for item in body.get("value", []):
            yield item
        url = body.get("@odata.nextLink")
        pages += 1


def graph_post(path: str, token: str) -> requests.Response:
    response = requests.post(
        f"{GRAPH_ROOT}/v1.0/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=HTTP_TIMEOUT,
    )
    return response


def graph_patch(path: str, token: str, body: Dict[str, Any]) -> requests.Response:
    return requests.patch(
        f"{GRAPH_ROOT}/v1.0/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body,
        timeout=HTTP_TIMEOUT,
    )


def normalized_signin(s: Dict[str, Any]) -> Dict[str, Any]:
    device = s.get("deviceDetail") or {}
    location = s.get("location") or {}
    status = s.get("status") or {}
    return {
        "id": s.get("id"),
        "createdDateTime": s.get("createdDateTime"),
        "userId": s.get("userId"),
        "userPrincipalName": s.get("userPrincipalName"),
        "appId": s.get("appId"),
        "appDisplayName": s.get("appDisplayName"),
        "resourceId": s.get("resourceId"),
        "resourceDisplayName": s.get("resourceDisplayName"),
        "clientAppUsed": s.get("clientAppUsed"),
        "authenticationProtocol": s.get("authenticationProtocol"),
        "authenticationRequirement": s.get("authenticationRequirement"),
        "incomingTokenType": s.get("incomingTokenType"),
        "isInteractive": s.get("isInteractive"),
        "signInEventTypes": s.get("signInEventTypes") or [],
        "conditionalAccessStatus": s.get("conditionalAccessStatus"),
        "ipAddress": s.get("ipAddress"),
        "userAgent": s.get("userAgent"),
        "country": location.get("countryOrRegion"),
        "state": location.get("state"),
        "city": location.get("city"),
        "deviceId": device.get("deviceId"),
        "operatingSystem": device.get("operatingSystem"),
        "browser": device.get("browser"),
        "isManaged": device.get("isManaged"),
        "isCompliant": device.get("isCompliant"),
        "trustType": device.get("trustType"),
        "riskLevelAggregated": s.get("riskLevelAggregated"),
        "riskLevelDuringSignIn": s.get("riskLevelDuringSignIn"),
        "riskState": s.get("riskState"),
        "riskEventTypes": s.get("riskEventTypes_v2") or s.get("riskEventTypes") or [],
        "statusErrorCode": status.get("errorCode"),
        "statusFailureReason": status.get("failureReason"),
        "correlationId": s.get("correlationId"),
        "originalRequestId": s.get("originalRequestId"),
    }


def empty_profile(event: Dict[str, Any]) -> Dict[str, Any]:
    created = event.get("createdDateTime") or iso(utcnow())
    return {
        "version": 1,
        "userId": event.get("userId"),
        "userPrincipalName": event.get("userPrincipalName"),
        "firstSeen": created,
        "lastSeen": created,
        "successfulEvents": 0,
        "apps": {},
        "resources": {},
        "authProtocols": {},
        "clientApps": {},
        "countries": {},
        "operatingSystems": {},
        "browsers": {},
        "incomingTokenTypes": {},
        "hoursOfWeek": {},
        "managed": {"true": 0, "false": 0, "unknown": 0},
        "compliant": {"true": 0, "false": 0, "unknown": 0},
        "recent": [],
    }


def inc(map_obj: Dict[str, int], value: Any) -> None:
    key = str(value if value not in (None, "") else "unknown")
    map_obj[key] = int(map_obj.get(key, 0)) + 1


def how(v: Any) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    return "unknown"


def hour_of_week(dt: datetime) -> str:
    return str(dt.weekday() * 24 + dt.hour)


def update_profile(profile: Dict[str, Any], event: Dict[str, Any]) -> None:
    dt = parse_dt(event.get("createdDateTime")) or utcnow()
    profile["lastSeen"] = event.get("createdDateTime") or iso(dt)
    if event.get("statusErrorCode") not in (0, "0", None):
        return
    profile["successfulEvents"] = int(profile.get("successfulEvents", 0)) + 1
    inc(profile["apps"], event.get("appId") or event.get("appDisplayName"))
    inc(profile["resources"], event.get("resourceId") or event.get("resourceDisplayName"))
    inc(profile["authProtocols"], event.get("authenticationProtocol"))
    inc(profile["clientApps"], event.get("clientAppUsed"))
    inc(profile["countries"], event.get("country"))
    inc(profile["operatingSystems"], event.get("operatingSystem"))
    inc(profile["browsers"], event.get("browser"))
    inc(profile["incomingTokenTypes"], event.get("incomingTokenType"))
    inc(profile["hoursOfWeek"], hour_of_week(dt))
    profile["managed"][how(event.get("isManaged"))] += 1
    profile["compliant"][how(event.get("isCompliant"))] += 1
    recent = profile.setdefault("recent", [])
    recent.append({
        "t": event.get("createdDateTime"),
        "ip": event.get("ipAddress"),
        "country": event.get("country"),
        "app": event.get("appId") or event.get("appDisplayName"),
        "interactive": event.get("isInteractive"),
    })
    del recent[:-20]


def profile_age_days(profile: Dict[str, Any], event_dt: datetime) -> float:
    first = parse_dt(profile.get("firstSeen")) or event_dt
    return max((event_dt - first).total_seconds() / 86400.0, 0.0)


def seen_count(profile: Dict[str, Any], key: str, value: Any) -> int:
    map_obj = profile.get(key, {})
    k = str(value if value not in (None, "") else "unknown")
    return int(map_obj.get(k, 0))


def score_event(profile: Dict[str, Any], event: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    score = 0
    reasons: List[Dict[str, Any]] = []
    dt = parse_dt(event.get("createdDateTime")) or utcnow()
    events = int(profile.get("successfulEvents", 0))
    min_events = _int("MIN_BASELINE_EVENTS", 25)

    def add(points: int, code: str, detail: str):
        nonlocal score
        score += points
        reasons.append({"points": points, "code": code, "detail": detail})

    protocol = (event.get("authenticationProtocol") or "unknown").lower()
    if "devicecode" in protocol.replace("_", "").replace("-", "") and seen_count(profile, "authProtocols", event.get("authenticationProtocol")) == 0:
        add(55, "never_seen_device_code", "Successful device-code authentication was not present in this user's learned baseline.")

    app_key = event.get("appId") or event.get("appDisplayName")
    if app_key and events >= min_events and seen_count(profile, "apps", app_key) == 0:
        add(20, "new_application", f"First observed successful sign-in to application {event.get('appDisplayName') or app_key}.")

    country = event.get("country")
    if country and events >= min_events and seen_count(profile, "countries", country) == 0:
        add(20, "new_country", f"First observed successful sign-in from country/region {country}.")

    browser = event.get("browser")
    if browser and events >= min_events and seen_count(profile, "browsers", browser) == 0:
        add(10, "new_browser", f"First observed browser {browser}.")

    os_name = event.get("operatingSystem")
    if os_name and events >= min_events and seen_count(profile, "operatingSystems", os_name) == 0:
        add(10, "new_os", f"First observed operating system {os_name}.")

    how_key = hour_of_week(dt)
    how_count = seen_count(profile, "hoursOfWeek", how_key)
    if events >= max(min_events, 50) and how_count == 0:
        add(12, "new_time_window", f"No learned successful sign-ins in this hour-of-week bucket ({how_key}).")

    historically_managed = int(profile.get("managed", {}).get("true", 0))
    historically_unmanaged = int(profile.get("managed", {}).get("false", 0))
    if event.get("isManaged") is False and historically_managed >= 10 and historically_unmanaged == 0:
        add(20, "first_unmanaged_device", "User's learned successful sign-ins were managed-device only.")

    risk = (event.get("riskLevelAggregated") or "none").lower()
    if risk == "high":
        add(60, "entra_high_risk", "Microsoft Entra reported aggregated sign-in risk as high.")
    elif risk == "medium":
        add(35, "entra_medium_risk", "Microsoft Entra reported aggregated sign-in risk as medium.")

    if event.get("riskEventTypes"):
        add(20, "risk_events_present", f"Entra risk events present: {', '.join(map(str, event['riskEventTypes']))}")

    # Possible token/session replay / AiTM heuristic. This is deliberately labeled heuristic, not definitive.
    recent = profile.get("recent", [])
    for prev in reversed(recent[-8:]):
        prev_dt = parse_dt(prev.get("t"))
        if not prev_dt:
            continue
        delta = abs((dt - prev_dt).total_seconds())
        if delta > 1800:
            break
        different_ip = prev.get("ip") and event.get("ipAddress") and prev.get("ip") != event.get("ipAddress")
        different_country = prev.get("country") and country and prev.get("country") != country
        same_app = prev.get("app") and app_key and prev.get("app") == app_key
        if same_app and different_ip and different_country:
            add(35, "possible_session_replay_or_aitm", "Same application was used from a different IP and country within 30 minutes. Correlate with Defender XDR and device/network telemetry.")
            break

    if event.get("isInteractive") is False and country and events >= min_events and seen_count(profile, "countries", country) == 0:
        add(15, "new_country_noninteractive", "A non-interactive sign-in appeared from a country not present in the learned baseline.")

    return min(score, 100), reasons


def bake_in_complete(profile: Dict[str, Any], event_dt: datetime) -> bool:
    return (
        profile_age_days(profile, event_dt) >= _int("BAKE_IN_DAYS", 14)
        and int(profile.get("successfulEvents", 0)) >= _int("MIN_BASELINE_EVENTS", 25)
    )


def is_protected(event: Dict[str, Any]) -> bool:
    protected_ids = set(_csv("PROTECTED_USER_IDS"))
    protected_upns = set(_csv("PROTECTED_UPNS"))
    return str(event.get("userId") or "").lower() in protected_ids or str(event.get("userPrincipalName") or "").lower() in protected_upns


def enforce(token: str, event: Dict[str, Any], score: int, reasons: List[Dict[str, Any]]) -> Dict[str, Any]:
    result = {
        "attempted": False,
        "action": None,
        "success": False,
        "details": [],
    }
    if not _bool("ENFORCEMENT_ENABLED", False):
        result["details"].append("Enforcement disabled")
        return result
    if is_protected(event):
        result["details"].append("User is on the protected-user exclusion list")
        return result
    threshold = _int("ENFORCEMENT_SCORE_THRESHOLD", 80)
    if score < threshold:
        result["details"].append(f"Score {score} below enforcement threshold {threshold}")
        return result

    user_id = event.get("userId")
    if not user_id:
        result["details"].append("Missing userId")
        return result

    mode = _env("ENFORCEMENT_ACTION", "revokeSessions").strip()
    result["attempted"] = True
    result["action"] = mode

    if mode in {"revokeSessions", "disableAndRevoke"}:
        r = graph_post(f"users/{quote(user_id)}/revokeSignInSessions", token)
        result["details"].append(f"revokeSignInSessions HTTP {r.status_code}")
        if not r.ok:
            result["details"].append(r.text[:500])

    disable_ok = True
    if mode == "disableAndRevoke":
        r2 = graph_patch(f"users/{quote(user_id)}", token, {"accountEnabled": False})
        result["details"].append(f"disable account HTTP {r2.status_code}")
        if not r2.ok:
            disable_ok = False
            result["details"].append(r2.text[:500])

    result["success"] = all("HTTP 2" in x for x in result["details"] if "HTTP" in x) and disable_ok
    return result


def collect_signins(token: str, since: datetime) -> List[Dict[str, Any]]:
    use_beta = _bool("ENABLE_BETA_NONINTERACTIVE", False)
    version = "beta" if use_beta else "v1.0"
    filter_expr = f"createdDateTime ge {iso(since)}"
    if use_beta:
        filter_expr += " and signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')"
    url = f"{GRAPH_ROOT}/{version}/auditLogs/signIns?$filter={quote(filter_expr, safe="()': ")}&$orderby=createdDateTime asc&$top=1000"
    return [normalized_signin(x) for x in graph_get_all(url, token)]


def normalize_oauth_audit(a: Dict[str, Any]) -> Dict[str, Any]:
    initiated = (a.get("initiatedBy") or {}).get("user") or {}
    targets = a.get("targetResources") or []
    return {
        "id": a.get("id"),
        "activityDateTime": a.get("activityDateTime"),
        "activityDisplayName": a.get("activityDisplayName"),
        "category": a.get("category"),
        "result": a.get("result"),
        "resultReason": a.get("resultReason"),
        "correlationId": a.get("correlationId"),
        "userId": initiated.get("id"),
        "userPrincipalName": initiated.get("userPrincipalName"),
        "initiatedByApp": (a.get("initiatedBy") or {}).get("app"),
        "targetResources": targets,
    }


def collect_oauth_audits(token: str, since: datetime) -> List[Dict[str, Any]]:
    # Captures consent and permission grant/removal activity from Entra directory audit logs.
    filter_expr = f"activityDateTime ge {iso(since)} and category eq 'ApplicationManagement'"
    url = f"{GRAPH_ROOT}/v1.0/auditLogs/directoryAudits?$filter={quote(filter_expr, safe="' :")}&$orderby=activityDateTime asc&$top=100"
    interesting = {
        "Consent to application",
        "Add delegated permission grant",
        "Remove delegated permission grant",
        "Add app role assignment to service principal",
        "Remove app role assignment from service principal",
        "Add service principal credentials",
        "Remove service principal credentials",
    }
    out = []
    for a in graph_get_all(url, token):
        if a.get("activityDisplayName") in interesting:
            out.append(normalize_oauth_audit(a))
    return out


def oauth_profile_default(audit: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "version": 1,
        "userId": audit.get("userId"),
        "userPrincipalName": audit.get("userPrincipalName"),
        "firstSeen": audit.get("activityDateTime") or iso(utcnow()),
        "lastSeen": audit.get("activityDateTime") or iso(utcnow()),
        "events": 0,
        "activities": {},
        "targetApps": {},
    }


def oauth_target_keys(audit: Dict[str, Any]) -> List[str]:
    keys = []
    for t in audit.get("targetResources") or []:
        key = t.get("id") or t.get("displayName")
        if key:
            keys.append(str(key))
    return keys


def oauth_bake_in_complete(profile: Dict[str, Any], event_dt: datetime) -> bool:
    first = parse_dt(profile.get("firstSeen")) or event_dt
    age = max((event_dt - first).total_seconds() / 86400.0, 0.0)
    return age >= _int("BAKE_IN_DAYS", 14) and int(profile.get("events", 0)) >= _int("MIN_OAUTH_BASELINE_EVENTS", 3)


def score_oauth(profile: Dict[str, Any], audit: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    score = 0
    reasons: List[Dict[str, Any]] = []
    activity = audit.get("activityDisplayName") or "unknown"
    previous_activity = int(profile.get("activities", {}).get(activity, 0))
    targets = oauth_target_keys(audit)

    def add(points: int, code: str, detail: str):
        nonlocal score
        score += points
        reasons.append({"points": points, "code": code, "detail": detail})

    if activity == "Consent to application" and previous_activity == 0:
        add(45, "first_user_oauth_consent", "This user's mature OAuth baseline contains no prior successful 'Consent to application' event.")
    for key in targets:
        if int(profile.get("targetApps", {}).get(key, 0)) == 0:
            add(20, "new_oauth_target_app", f"First learned OAuth/application-management event involving target {key}.")
            break
    reason = (audit.get("resultReason") or "").lower()
    if "risky application" in reason or "risky app" in reason:
        add(40, "entra_risky_application_reason", f"Entra audit result reason referenced a risky application: {audit.get('resultReason')}")
    return min(score, 100), reasons


def update_oauth_profile(profile: Dict[str, Any], audit: Dict[str, Any]) -> None:
    profile["lastSeen"] = audit.get("activityDateTime") or iso(utcnow())
    if str(audit.get("result") or "").lower() not in {"success", "succeeded"}:
        return
    profile["events"] = int(profile.get("events", 0)) + 1
    inc(profile["activities"], audit.get("activityDisplayName"))
    for key in oauth_target_keys(audit):
        inc(profile["targetApps"], key)


def process() -> Dict[str, Any]:
    token = graph_token()
    state = load_json_blob("state/checkpoint.json", {}) or {}
    overlap_minutes = _int("QUERY_OVERLAP_MINUTES", 5)
    fallback_minutes = _int("INITIAL_LOOKBACK_MINUTES", 60)
    last = parse_dt(state.get("lastSignInCheckpoint"))
    since = (last - timedelta(minutes=overlap_minutes)) if last else (utcnow() - timedelta(minutes=fallback_minutes))

    signins = collect_signins(token, since)
    oauth = collect_oauth_audits(token, since)
    max_actions = _int("MAX_ENFORCEMENT_ACTIONS_PER_RUN", 3)
    actions_used = 0
    alerts = 0

    seen_ids = set(load_json_blob("state/recent-event-ids.json", []) or [])
    new_seen: List[str] = []

    for event in signins:
        event_id = event.get("id")
        if event_id and event_id in seen_ids:
            continue
        if event_id:
            new_seen.append(event_id)

        append_event_blob("telemetry/signins", event)
        user_id = event.get("userId")
        if not user_id:
            continue
        profile_path = f"profiles/{safe_key(user_id)}.json"
        profile = load_json_blob(profile_path, None) or empty_profile(event)
        event_dt = parse_dt(event.get("createdDateTime")) or utcnow()
        complete = bake_in_complete(profile, event_dt)
        score, reasons = score_event(profile, event) if complete else (0, [{"points": 0, "code": "bake_in", "detail": "Learning-only: bake-in window or minimum event count is not complete."}])

        if complete and score >= _int("ALERT_SCORE_THRESHOLD", 45):
            alerts += 1
            alert = {
                "schemaVersion": 1,
                "detectedAt": iso(utcnow()),
                "userId": user_id,
                "userPrincipalName": event.get("userPrincipalName"),
                "score": score,
                "reasons": reasons,
                "event": event,
                "label": "possible_aitm_or_auth_anomaly" if any(r["code"] == "possible_session_replay_or_aitm" for r in reasons) else "authentication_behavior_anomaly",
                "enforcement": {"attempted": False, "details": ["Per-run action cap reached"]} if actions_used >= max_actions else None,
            }
            if actions_used < max_actions:
                enforcement = enforce(token, event, score, reasons)
                alert["enforcement"] = enforcement
                if enforcement.get("attempted"):
                    actions_used += 1
                    append_event_blob("actions", {"detectedAt": alert["detectedAt"], "userId": user_id, "upn": event.get("userPrincipalName"), "score": score, "reasons": reasons, "result": enforcement})
            append_event_blob("alerts", alert)

        update_profile(profile, event)
        save_json_blob(profile_path, profile)

    for audit in oauth:
        append_event_blob("telemetry/oauth-audit", audit)
        user_id = audit.get("userId")
        if not user_id:
            continue
        event_dt = parse_dt(audit.get("activityDateTime")) or utcnow()
        oauth_path = f"oauth-profiles/{safe_key(user_id)}.json"
        oauth_profile = load_json_blob(oauth_path, None) or oauth_profile_default(audit)
        if oauth_bake_in_complete(oauth_profile, event_dt) and str(audit.get("result") or "").lower() in {"success", "succeeded"}:
            oauth_score, oauth_reasons = score_oauth(oauth_profile, audit)
            if oauth_score >= _int("ALERT_SCORE_THRESHOLD", 45):
                alert = {
                    "schemaVersion": 1,
                    "detectedAt": iso(utcnow()),
                    "userId": user_id,
                    "userPrincipalName": audit.get("userPrincipalName"),
                    "score": oauth_score,
                    "reasons": oauth_reasons,
                    "oauthAudit": audit,
                    "label": "oauth_behavior_anomaly",
                    "enforcement": {"attempted": False, "details": ["OAuth anomalies are alert-only in this release; review consent/permission scope before remediation."]},
                }
                append_event_blob("alerts", alert)
                alerts += 1
        update_oauth_profile(oauth_profile, audit)
        save_json_blob(oauth_path, oauth_profile)

    checkpoint = max((parse_dt(e.get("createdDateTime")) for e in signins if e.get("createdDateTime")), default=utcnow())
    state["lastSignInCheckpoint"] = iso(checkpoint)
    state["lastRun"] = iso(utcnow())
    state["lastRunCounts"] = {"signIns": len(signins), "oauthAudits": len(oauth), "alerts": alerts, "actions": actions_used}
    save_json_blob("state/checkpoint.json", state)
    save_json_blob("state/recent-event-ids.json", (list(seen_ids)[-2000:] + new_seen)[-5000:])
    return state["lastRunCounts"]


@app.timer_trigger(schedule="%TIMER_SCHEDULE%", arg_name="timer", run_on_startup=False, use_monitor=True)
def EntraBehaviorGuardTimer(timer: func.TimerRequest) -> None:
    try:
        counts = process()
        logging.info("EntraBehaviorGuard run completed: %s", counts)
    except Exception:
        logging.exception("EntraBehaviorGuard run failed")
        raise
