# Entra Behavior Guard

A deployable Microsoft Entra ID behavior-learning collector and response service for authentication anomalies, unusual OAuth/application activity, first-time Device Code use, and possible AiTM/session-replay patterns.

> **Safe default:** enforcement is OFF. The service learns each user's baseline during a configurable bake-in window, writes evidence to Azure Blob Storage, and only becomes enforcement-eligible after the user's bake-in time **and** minimum-event count are complete.

## What it collects

From Microsoft Graph sign-in logs:

- user, application, target resource;
- time and hour-of-week;
- authentication protocol (including Device Code when surfaced);
- client app and incoming token type;
- interactive/non-interactive marker when available;
- IP and coarse Entra location fields;
- browser/OS/device ID, managed/compliant state and trust type;
- Conditional Access status;
- sign-in risk fields when available in your licensing/tenant;
- correlation/original request IDs.

From Entra directory audit logs it preserves OAuth/application-management activity such as user consent, delegated permission grants, app-role assignments, and service-principal credential changes. It also learns a per-user OAuth activity baseline so a mature profile can flag a first-ever consent or first-seen target application.

## Example findings

The alert record is designed to say *why* something was unusual, for example:

- `never_seen_device_code` — “Successful device-code authentication was not present in this user's learned baseline.”
- `new_application` — first successful use of an app after baseline maturity.
- `new_time_window` — no learned successful sign-ins in that hour-of-week bucket.
- `first_unmanaged_device` — user had managed-only history and then used an unmanaged device.
- `possible_session_replay_or_aitm` — same application used from a different IP and country inside 30 minutes; this is deliberately a heuristic, not a definitive AiTM declaration.

Microsoft describes Device Code as a higher-risk authentication flow that can be used in phishing, and documents AiTM campaigns that steal authenticated session cookies/tokens to bypass repeated MFA challenges. See `docs/ATTACK-REFERENCES.md`.

## Azure resources

The installer creates:

- Microsoft Entra app registration + service principal;
- certificate credential whose private key stays in Azure Key Vault;
- Azure Function App (Python timer trigger);
- hardened Azure Blob data account with public blob access disabled and shared-key authorization disabled;
- separate Functions host storage account;
- Azure Key Vault using RBAC;
- managed identity permissions: `Storage Blob Data Contributor` on the data account and `Key Vault Secrets User` on the vault;
- Application Insights.

## Microsoft Graph application permissions

Default:

- `AuditLog.Read.All` — read sign-in and directory audit logs.
- `User.RevokeSessions.All` — revoke user sign-in sessions.

Optional, only when `-GrantDisablePermission` is used:

- `User.EnableDisableAccount.All`
- `User.Read.All`

The disable pair is the least-privileged Graph application-permission combination documented for changing `accountEnabled`. For privileged administrator targets, Microsoft additionally requires an appropriate Entra administrator role for the calling app. This installer does **not** auto-assign a privileged directory role.

## Prerequisites

- Azure subscription where you can create resource groups/resources and role assignments.
- Microsoft Entra permissions sufficient to create an app/service principal and grant Microsoft Graph **application** permissions. In many tenants this requires Privileged Role Administrator or Global Administrator for the consent step.
- Azure CLI (`az`) authenticated to the target tenant/subscription.
- PowerShell 7+ recommended. The installer intentionally uses Azure CLI rather than Az PowerShell modules, which avoids module-installation problems on locked-down WindowsApps environments.
- Tenant licensing/retention sufficient for the sign-in data you expect Microsoft Graph to return.

## Install

From PowerShell:

```powershell
cd .\EntraBehaviorGuard
az login

.\installer\Install-EntraBehaviorGuard.ps1 `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -ResourceGroup "rg-entra-behavior-guard" `
  -Location "eastus2" `
  -Prefix "ebg" `
  -BakeInDays 14 `
  -MinBaselineEvents 25 `
  -ProtectedUpns "breakglass1@contoso.com,breakglass2@contoso.com"
```

For optional account-disable capability, add `-GrantDisablePermission`. Do not grant it unless you intend to use `disableAndRevoke`.

The installer writes `deployment.json` locally with non-secret deployment identifiers. No private key is written to disk by the installer.

## Bake-in and learning

Defaults:

- `BAKE_IN_DAYS=14`
- `MIN_BASELINE_EVENTS=25`
- `MIN_OAUTH_BASELINE_EVENTS=3`
- `ALERT_SCORE_THRESHOLD=45`
- `ENFORCEMENT_SCORE_THRESHOLD=80`
- `ENFORCEMENT_ENABLED=false`
- maximum three automated responses per five-minute run.

A user must satisfy both bake-in conditions before anomaly scoring can drive enforcement.

## Enable enforcement

First review alerts for an appropriate period and protect emergency accounts. Then:

```powershell
.\installer\Set-Enforcement.ps1 `
  -ResourceGroup "rg-entra-behavior-guard" `
  -FunctionAppName "<name from deployment.json>" `
  -Enabled $true `
  -Action "revokeSessions" `
  -ScoreThreshold 80 `
  -ProtectedUpns "breakglass1@contoso.com,breakglass2@contoso.com"
```

To permit account disablement, the app must have been installed with `-GrantDisablePermission`, and you can then select `-Action disableAndRevoke`. Keep privileged administrator and emergency accounts protected unless you have separately reviewed and granted the directory-role requirements.

## Read alerts

```powershell
.\installer\Get-Alerts.ps1 `
  -StorageAccount "<dataStorageName from deployment.json>"
```

Your operator identity needs an Azure Storage data role such as `Storage Blob Data Reader` on the data storage account.

## Interactive vs non-interactive sign-ins

The stable Microsoft Graph v1.0 sign-in API is the default. Microsoft documents that the beta sign-in API can be filtered for non-interactive user sign-ins. If you intentionally accept the beta API support risk, install with:

```powershell
-EnableBetaNonInteractive
```

Microsoft explicitly warns that Graph `/beta` APIs are subject to change and are not supported for production applications. Treat this as an optional enrichment feature, not a required dependency.

## Storage security

The behavioral data storage account uses:

- HTTPS only;
- TLS 1.2 minimum;
- anonymous/public blob access disabled;
- shared-key authorization disabled;
- OAuth/Entra authentication as default;
- managed-identity access from the Function;
- blob versioning and 14-day soft deletion.

The default Consumption-plan design leaves the authenticated data endpoint reachable over Azure's public service endpoint. For strict private-network-only storage, move the Function to a VNet-capable plan and add private endpoints/DNS for Blob and Key Vault.

## Operational recommendations

1. Keep `ENFORCEMENT_ENABLED=false` through at least one full business cycle; 14–30 days is common for users with weekly patterns.
2. Exclude break-glass/emergency identities and service/test accounts whose behavior is intentionally irregular.
3. Start with `revokeSessions`, not account disablement.
4. Review `alerts/` for false positives and tune thresholds before enabling automated actions.
5. Correlate `possible_session_replay_or_aitm` with Microsoft Defender XDR / Defender for Cloud Apps, endpoint telemetry, browser/device posture, and identity-risk signals.
6. Rotate the Key Vault certificate before expiration. The installer creates a two-year certificate by default.
7. Forward the Blob records to Sentinel/Log Analytics if you need central SOC alerting, workbooks, or incident automation.

## Limitations

- This is a statistical novelty detector, not a replacement for Entra ID Protection, Conditional Access, Defender XDR, or Sentinel.
- Geolocation fields are coarse and can create false positives due to VPNs, mobile carriers, proxies, and corporate egress.
- A new app, OAuth consent, or Device Code use can be legitimate. The detector records the reason; humans should tune policy to the environment. OAuth anomalies are alert-only by design in this release.
- Automatic disablement of privileged admins needs additional directory-role authorization in app-only scenarios and is intentionally not bootstrapped here.
- Session revocation can take a short time to propagate and does not revoke sessions for external users in their home tenant.

See `docs/DETECTIONS.md`, `docs/ARCHITECTURE.md`, and `docs/ATTACK-REFERENCES.md` for details.
