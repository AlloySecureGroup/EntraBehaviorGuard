# Detection logic

## Bake-in

A user's profile becomes enforcement-eligible only when both conditions are true:

- `BAKE_IN_DAYS` have elapsed since that user's first learned event; and
- at least `MIN_BASELINE_EVENTS` successful sign-ins were observed.

Before that point, events are stored and learned but receive no enforceable anomaly score.

## Included detections

| Detection | Default points | Rationale |
|---|---:|---|
| First successful Device Code use | 55 | Useful for the statement: “this user has never used Device Code.” Device code is legitimate, but Microsoft describes it as a higher-risk flow that can be used in phishing. |
| New application | 20 | A new app can be benign; combines with other signals. |
| New country/region | 20 | New geography is useful context, not proof of compromise. |
| New browser | 10 | Lightweight novelty feature. |
| New OS | 10 | Lightweight novelty feature. |
| New hour-of-week bucket | 12 | Detects unusual timing after adequate history. |
| First unmanaged device after managed-only history | 20 | Flags a trust-posture shift. |
| Entra medium sign-in risk | 35 | Uses Microsoft's risk signal if present/licensed. |
| Entra high sign-in risk | 60 | Strong corroborating signal if present/licensed. |
| Entra risk-event types present | 20 | Adds corroboration. |
| Same app, different IP + country within 30 min | 35 | Labeled `possible_session_replay_or_aitm`; not treated as definitive proof. |
| New-country non-interactive event | +15 | Available when optional beta non-interactive collection is enabled. |

Default alert threshold is 45; default enforcement threshold is 80.

## OAuth/application activity

The collector also stores Entra `ApplicationManagement` audit events for:

- Consent to application
- Add/remove delegated permission grant
- Add/remove app role assignment to service principal
- Add/remove service principal credentials

These events are retained in `telemetry/oauth-audit/` and learned per user in `oauth-profiles/`. After `BAKE_IN_DAYS` and at least `MIN_OAUTH_BASELINE_EVENTS` (default 3), a first-ever successful `Consent to application` event scores 45 points and a first-seen OAuth target application adds 20 points.

OAuth anomalies are **alert-only** in this release. Automatic grant removal or user containment from a consent event can disrupt legitimate business applications and should use a separately reviewed policy and permission-scope inspection.

## Enforcement

`ENFORCEMENT_ENABLED=false` by default.

Supported actions:

- `revokeSessions`: call Microsoft Graph `revokeSignInSessions`.
- `disableAndRevoke`: revoke sessions, then set `accountEnabled=false`.

Additional guardrails:

- protected UPN/user-ID exclusion list;
- maximum actions per run;
- minimum bake-in and event count;
- independent alert and enforcement thresholds;
- every attempted action written to `actions/`.

Important: disabling privileged administrators in app-only mode can require the application to hold an appropriate Microsoft Entra administrator role in addition to Graph permissions. This package deliberately does not assign such a directory role automatically. Protect administrative/break-glass accounts and prefer `revokeSessions` unless you have explicitly designed and reviewed privileged-user response.
