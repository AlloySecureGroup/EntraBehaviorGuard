# Entra Behavior Guard architecture

## Components

1. **Microsoft Entra app registration** uses an X.509 certificate stored in Azure Key Vault for app-only Microsoft Graph authentication.
2. **Azure Function (Python, timer trigger)** runs every five minutes by default.
3. **Managed identity** on the Function reads the certificate secret from Key Vault and writes to the data storage account without storage account keys.
4. **Hardened Azure Blob Storage** stores normalized sign-ins, OAuth/application-management audit records, user baselines, alerts, state/checkpoints, and enforcement actions.
5. **Per-user baseline** learns each user's successful apps, resources, auth protocols, client apps, countries, OS/browser families, managed/compliant-device tendencies, token types, and hour-of-week distribution.
6. **Decision engine** scores post-bake-in deviations. Enforcement is gated by `ENFORCEMENT_ENABLED`, score threshold, exclusion lists, and a max-actions-per-run circuit breaker.

## Blob layout

- `telemetry/signins/YYYY/MM/DD/HH/*.json`
- `telemetry/oauth-audit/YYYY/MM/DD/HH/*.json`
- `profiles/<sha256-user-object-id>.json`
- `oauth-profiles/<sha256-user-object-id>.json`
- `alerts/YYYY/MM/DD/HH/*.json`
- `actions/YYYY/MM/DD/HH/*.json`
- `state/checkpoint.json`

## Security boundaries

The **data** storage account disables anonymous public blobs and shared-key authorization. The Function writes to it through its managed identity with `Storage Blob Data Contributor`. The Key Vault uses Azure RBAC, and the Function is limited to `Key Vault Secrets User`. The separate Azure Functions host storage account remains a normal Functions dependency and is not used for behavioral telemetry.

For a higher-assurance deployment, place the data account and Key Vault behind private endpoints and run the Function on a VNet-capable plan. This reference package intentionally uses authenticated public endpoints so it remains deployable on the low-cost Consumption plan.

## Why AITM is a heuristic here

Entra sign-in logs alone do not provide a universal `isAITM=true` field. The detector therefore labels suspicious correlation as **possible AiTM/session replay** and preserves the evidence that caused the score. Microsoft Defender XDR / Defender for Cloud Apps can provide additional dedicated detections such as stolen session-cookie use. Treat those signals as stronger corroboration.
