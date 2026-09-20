# Attack and API references

Authoritative references used to design the detector:

1. Microsoft Graph — List sign-ins (requires `AuditLog.Read.All`):
   https://learn.microsoft.com/graph/api/signin-list
2. Microsoft Graph — List directory audits:
   https://learn.microsoft.com/graph/api/directoryaudit-list
3. Microsoft Graph — Revoke sign-in sessions (`User.RevokeSessions.All`):
   https://learn.microsoft.com/graph/api/user-revokesigninsessions
4. Microsoft Graph — Update user / `accountEnabled` permission requirements:
   https://learn.microsoft.com/graph/api/user-update
5. Microsoft Graph permissions reference:
   https://learn.microsoft.com/graph/permissions-reference
6. Microsoft Entra Conditional Access authentication flows — device code flow:
   https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows
7. Microsoft Entra — activity logs of application permissions / consent:
   https://learn.microsoft.com/entra/identity/enterprise-apps/app-perms-audit-logs
8. Microsoft Security Blog — From cookie theft to BEC: attackers use AiTM phishing sites:
   https://www.microsoft.com/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/
9. Microsoft Security Blog — Detecting and mitigating a multi-stage AiTM phishing and BEC campaign:
   https://www.microsoft.com/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/
10. Microsoft Security Blog — Token tactics: prevent, detect, and respond to cloud token theft:
    https://www.microsoft.com/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/
11. Microsoft Security Blog — OAuth applications abused in financially driven attacks:
    https://www.microsoft.com/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
12. Microsoft Security Blog — Inside Tycoon2FA (2026):
    https://www.microsoft.com/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/
13. Microsoft Security Blog — 2026 multi-stage AiTM token compromise campaign:
    https://www.microsoft.com/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/
14. MITRE ATT&CK — Adversary-in-the-Middle (T1557):
    https://attack.mitre.org/techniques/T1557/
15. MITRE ATT&CK — Steal Web Session Cookie (T1539):
    https://attack.mitre.org/techniques/T1539/

## Interpretation notes

- Device Code is not inherently malicious. The high score applies specifically when a mature user baseline has never contained it before.
- AiTM cannot be conclusively proven by one Entra sign-in row. The package generates an evidence-based hypothesis and recommends correlation with Defender XDR, endpoint/browser telemetry, network data, and identity-risk signals.
- Password reset alone is insufficient for stolen-session-cookie incidents; Microsoft guidance emphasizes session/token revocation as part of remediation.
