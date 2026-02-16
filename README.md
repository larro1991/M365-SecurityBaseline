# M365-SecurityBaseline

PowerShell module for auditing Microsoft 365 tenant security posture. Generates HTML dashboard reports with actionable findings.

## What It Does

| Function | Purpose |
|----------|---------|
| `Invoke-M365SecurityAudit` | Run all checks and generate a consolidated HTML dashboard |
| `Get-MFAStatus` | Report MFA enrollment for all users with method details |
| `Get-MailboxForwardingRules` | Find mailbox forwarding rules (data exfiltration detection) |
| `Get-ConditionalAccessReview` | Evaluate CA policies against security baselines |
| `Get-GuestAccessReport` | Review external/guest accounts and their access |

## Quick Start

```powershell
# Import the module
Import-Module .\M365-SecurityBaseline.psd1

# Run a full audit (will prompt for M365 authentication)
Invoke-M365SecurityAudit

# Or run individual checks
Get-MFAStatus | Where-Object { -not $_.MFAEnabled } | Export-Csv NoMFA.csv
Get-MailboxForwardingRules -ExternalOnly
Get-GuestAccessReport -DaysInactive 30
```

## Requirements

- PowerShell 5.1 or later (PowerShell 7+ recommended)
- **Microsoft Graph PowerShell SDK:**
  ```powershell
  Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns
  ```
- **Exchange Online Management:**
  ```powershell
  Install-Module ExchangeOnlineManagement
  ```
- Azure AD role: Global Reader or Security Reader (minimum)
- Exchange role: View-Only Organization Management (minimum)

## What the Report Covers

**MFA Adoption**: Percentage enrolled, which methods (Authenticator, FIDO2, Phone), and who's unprotected.

**Mailbox Forwarding**: Three layers checked — mailbox-level forwarding, SMTP forwarding, and inbox rules. External destinations flagged.

**Conditional Access**: Policy inventory with analysis — does your tenant block legacy auth? Require MFA for admins? For all users?

**Guest Accounts**: Stale invitations, unredeemed invites, group memberships, and last sign-in activity.

## Running Tests

```powershell
Invoke-Pester .\Tests\
```
