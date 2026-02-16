# M365-SecurityBaseline

PowerShell module for auditing Microsoft 365 tenant security posture. Checks MFA enrollment, Conditional Access policies, mailbox forwarding rules, and guest account hygiene. Generates HTML dashboard reports with findings and recommendations.

## The Problem

M365 tenants accumulate risk quietly. Users disable MFA, create forwarding rules to personal email, guest accounts go stale, and Conditional Access policies have gaps nobody reviews. Most orgs don't find out until after an incident.

## What This Module Does

| Function | Purpose |
|----------|---------|
| `Invoke-M365SecurityAudit` | Run all checks, generate an HTML dashboard |
| `Get-MFAStatus` | Report MFA enrollment status with authentication method details |
| `Get-MailboxForwardingRules` | Find all forwarding rules -- mailbox-level, SMTP, and inbox rules |
| `Get-ConditionalAccessReview` | Evaluate CA policies against baseline recommendations |
| `Get-GuestAccessReport` | Review external/guest accounts with stale detection |

## Quick Start

```powershell
Import-Module .\M365-SecurityBaseline.psd1

# Full audit (prompts for M365 authentication)
Invoke-M365SecurityAudit

# Check MFA gaps
Get-MFAStatus | Where-Object { -not $_.MFAEnabled } | Export-Csv NoMFA.csv

# Find external forwarding (data exfiltration check)
Get-MailboxForwardingRules -ExternalOnly

# Review guest accounts inactive for 30+ days
Get-GuestAccessReport -DaysInactive 30 | Where-Object StaleGuest
```

## Example Output

**MFA Status:**
```
DisplayName       UserPrincipalName         MFAEnabled  Methods              LastSignIn
-----------       -----------------         ----------  -------              ----------
Williams, Mark    mwilliams@contoso.com     False                            2026-02-14
Smith, Jane       jsmith@contoso.com        True        Authenticator App    2026-02-14
```

**Mailbox Forwarding:**
```
Mailbox                    RuleType           ForwardTo                        IsExternal  RuleName
-------                    --------           ---------                        ----------  --------
mwilliams@contoso.com      InboxRule          mwilliams.personal@gmail.com     True        Forward to Personal
ethompson@contoso.com      InboxRule          ethompson@competitor.com         True        FW All
```

**HTML Dashboard:**

See [`Samples/sample-report.html`](Samples/sample-report.html) for the full audit dashboard.

## Installation

```powershell
# Install dependencies
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser

# Import the module
Import-Module .\M365-SecurityBaseline.psd1
```

## Requirements

- PowerShell 5.1+ (PowerShell 7+ recommended)
- Microsoft Graph PowerShell SDK (`Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Identity.SignIns`)
- Exchange Online Management module (`ExchangeOnlineManagement`)
- Azure AD role: **Global Reader** or **Security Reader** (minimum)
- Exchange role: **View-Only Organization Management** (minimum)

## What Gets Checked

**MFA Enrollment** -- Queries Graph API authentication methods for every user. Reports which users have MFA, what methods they use (Authenticator, FIDO2, Phone, TOTP), and who has only a password. Calculates adoption percentage.

**Mailbox Forwarding** -- Three-layer check:
1. `ForwardingAddress` set on the mailbox
2. `ForwardingSMTPAddress` set on the mailbox
3. Inbox rules with forward/redirect actions

Each target is classified as internal or external by comparing against accepted domains. External forwarding to personal email is the #1 indicator of compromised accounts.

**Conditional Access** -- Inventories all CA policies and checks for baseline gaps:
- Is MFA required for admin roles?
- Is MFA required for all users?
- Is legacy authentication blocked?
- Are high-risk sign-ins blocked?

**Guest Accounts** -- Enumerates all guest users with invite state, last sign-in, group memberships. Flags stale guests (configurable threshold) and unredeemed invitations.

## Design Decisions

- **Graph API over MSOL/AzureAD** -- uses the Microsoft Graph PowerShell SDK, not the deprecated MSOL or AzureAD modules.
- **Three-layer forwarding check** -- most scripts only check mailbox-level forwarding. Inbox rules are where compromised accounts actually set up exfiltration.
- **-SkipConnect flag** -- for environments where you're already authenticated. Avoids double-prompting in scripts that connect upstream.
- **Progress reporting** -- MFA check iterates every user for auth methods. Progress bars keep operators informed on large tenants.

## Project Structure

```
M365-SecurityBaseline/
├── M365-SecurityBaseline.psd1             # Module manifest
├── M365-SecurityBaseline.psm1             # Root module
├── Public/
│   ├── Invoke-M365SecurityAudit.ps1       # Orchestrator
│   ├── Get-MFAStatus.ps1                  # MFA enrollment checker
│   ├── Get-MailboxForwardingRules.ps1     # Forwarding rule auditor
│   ├── Get-ConditionalAccessReview.ps1    # CA policy reviewer
│   └── Get-GuestAccessReport.ps1          # Guest account reviewer
├── Private/
│   └── _New-M365AuditHtml.ps1             # Dashboard HTML generator
├── Tests/
│   └── M365-SecurityBaseline.Tests.ps1    # Pester tests
└── Samples/
    └── sample-report.html                 # Example dashboard output
```

## Running Tests

```powershell
Invoke-Pester .\Tests\ -Output Detailed
```

## License

MIT
