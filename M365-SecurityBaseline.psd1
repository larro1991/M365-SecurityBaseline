@{
    RootModule        = 'M365-SecurityBaseline.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '7fbb6c8f-6121-42bb-bdfb-466bbdd996bc'
    Author            = 'Larry Roberts'
    CompanyName       = 'Independent Consultant'
    Copyright         = '(c) 2026 Larry Roberts. All rights reserved.'
    Description       = 'Microsoft 365 tenant security baseline audit. Checks MFA enrollment, Conditional Access policies, mailbox forwarding rules, and guest account hygiene. Generates HTML dashboard reports. Requires Microsoft.Graph and ExchangeOnlineManagement modules.'

    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-M365SecurityAudit',
        'Get-MFAStatus',
        'Get-MailboxForwardingRules',
        'Get-ConditionalAccessReview',
        'Get-GuestAccessReport'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Microsoft365', 'M365', 'Security', 'MFA', 'Azure', 'Audit', 'Compliance')
            LicenseUri = 'https://github.com/larro1991/M365-SecurityBaseline/blob/master/LICENSE'
            ProjectUri = 'https://github.com/larro1991/M365-SecurityBaseline'
        }
    }
}
