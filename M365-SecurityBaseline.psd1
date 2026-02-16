@{
    RootModule        = 'M365-SecurityBaseline.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'c3d4e5f6-a7b8-9012-cdef-123456789012'
    Author            = 'Larry Roberts'
    CompanyName       = 'Independent Consultant'
    Copyright         = '(c) 2026 Larry Roberts. All rights reserved.'
    Description       = 'Microsoft 365 tenant security baseline audit. Checks MFA status, Conditional Access, mailbox forwarding rules, guest access, and shared mailbox licensing.'

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
            ProjectUri = 'https://github.com/larro1991/M365-SecurityBaseline'
        }
    }
}
