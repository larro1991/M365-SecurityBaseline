BeforeAll {
    $modulePath = Split-Path -Parent $PSScriptRoot
    Import-Module "$modulePath\M365-SecurityBaseline.psd1" -Force
}

Describe 'M365-SecurityBaseline Module' {
    Context 'Module Loading' {
        It 'Should import without errors' {
            { Import-Module "$PSScriptRoot\..\M365-SecurityBaseline.psd1" -Force } | Should -Not -Throw
        }

        It 'Should export Invoke-M365SecurityAudit' {
            Get-Command -Module M365-SecurityBaseline -Name Invoke-M365SecurityAudit | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-MFAStatus' {
            Get-Command -Module M365-SecurityBaseline -Name Get-MFAStatus | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-MailboxForwardingRules' {
            Get-Command -Module M365-SecurityBaseline -Name Get-MailboxForwardingRules | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-ConditionalAccessReview' {
            Get-Command -Module M365-SecurityBaseline -Name Get-ConditionalAccessReview | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-GuestAccessReport' {
            Get-Command -Module M365-SecurityBaseline -Name Get-GuestAccessReport | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-MFAStatus' {
        It 'Should validate UserType parameter' {
            $validateSet = (Get-Command Get-MFAStatus).Parameters['UserType'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'All'
            $validateSet.ValidValues | Should -Contain 'Member'
            $validateSet.ValidValues | Should -Contain 'Guest'
        }
    }

    Context 'Get-MailboxForwardingRules' {
        It 'Should have ExternalOnly switch' {
            (Get-Command Get-MailboxForwardingRules).Parameters['ExternalOnly'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Get-GuestAccessReport' {
        It 'Should have DaysInactive parameter with default 90' {
            (Get-Command Get-GuestAccessReport).Parameters.ContainsKey('DaysInactive') | Should -BeTrue
        }
    }
}
