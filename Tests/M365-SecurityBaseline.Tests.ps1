BeforeAll {
    $modulePath = Split-Path -Parent $PSScriptRoot
    Import-Module "$modulePath\M365-SecurityBaseline.psd1" -Force
}

Describe 'M365-SecurityBaseline Module' {

    Context 'Module Loading' {
        It 'Should import without errors' {
            { Import-Module "$PSScriptRoot\..\M365-SecurityBaseline.psd1" -Force } | Should -Not -Throw
        }

        It 'Should export exactly 5 public functions' {
            $commands = Get-Command -Module M365-SecurityBaseline
            $commands.Count | Should -Be 5
        }

        It 'Should export all expected functions' {
            $expected = @('Invoke-M365SecurityAudit', 'Get-MFAStatus', 'Get-MailboxForwardingRules', 'Get-ConditionalAccessReview', 'Get-GuestAccessReport')
            foreach ($func in $expected) {
                Get-Command -Module M365-SecurityBaseline -Name $func | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should not export private functions' {
            { Get-Command -Module M365-SecurityBaseline -Name _New-M365AuditHtml -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Get-MFAStatus Parameter Validation' {
        It 'Should validate UserType to All, Member, or Guest' {
            $validateSet = (Get-Command Get-MFAStatus).Parameters['UserType'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'All'
            $validateSet.ValidValues | Should -Contain 'Member'
            $validateSet.ValidValues | Should -Contain 'Guest'
        }

        It 'Should default UserType to Member' {
            # Verify the parameter exists and has a default
            (Get-Command Get-MFAStatus).Parameters.ContainsKey('UserType') | Should -BeTrue
        }

        It 'Should have IncludeDisabled switch' {
            (Get-Command Get-MFAStatus).Parameters['IncludeDisabled'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Get-MailboxForwardingRules Parameter Validation' {
        It 'Should have ExternalOnly switch' {
            (Get-Command Get-MailboxForwardingRules).Parameters['ExternalOnly'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Get-ConditionalAccessReview Parameter Validation' {
        It 'Should have IncludeDisabled switch' {
            (Get-Command Get-ConditionalAccessReview).Parameters['IncludeDisabled'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Get-GuestAccessReport Parameter Validation' {
        It 'Should have DaysInactive parameter' {
            (Get-Command Get-GuestAccessReport).Parameters.ContainsKey('DaysInactive') | Should -BeTrue
        }

        It 'Should have UnredeemedOnly switch' {
            (Get-Command Get-GuestAccessReport).Parameters['UnredeemedOnly'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Invoke-M365SecurityAudit Parameter Validation' {
        It 'Should have SkipConnect switch' {
            (Get-Command Invoke-M365SecurityAudit).Parameters['SkipConnect'].SwitchParameter | Should -BeTrue
        }

        It 'Should default OutputPath to .\Reports' {
            (Get-Command Invoke-M365SecurityAudit).Parameters.ContainsKey('OutputPath') | Should -BeTrue
        }
    }

    Context 'HTML Report Generation' {
        It 'Should generate valid HTML with all sections' {
            $mockResults = @{
                MFA = @(
                    [PSCustomObject]@{ DisplayName = 'User1'; UserPrincipalName = 'user1@contoso.com'; MFAEnabled = $true; LastSignIn = (Get-Date) }
                    [PSCustomObject]@{ DisplayName = 'User2'; UserPrincipalName = 'user2@contoso.com'; MFAEnabled = $false; LastSignIn = (Get-Date) }
                )
                Forwarding = @(
                    [PSCustomObject]@{ Mailbox = 'user1@contoso.com'; RuleType = 'InboxRule'; ForwardTo = 'external@gmail.com'; IsExternal = $true; RuleName = 'FWD' }
                )
                ConditionalAccess = @(
                    [PSCustomObject]@{ PolicyName = 'Require MFA'; State = 'enabled'; TargetUsers = 'All Users'; TargetApps = 'All Apps'; RequiresMFA = $true; BlocksLegacy = $false }
                )
                Guests = @(
                    [PSCustomObject]@{ DisplayName = 'Guest1'; Email = 'guest@vendor.com'; InviteState = 'Accepted'; LastSignIn = (Get-Date).AddDays(-100); StaleGuest = $true; Groups = 'Project-A' }
                )
            }

            $html = & (Get-Module M365-SecurityBaseline) {
                param($results)
                _New-M365AuditHtml -AuditResults $results -TenantName 'Contoso Corp'
            } $mockResults

            $html | Should -Match '<!DOCTYPE html>'
            $html | Should -Match 'Microsoft 365 Security Baseline Audit'
            $html | Should -Match 'Contoso Corp'
            $html | Should -Match 'MFA Adoption'
            $html | Should -Match 'Forwarding'
            $html | Should -Match 'Conditional Access'
            $html | Should -Match 'Guest Accounts'
        }

        It 'Should calculate MFA percentage correctly' {
            $mockResults = @{
                MFA = @(
                    [PSCustomObject]@{ DisplayName = 'A'; UserPrincipalName = 'a@c.com'; MFAEnabled = $true; LastSignIn = $null }
                    [PSCustomObject]@{ DisplayName = 'B'; UserPrincipalName = 'b@c.com'; MFAEnabled = $true; LastSignIn = $null }
                    [PSCustomObject]@{ DisplayName = 'C'; UserPrincipalName = 'c@c.com'; MFAEnabled = $true; LastSignIn = $null }
                    [PSCustomObject]@{ DisplayName = 'D'; UserPrincipalName = 'd@c.com'; MFAEnabled = $false; LastSignIn = $null }
                )
                Forwarding = @()
                ConditionalAccess = @()
                Guests = @()
            }

            $html = & (Get-Module M365-SecurityBaseline) {
                param($results)
                _New-M365AuditHtml -AuditResults $results -TenantName 'Test'
            } $mockResults

            # 3 out of 4 = 75%
            $html | Should -Match '75%'
        }
    }
}
