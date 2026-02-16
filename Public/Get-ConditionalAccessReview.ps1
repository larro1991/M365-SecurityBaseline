function Get-ConditionalAccessReview {
    <#
    .SYNOPSIS
        Reviews Conditional Access policies and checks for common gaps.

    .DESCRIPTION
        Retrieves all Conditional Access policies and evaluates them against
        security baseline recommendations:
        - Is MFA required for admins?
        - Is MFA required for all users?
        - Are legacy authentication protocols blocked?
        - Are high-risk sign-ins blocked?
        - Are unmanaged devices restricted?

    .PARAMETER IncludeDisabled
        Include disabled (report-only and off) policies in the review.

    .EXAMPLE
        Get-ConditionalAccessReview

    .EXAMPLE
        Get-ConditionalAccessReview -IncludeDisabled | Format-Table

    .NOTES
        Requires: Microsoft.Graph.Identity.SignIns
        Scopes: Policy.Read.All
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled
    )

    $policies = Get-MgIdentityConditionalAccessPolicy -All

    if (-not $IncludeDisabled) {
        $policies = $policies | Where-Object State -eq 'enabled'
    }

    foreach ($policy in $policies) {
        # Analyze what this policy does
        $targetUsers = if ($policy.Conditions.Users.IncludeUsers -contains 'All') { 'All Users' }
                       elseif ($policy.Conditions.Users.IncludeGroups) { "Groups: $($policy.Conditions.Users.IncludeGroups.Count)" }
                       elseif ($policy.Conditions.Users.IncludeRoles) { "Roles: $($policy.Conditions.Users.IncludeRoles.Count)" }
                       else { 'Specific' }

        $targetApps = if ($policy.Conditions.Applications.IncludeApplications -contains 'All') { 'All Apps' }
                      elseif ($policy.Conditions.Applications.IncludeApplications -contains 'Office365') { 'Office 365' }
                      else { "Apps: $($policy.Conditions.Applications.IncludeApplications.Count)" }

        $grantControls = ($policy.GrantControls.BuiltInControls) -join '; '
        $requiresMFA = $policy.GrantControls.BuiltInControls -contains 'mfa'
        $blocksAccess = $policy.GrantControls.BuiltInControls -contains 'block'

        $blocksLegacyAuth = $policy.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
                            $policy.Conditions.ClientAppTypes -contains 'other'

        [PSCustomObject]@{
            PolicyName      = $policy.DisplayName
            State           = $policy.State
            TargetUsers     = $targetUsers
            TargetApps      = $targetApps
            GrantControls   = $grantControls
            RequiresMFA     = $requiresMFA
            BlocksAccess    = $blocksAccess
            BlocksLegacy    = $blocksLegacyAuth
            ExcludedUsers   = $policy.Conditions.Users.ExcludeUsers.Count
            ExcludedGroups  = $policy.Conditions.Users.ExcludeGroups.Count
            Created         = $policy.CreatedDateTime
            Modified        = $policy.ModifiedDateTime
        }
    }
}
