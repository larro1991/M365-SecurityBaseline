function Get-GuestAccessReport {
    <#
    .SYNOPSIS
        Reviews guest (external) user accounts in the Microsoft 365 tenant.

    .DESCRIPTION
        Enumerates all guest accounts and reports on:
        - When they were invited and by whom
        - Last sign-in activity
        - Whether they've redeemed their invitation
        - Group memberships and app access

        Stale guest accounts are a common compliance finding and attack surface.

    .PARAMETER DaysInactive
        Flag guests who haven't signed in within this many days. Defaults to 90.

    .PARAMETER UnredeemedOnly
        Only show guests who never accepted their invitation.

    .EXAMPLE
        Get-GuestAccessReport

    .EXAMPLE
        Get-GuestAccessReport -DaysInactive 30 | Where-Object StaleGuest -eq $true

    .NOTES
        Requires: Microsoft.Graph.Users
        Scopes: User.Read.All, Directory.Read.All
    #>
    [CmdletBinding()]
    param(
        [int]$DaysInactive = 90,

        [switch]$UnredeemedOnly
    )

    $inactiveThreshold = (Get-Date).AddDays(-$DaysInactive)

    $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -Property @(
        'Id', 'DisplayName', 'Mail', 'UserPrincipalName', 'CreatedDateTime',
        'ExternalUserState', 'ExternalUserStateChangeDateTime', 'SignInActivity',
        'AccountEnabled'
    )

    if ($UnredeemedOnly) {
        $guests = $guests | Where-Object ExternalUserState -ne 'Accepted'
    }

    foreach ($guest in $guests) {
        $lastSignIn = $guest.SignInActivity.LastSignInDateTime
        $isStale = if ($lastSignIn) { $lastSignIn -lt $inactiveThreshold } else { $true }
        $daysSinceSignIn = if ($lastSignIn) { [math]::Round(((Get-Date) - $lastSignIn).TotalDays) } else { $null }

        # Get group memberships
        $memberOf = try {
            (Get-MgUserMemberOf -UserId $guest.Id -ErrorAction Stop).AdditionalProperties.displayName -join '; '
        }
        catch { '' }

        [PSCustomObject]@{
            DisplayName      = $guest.DisplayName
            Email            = $guest.Mail
            UPN              = $guest.UserPrincipalName
            InviteState      = $guest.ExternalUserState
            InviteDate       = $guest.CreatedDateTime
            AccountEnabled   = $guest.AccountEnabled
            LastSignIn       = $lastSignIn
            DaysSinceSignIn  = $daysSinceSignIn
            StaleGuest       = $isStale
            Groups           = $memberOf
        }
    }
}
