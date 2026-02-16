function Get-MFAStatus {
    <#
    .SYNOPSIS
        Reports MFA enrollment status for all Microsoft 365 users.

    .DESCRIPTION
        Queries Microsoft Graph for user authentication methods and reports
        which users have MFA enabled, what methods they use, and which users
        are unprotected.

    .PARAMETER UserType
        Filter by user type: All, Member, or Guest. Defaults to Member.

    .PARAMETER IncludeDisabled
        Include disabled/blocked accounts in the report.

    .EXAMPLE
        Get-MFAStatus

        Returns MFA status for all enabled member accounts.

    .EXAMPLE
        Get-MFAStatus -UserType All | Where-Object { -not $_.MFAEnabled }

        Lists all users without MFA.

    .NOTES
        Requires: Microsoft.Graph.Users, Microsoft.Graph.Authentication
        Scopes: User.Read.All, UserAuthenticationMethod.Read.All
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('All', 'Member', 'Guest')]
        [string]$UserType = 'Member',

        [switch]$IncludeDisabled
    )

    # Get all users
    $userParams = @{
        All      = $true
        Property = @('Id', 'DisplayName', 'UserPrincipalName', 'UserType', 'AccountEnabled', 'CreatedDateTime', 'SignInActivity')
    }

    $users = Get-MgUser @userParams

    if ($UserType -ne 'All') {
        $users = $users | Where-Object UserType -eq $UserType
    }

    if (-not $IncludeDisabled) {
        $users = $users | Where-Object AccountEnabled -eq $true
    }

    $total = $users.Count
    $current = 0

    foreach ($user in $users) {
        $current++
        Write-Progress -Activity "Checking MFA status" -Status "$($user.DisplayName) ($current/$total)" -PercentComplete (($current / $total) * 100)

        try {
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop

            $methods = $authMethods | ForEach-Object {
                switch ($_.AdditionalProperties['@odata.type']) {
                    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { 'Authenticator App' }
                    '#microsoft.graph.phoneAuthenticationMethod'                 { 'Phone' }
                    '#microsoft.graph.fido2AuthenticationMethod'                 { 'FIDO2 Key' }
                    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' { 'Windows Hello' }
                    '#microsoft.graph.emailAuthenticationMethod'                 { 'Email' }
                    '#microsoft.graph.passwordAuthenticationMethod'              { 'Password' }
                    '#microsoft.graph.softwareOathAuthenticationMethod'          { 'TOTP Token' }
                    default { $_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', '' }
                }
            }

            # MFA is enabled if they have any method beyond just Password
            $nonPasswordMethods = $methods | Where-Object { $_ -ne 'Password' }
            $mfaEnabled = ($nonPasswordMethods.Count -gt 0)

            $lastSignIn = $user.SignInActivity.LastSignInDateTime

            [PSCustomObject]@{
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                UserType          = $user.UserType
                AccountEnabled    = $user.AccountEnabled
                MFAEnabled        = $mfaEnabled
                Methods           = ($nonPasswordMethods -join '; ')
                AllMethods        = ($methods -join '; ')
                LastSignIn        = $lastSignIn
                Created           = $user.CreatedDateTime
            }
        }
        catch {
            Write-Warning "Failed to get auth methods for $($user.UserPrincipalName): $_"
            [PSCustomObject]@{
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                UserType          = $user.UserType
                AccountEnabled    = $user.AccountEnabled
                MFAEnabled        = 'Error'
                Methods           = "Error: $_"
                AllMethods        = $null
                LastSignIn        = $null
                Created           = $user.CreatedDateTime
            }
        }
    }

    Write-Progress -Activity "Checking MFA status" -Completed
}
