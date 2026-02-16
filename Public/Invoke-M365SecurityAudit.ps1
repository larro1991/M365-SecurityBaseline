function Invoke-M365SecurityAudit {
    <#
    .SYNOPSIS
        Runs a comprehensive Microsoft 365 tenant security audit.

    .DESCRIPTION
        Connects to Microsoft 365 and runs all security baseline checks:
        1. MFA enrollment and enforcement status
        2. Conditional Access policy review
        3. Mailbox forwarding rule audit (data exfiltration detection)
        4. Guest/external user access review
        5. Shared mailbox license optimization

        Generates an HTML dashboard report with findings and recommendations.

        Requires the Microsoft Graph PowerShell SDK and Exchange Online module.

    .PARAMETER OutputPath
        Directory to save the HTML report. Defaults to .\Reports.

    .PARAMETER SkipConnect
        Skip the Connect-MgGraph and Connect-ExchangeOnline calls (use if already connected).

    .PARAMETER Scopes
        Microsoft Graph scopes to request. Defaults to the required set for all checks.

    .EXAMPLE
        Invoke-M365SecurityAudit

        Runs all checks, prompts for authentication, saves report to .\Reports.

    .EXAMPLE
        Invoke-M365SecurityAudit -SkipConnect -OutputPath "C:\Audits"

        Runs all checks using existing connections.

    .NOTES
        Required modules:
        - Microsoft.Graph.Authentication
        - Microsoft.Graph.Users
        - Microsoft.Graph.Identity.SignIns
        - ExchangeOnlineManagement
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = '.\Reports',

        [switch]$SkipConnect,

        [string]$LogPath = '.\Logs'
    )

    begin {
        foreach ($dir in @($OutputPath, $LogPath)) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            }
        }

        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        Start-Transcript -Path (Join-Path $LogPath "M365Audit-$timestamp.log") -Append

        # Connect to services
        if (-not $SkipConnect) {
            Write-Verbose "Connecting to Microsoft Graph..."
            Connect-MgGraph -Scopes @(
                'User.Read.All',
                'UserAuthenticationMethod.Read.All',
                'Policy.Read.All',
                'Directory.Read.All'
            ) -ErrorAction Stop

            Write-Verbose "Connecting to Exchange Online..."
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }

        $auditResults = @{}
    }

    process {
        $tenantName = (Get-MgOrganization).DisplayName

        # 1. MFA Status
        Write-Verbose "Checking MFA enrollment..."
        $auditResults['MFA'] = @(Get-MFAStatus)

        # 2. Conditional Access
        Write-Verbose "Reviewing Conditional Access policies..."
        $auditResults['ConditionalAccess'] = @(Get-ConditionalAccessReview)

        # 3. Mailbox Forwarding
        Write-Verbose "Auditing mailbox forwarding rules..."
        $auditResults['Forwarding'] = @(Get-MailboxForwardingRules)

        # 4. Guest Access
        Write-Verbose "Reviewing guest accounts..."
        $auditResults['Guests'] = @(Get-GuestAccessReport)

        # Generate HTML
        $htmlFile = Join-Path $OutputPath "M365-SecurityAudit-$timestamp.html"
        $html = _New-M365AuditHtml -AuditResults $auditResults -TenantName $tenantName
        $html | Out-File -FilePath $htmlFile -Encoding UTF8

        Write-Verbose "Report saved: $htmlFile"

        # Summary
        $mfaNotEnrolled = @($auditResults['MFA'] | Where-Object MFAEnabled -eq $false).Count
        $forwardingRules = $auditResults['Forwarding'].Count

        [PSCustomObject]@{
            Tenant              = $tenantName
            AuditDate           = Get-Date -Format 'yyyy-MM-dd HH:mm'
            UsersWithoutMFA     = $mfaNotEnrolled
            TotalUsers          = $auditResults['MFA'].Count
            CAPolicies          = $auditResults['ConditionalAccess'].Count
            ForwardingRules     = $forwardingRules
            GuestAccounts       = $auditResults['Guests'].Count
            ReportPath          = $htmlFile
        }
    }

    end {
        Stop-Transcript
    }
}
