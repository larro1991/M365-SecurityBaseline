function _New-M365AuditHtml {
    <#
    .SYNOPSIS
        Generates the M365 security audit HTML dashboard.
    #>
    param(
        [hashtable]$AuditResults,
        [string]$TenantName
    )

    $css = @"
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; }
        .meta { color: #7f8c8d; margin-bottom: 20px; }
        .dashboard { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 180px; text-align: center; }
        .card .number { font-size: 36px; font-weight: bold; }
        .card .label { color: #7f8c8d; font-size: 12px; margin-top: 5px; }
        .card.danger .number { color: #e74c3c; }
        .card.warning .number { color: #e67e22; }
        .card.ok .number { color: #27ae60; }
        table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
        th { background: #0078d4; color: #fff; padding: 10px 8px; text-align: left; font-size: 11px; }
        td { padding: 8px; border-bottom: 1px solid #ecf0f1; font-size: 11px; }
        tr:nth-child(even) { background: #f9f9f9; }
        tr:hover { background: #eaf2f8; }
        .risk { color: #e74c3c; font-weight: bold; }
        .ok { color: #27ae60; }
        .rec { background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #e67e22; margin: 10px 0; }
    </style>
"@

    $mfaTotal = $AuditResults['MFA'].Count
    $mfaEnabled = @($AuditResults['MFA'] | Where-Object MFAEnabled -eq $true).Count
    $mfaDisabled = $mfaTotal - $mfaEnabled
    $mfaPercent = if ($mfaTotal -gt 0) { [math]::Round(($mfaEnabled / $mfaTotal) * 100) } else { 0 }
    $forwardingCount = $AuditResults['Forwarding'].Count
    $externalForwarding = @($AuditResults['Forwarding'] | Where-Object IsExternal -eq $true).Count
    $guestCount = $AuditResults['Guests'].Count
    $staleGuests = @($AuditResults['Guests'] | Where-Object StaleGuest -eq $true).Count
    $caCount = $AuditResults['ConditionalAccess'].Count

    $mfaClass = if ($mfaPercent -ge 95) { 'ok' } elseif ($mfaPercent -ge 80) { 'warning' } else { 'danger' }

    # MFA table rows
    $mfaNoRows = ($AuditResults['MFA'] | Where-Object MFAEnabled -eq $false | ForEach-Object {
        "<tr><td>$($_.DisplayName)</td><td>$($_.UserPrincipalName)</td><td class='risk'>No MFA</td><td>$($_.LastSignIn)</td></tr>"
    }) -join "`n"

    # Forwarding rows
    $fwdRows = ($AuditResults['Forwarding'] | ForEach-Object {
        $extClass = if ($_.IsExternal) { " class='risk'" } else { '' }
        "<tr><td>$($_.Mailbox)</td><td>$($_.RuleType)</td><td$extClass>$($_.ForwardTo)</td><td>$($_.IsExternal)</td><td>$($_.RuleName)</td></tr>"
    }) -join "`n"

    # CA rows
    $caRows = ($AuditResults['ConditionalAccess'] | ForEach-Object {
        "<tr><td>$($_.PolicyName)</td><td>$($_.State)</td><td>$($_.TargetUsers)</td><td>$($_.TargetApps)</td><td>$($_.RequiresMFA)</td><td>$($_.BlocksLegacy)</td></tr>"
    }) -join "`n"

    # Guest rows
    $guestRows = ($AuditResults['Guests'] | Sort-Object StaleGuest -Descending | ForEach-Object {
        $staleClass = if ($_.StaleGuest) { " class='risk'" } else { '' }
        "<tr><td>$($_.DisplayName)</td><td>$($_.Email)</td><td>$($_.InviteState)</td><td>$($_.LastSignIn)</td><td$staleClass>$($_.StaleGuest)</td><td>$($_.Groups)</td></tr>"
    }) -join "`n"

    @"
<!DOCTYPE html>
<html>
<head><title>M365 Security Audit - $TenantName</title>$css</head>
<body>
    <h1>Microsoft 365 Security Baseline Audit</h1>
    <div class="meta">Tenant: $TenantName | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>

    <div class="dashboard">
        <div class="card $mfaClass"><div class="number">$mfaPercent%</div><div class="label">MFA Adoption</div></div>
        <div class="card $(if($mfaDisabled -gt 0){'danger'}else{'ok'})"><div class="number">$mfaDisabled</div><div class="label">Users Without MFA</div></div>
        <div class="card $(if($externalForwarding -gt 0){'danger'}else{'ok'})"><div class="number">$externalForwarding</div><div class="label">External Forwarding</div></div>
        <div class="card"><div class="number">$caCount</div><div class="label">CA Policies</div></div>
        <div class="card $(if($staleGuests -gt 5){'warning'}else{'ok'})"><div class="number">$staleGuests</div><div class="label">Stale Guests</div></div>
    </div>

    <h2>Users Without MFA ($mfaDisabled)</h2>
    $(if($mfaDisabled -gt 0){"<div class='rec'>Recommendation: Enable MFA for all users via Conditional Access policy.</div>"})
    <table>
        <tr><th>Name</th><th>UPN</th><th>MFA Status</th><th>Last Sign-In</th></tr>
        $mfaNoRows
    </table>

    <h2>Mailbox Forwarding Rules ($forwardingCount)</h2>
    $(if($externalForwarding -gt 0){"<div class='rec'>Recommendation: Review external forwarding rules. Consider blocking auto-forwarding to external domains via transport rule.</div>"})
    <table>
        <tr><th>Mailbox</th><th>Rule Type</th><th>Forward To</th><th>External</th><th>Rule Name</th></tr>
        $fwdRows
    </table>

    <h2>Conditional Access Policies ($caCount)</h2>
    <table>
        <tr><th>Policy</th><th>State</th><th>Target Users</th><th>Target Apps</th><th>Requires MFA</th><th>Blocks Legacy</th></tr>
        $caRows
    </table>

    <h2>Guest Accounts ($guestCount)</h2>
    <table>
        <tr><th>Name</th><th>Email</th><th>Invite State</th><th>Last Sign-In</th><th>Stale</th><th>Groups</th></tr>
        $guestRows
    </table>
</body>
</html>
"@
}
