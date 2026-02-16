function Get-MailboxForwardingRules {
    <#
    .SYNOPSIS
        Audits all mailbox forwarding rules for potential data exfiltration.

    .DESCRIPTION
        Checks three types of mail forwarding:
        1. ForwardingAddress (set on the mailbox directly)
        2. ForwardingSMTPAddress (set on the mailbox directly)
        3. Inbox rules that forward or redirect to external addresses

        External forwarding is a common attack vector after account compromise
        and is a finding in most security frameworks.

    .PARAMETER ExternalOnly
        Only report rules forwarding to external (non-tenant) domains.

    .EXAMPLE
        Get-MailboxForwardingRules

        Returns all forwarding rules across all mailboxes.

    .EXAMPLE
        Get-MailboxForwardingRules -ExternalOnly

        Returns only rules forwarding to external domains.

    .NOTES
        Requires: ExchangeOnlineManagement module, Exchange Admin role.
    #>
    [CmdletBinding()]
    param(
        [switch]$ExternalOnly
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Get accepted domains for internal/external classification
    $acceptedDomains = (Get-AcceptedDomain).DomainName

    # Check 1 & 2: Mailbox-level forwarding
    Write-Verbose "Checking mailbox-level forwarding..."
    $mailboxes = Get-Mailbox -ResultSize Unlimited |
        Where-Object { $_.ForwardingAddress -or $_.ForwardingSMTPAddress }

    foreach ($mbx in $mailboxes) {
        $target = if ($mbx.ForwardingSMTPAddress) { $mbx.ForwardingSMTPAddress.ToString() }
                  elseif ($mbx.ForwardingAddress) { $mbx.ForwardingAddress.ToString() }
                  else { '' }

        $isExternal = $true
        foreach ($domain in $acceptedDomains) {
            if ($target -like "*@$domain*" -or $target -like "*$domain*") {
                $isExternal = $false
                break
            }
        }

        if (-not $ExternalOnly -or $isExternal) {
            $results.Add([PSCustomObject]@{
                Mailbox            = $mbx.UserPrincipalName
                DisplayName        = $mbx.DisplayName
                RuleType           = 'MailboxForwarding'
                ForwardTo          = $target
                DeliverToMailbox   = $mbx.DeliverToMailboxAndForward
                IsExternal         = $isExternal
                RuleName           = 'N/A (Mailbox Setting)'
                Enabled            = $true
            })
        }
    }

    # Check 3: Inbox rules with forwarding
    Write-Verbose "Checking inbox rules (this may take a while)..."
    $allMailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox

    $total = $allMailboxes.Count
    $current = 0

    foreach ($mbx in $allMailboxes) {
        $current++
        if ($current % 50 -eq 0) {
            Write-Progress -Activity "Checking inbox rules" -Status "$($mbx.Alias) ($current/$total)" -PercentComplete (($current / $total) * 100)
        }

        try {
            $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue |
                Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }

            foreach ($rule in $rules) {
                $targets = @()
                if ($rule.ForwardTo)              { $targets += $rule.ForwardTo }
                if ($rule.ForwardAsAttachmentTo)  { $targets += $rule.ForwardAsAttachmentTo }
                if ($rule.RedirectTo)             { $targets += $rule.RedirectTo }

                foreach ($target in $targets) {
                    $targetStr = $target.ToString()
                    $isExternal = $true
                    foreach ($domain in $acceptedDomains) {
                        if ($targetStr -like "*@$domain*" -or $targetStr -like "*$domain*") {
                            $isExternal = $false
                            break
                        }
                    }

                    if (-not $ExternalOnly -or $isExternal) {
                        $results.Add([PSCustomObject]@{
                            Mailbox            = $mbx.UserPrincipalName
                            DisplayName        = $mbx.DisplayName
                            RuleType           = 'InboxRule'
                            ForwardTo          = $targetStr
                            DeliverToMailbox   = $null
                            IsExternal         = $isExternal
                            RuleName           = $rule.Name
                            Enabled            = $rule.Enabled
                        })
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not check rules for $($mbx.UserPrincipalName): $_"
        }
    }

    Write-Progress -Activity "Checking inbox rules" -Completed
    $results
}
