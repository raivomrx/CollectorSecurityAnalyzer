Import-Module (Join-Path $PSScriptRoot "General.psm1")

function ConvertTo-CSAUserClassification {
    param($PrincipalSource, [string]$Name)

    $source = [string]$PrincipalSource
    if ($source -match "AzureAD|Entra") { return "ENTRA" }
    if ($source -match "ActiveDirectory") { return "DOMAIN" }
    if ($source -match "Local") { return "LOCAL" }
    if ($Name -match '^(?i)(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-|DefaultAccount|WDAGUtilityAccount)') { return "SERVICE" }
    return "UNKNOWN"
}

function Get-CSAAccountsEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $warnings = @()
    $moduleStatus = ""
    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        $errorItem = New-CSACollectionError "Accounts" "NOT_SUPPORTED" "CSA-ACCOUNTS-NOT-SUPPORTED" "Microsoft.PowerShell.LocalAccounts cmdlets are unavailable."
        return New-CSAModuleResult -Module "Accounts" -Errors @($errorItem) -StartedAt $startedAt -Status "NOT_SUPPORTED"
    }

    try {
        $now = Get-Date
        $users = @(Get-LocalUser -ErrorAction Stop)
        $userEvidence = @()
        foreach ($user in $users) {
            $classification = ConvertTo-CSAUserClassification $user.PrincipalSource $user.Name
            $userEvidence += [ordered]@{
                Name = Protect-CSAIdentifier $user.Name $PrivacyMode
                Enabled = [bool]$user.Enabled
                Classification = $classification
                PasswordNeverExpires = [bool]$user.PasswordNeverExpires
                LastLogon = if ($null -ne $user.LastLogon) { ([datetime]$user.LastLogon).ToUniversalTime().ToString("o") } else { $null }
                SidSuffix = if ($null -ne $user.SID) { ([string]$user.SID).Split('-')[-1] } else { $null }
            }
        }
        $settings += New-CSASetting "LOCAL_USERS" "Accounts" $userEvidence "RUNTIME_STATE" "SUCCESS" 90 "Get-LocalUser" "LocalUsers"

        $adminMembers = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop)
        $adminEvidence = @($adminMembers | ForEach-Object {
            [ordered]@{
                Name = Protect-CSAIdentifier $_.Name $PrivacyMode
                Classification = ConvertTo-CSAUserClassification $_.PrincipalSource $_.Name
                ObjectClass = [string]$_.ObjectClass
            }
        })
        $settings += New-CSASetting "LOCAL_ADMINISTRATORS" "Accounts" $adminEvidence "RUNTIME_STATE" "SUCCESS" 90 "Get-LocalGroupMember" "S-1-5-32-544"
        $settings += New-CSASetting "LOCAL_ADMINISTRATOR_COUNT" "Accounts" $adminEvidence.Count "RUNTIME_STATE" "SUCCESS" 95 "Get-LocalGroupMember" "S-1-5-32-544.Count"

        $guest = @($users | Where-Object { [string]$_.SID -match '-501$' } | Select-Object -First 1)
        $administrator = @($users | Where-Object { [string]$_.SID -match '-500$' } | Select-Object -First 1)
        $settings += New-CSASetting "GUEST_ACCOUNT_ENABLED" "Accounts" ($guest.Count -gt 0 -and [bool]$guest[0].Enabled) "RUNTIME_STATE" "SUCCESS" 95 "Get-LocalUser" "SID-501.Enabled"
        $settings += New-CSASetting "BUILTIN_ADMINISTRATOR_ENABLED" "Accounts" ($administrator.Count -gt 0 -and [bool]$administrator[0].Enabled) "RUNTIME_STATE" "SUCCESS" 95 "Get-LocalUser" "SID-500.Enabled"
        $passwordNeverExpiresCount = @($users | Where-Object { $_.Enabled -and $_.PasswordNeverExpires -and (ConvertTo-CSAUserClassification $_.PrincipalSource $_.Name) -ne "SERVICE" }).Count
        $staleCount = @($users | Where-Object { $_.Enabled -and $null -ne $_.LastLogon -and ($now - [datetime]$_.LastLogon).TotalDays -gt 90 }).Count
        $settings += New-CSASetting "PASSWORD_NEVER_EXPIRES_INTERACTIVE_COUNT" "Accounts" $passwordNeverExpiresCount "RUNTIME_STATE" "SUCCESS" 85 "Get-LocalUser" "PasswordNeverExpires"
        $settings += New-CSASetting "STALE_ENABLED_LOCAL_ACCOUNT_COUNT" "Accounts" $staleCount "RUNTIME_STATE" "SUCCESS" 75 "Get-LocalUser" "LastLogon" -Metadata @{ thresholdDays = 90 }

        $netAccounts = @(& net.exe accounts 2>$null)
        $numericValues = @($netAccounts | ForEach-Object {
            if ($_ -match ':\s*(\d+|Never)\s*$') { $Matches[1] }
        })
        if ($numericValues.Count -ge 7) {
            $maxAge = if ($numericValues[0] -eq "Never") { 0 } else { [int]$numericValues[0] }
            $minimumLength = [int]$numericValues[3]
            $history = [int]$numericValues[4]
            $threshold = [int]$numericValues[5]
            $lockoutDuration = [int]$numericValues[6]
            $settings += New-CSASetting "PASSWORD_POLICY_MINIMUM_LENGTH" "Accounts" $minimumLength "LOCAL_POLICY" "SUCCESS" 70 "net accounts" "MinimumPasswordLength"
            $settings += New-CSASetting "PASSWORD_POLICY_MIN_LENGTH" "Accounts" $minimumLength "LOCAL_POLICY" "SUCCESS" 70 "net accounts" "MinimumPasswordLength"
            $settings += New-CSASetting "PASSWORD_POLICY_MAXIMUM_AGE_DAYS" "Accounts" $maxAge "LOCAL_POLICY" "SUCCESS" 70 "net accounts" "MaximumPasswordAge"
            $settings += New-CSASetting "PASSWORD_POLICY_HISTORY" "Accounts" $history "LOCAL_POLICY" "SUCCESS" 70 "net accounts" "PasswordHistoryLength"
            $settings += New-CSASetting "ACCOUNT_LOCKOUT_THRESHOLD" "Accounts" $threshold "LOCAL_POLICY" "SUCCESS" 70 "net accounts" "LockoutThreshold"
            $settings += New-CSASetting "ACCOUNT_LOCKOUT_DURATION_MINUTES" "Accounts" $lockoutDuration "LOCAL_POLICY" "SUCCESS" 70 "net accounts" "LockoutDuration"
        } else {
            $warnings += "Password policy output could not be parsed reliably."
        }
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "Accounts" "ACCESS_DENIED" "CSA-ACCOUNTS-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "Accounts" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "Accounts" $moduleStatus "CSA-ACCOUNTS-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "Accounts" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSAAccountsEvidence
