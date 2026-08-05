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
                Sid = Protect-CSAIdentifier ([string]$user.SID) $PrivacyMode
                Enabled = [bool]$user.Enabled
                LocalAccount = $true
                Classification = $classification
                AccountType = "USER"
                PasswordRequired = if ($null -ne $user.PasswordRequired) { [bool]$user.PasswordRequired } else { $null }
                PasswordExpires = if ($null -ne $user.PasswordExpires) { ([datetime]$user.PasswordExpires).ToUniversalTime().ToString("o") } else { $null }
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
                Sid = Protect-CSAIdentifier ([string]$_.SID) $PrivacyMode
                Classification = ConvertTo-CSAUserClassification $_.PrincipalSource $_.Name
                ObjectClass = [string]$_.ObjectClass
                Resolved = -not [string]::IsNullOrWhiteSpace([string]$_.Name)
            }
        })
        $settings += New-CSASetting "LOCAL_ADMINISTRATORS" "Accounts" $adminEvidence "RUNTIME_STATE" "SUCCESS" 90 "Get-LocalGroupMember" "S-1-5-32-544"
        $settings += New-CSASetting "LOCAL_ADMINISTRATOR_COUNT" "Accounts" $adminEvidence.Count "RUNTIME_STATE" "SUCCESS" 95 "Get-LocalGroupMember" "S-1-5-32-544.Count"
        $unresolvedAdminCount = @($adminEvidence | Where-Object { -not $_.Resolved -or $_.Classification -eq "UNKNOWN" }).Count
        $settings += New-CSASetting "UNRESOLVED_LOCAL_ADMINISTRATOR_COUNT" "Accounts" $unresolvedAdminCount "RUNTIME_STATE" "SUCCESS" 85 "Get-LocalGroupMember" "S-1-5-32-544.Unresolved"
        $adminNames = @($adminMembers | ForEach-Object { ([string]$_.Name).Split('\')[-1] })
        $activeLocalAdminCount = @($users | Where-Object { $_.Enabled -and $adminNames -contains $_.Name }).Count
        $settings += New-CSASetting "ACTIVE_LOCAL_ADMINISTRATOR_ACCOUNT_COUNT" "Accounts" $activeLocalAdminCount "RUNTIME_STATE" "SUCCESS" 85 "Get-LocalGroupMember/Get-LocalUser" "S-1-5-32-544.ActiveLocalUsers"
        $passwordNotRequiredCount = @($users | Where-Object { $_.Enabled -and $_.PasswordRequired -eq $false }).Count
        $settings += New-CSASetting "LOCAL_PASSWORD_NOT_REQUIRED_COUNT" "Accounts" $passwordNotRequiredCount "RUNTIME_STATE" "SUCCESS" 85 "Get-LocalUser" "PasswordRequired"

        $guest = @($users | Where-Object { [string]$_.SID -match '-501$' } | Select-Object -First 1)
        $administrator = @($users | Where-Object { [string]$_.SID -match '-500$' } | Select-Object -First 1)
        $settings += New-CSASetting "GUEST_ACCOUNT_ENABLED" "Accounts" ($guest.Count -gt 0 -and [bool]$guest[0].Enabled) "RUNTIME_STATE" "SUCCESS" 95 "Get-LocalUser" "SID-501.Enabled"
        $settings += New-CSASetting "BUILTIN_ADMINISTRATOR_ENABLED" "Accounts" ($administrator.Count -gt 0 -and [bool]$administrator[0].Enabled) "RUNTIME_STATE" "SUCCESS" 95 "Get-LocalUser" "SID-500.Enabled"
        $passwordNeverExpiresCount = @($users | Where-Object { $_.Enabled -and $_.PasswordNeverExpires -and (ConvertTo-CSAUserClassification $_.PrincipalSource $_.Name) -ne "SERVICE" }).Count
        $staleCount = @($users | Where-Object { $_.Enabled -and $null -ne $_.LastLogon -and ($now - [datetime]$_.LastLogon).TotalDays -gt 90 }).Count
        $settings += New-CSASetting "PASSWORD_NEVER_EXPIRES_INTERACTIVE_COUNT" "Accounts" $passwordNeverExpiresCount "RUNTIME_STATE" "SUCCESS" 85 "Get-LocalUser" "PasswordNeverExpires"
        $settings += New-CSASetting "STALE_ENABLED_LOCAL_ACCOUNT_COUNT" "Accounts" $staleCount "RUNTIME_STATE" "SUCCESS" 75 "Get-LocalUser" "LastLogon" -Metadata @{ thresholdDays = 90 }

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $currentUser = [ordered]@{
            Name = Protect-CSAIdentifier $identity.Name $PrivacyMode
            Sid = Protect-CSAIdentifier ([string]$identity.User.Value) $PrivacyMode
            Classification = ConvertTo-CSAUserClassification $null $identity.Name
        }
        $settings += New-CSASetting "CURRENT_EXECUTION_USER" "Accounts" $currentUser "RUNTIME_STATE" "SUCCESS" 100 "WindowsIdentity" "Current"
        $settings += New-CSASetting "LOGGED_ON_USERS" "Accounts" @($currentUser) "RUNTIME_STATE" "SUCCESS" 70 "WindowsIdentity" "CurrentInteractiveContext"

        try {
            $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | ForEach-Object {
                [ordered]@{
                    ProfileName = Protect-CSAIdentifier (Split-Path -Leaf ([string]$_.LocalPath)) $PrivacyMode
                    ProfilePath = Protect-CSAPath $_.LocalPath $PrivacyMode
                    Sid = Protect-CSAIdentifier ([string]$_.SID) $PrivacyMode
                    SpecialProfile = [bool]$_.Special
                    Loaded = [bool]$_.Loaded
                    LastUseTime = if ($null -ne $_.LastUseTime) { ([datetime]$_.LastUseTime).ToUniversalTime().ToString("o") } else { $null }
                }
            })
            $settings += New-CSASetting "USER_PROFILES" "Accounts" $profiles "RUNTIME_STATE" "SUCCESS" 85 "Win32_UserProfile" "LocalProfiles"
        } catch {
            $warnings += "User profile inventory was unavailable."
            $settings += New-CSASetting "USER_PROFILES" "Accounts" @() "RUNTIME_STATE" "NOT_AVAILABLE" 0 "Win32_UserProfile" "LocalProfiles" -ErrorCode "CSA-USER-PROFILES-NOT-AVAILABLE"
        }

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
