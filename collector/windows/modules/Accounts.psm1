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
    param([string]$PrivacyMode = "Standard", [scriptblock]$PasswordPolicyProvider = $null)

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $warnings = @()
    $moduleStatus = ""
    $passwordPolicy = Get-CSAPasswordPolicyEvidence -Provider $PasswordPolicyProvider
    $settings += $passwordPolicy.Settings
    $errors += $passwordPolicy.Errors
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

    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "Accounts" "ACCESS_DENIED" "CSA-ACCOUNTS-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "Accounts" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status $(if (@($settings | Where-Object { $_.collectionStatus -eq "SUCCESS" }).Count -gt 0) { "PARTIAL" } else { "ACCESS_DENIED" })
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "Accounts" $moduleStatus "CSA-ACCOUNTS-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "Accounts" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status $moduleStatus
}


function Invoke-CSANetUserModals {
    param([int]$Level)
    if (-not ("CSA.Native.PasswordPolicy" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CSA.Native {
    [StructLayout(LayoutKind.Sequential)]
    public struct UserModals0 {
        public uint MinimumLength, MaximumAge, MinimumAge, ForceLogoff, HistoryLength;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct UserModals3 {
        public uint LockoutDuration, ObservationWindow, LockoutThreshold;
    }
    public static class PasswordPolicy {
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetUserModalsGet(string server, uint level, out IntPtr buffer);
        [DllImport("Netapi32.dll")]
        private static extern uint NetApiBufferFree(IntPtr buffer);
        public static object Read(uint level) {
            IntPtr buffer = IntPtr.Zero;
            try {
                uint result = NetUserModalsGet(null, level, out buffer);
                if (result == 5) throw new UnauthorizedAccessException("Password policy access denied");
                if (result != 0) throw new System.ComponentModel.Win32Exception((int)result);
                if (buffer == IntPtr.Zero) throw new InvalidOperationException("Policy API returned no buffer");
                if (level == 0) return Marshal.PtrToStructure(buffer, typeof(UserModals0));
                if (level == 3) return Marshal.PtrToStructure(buffer, typeof(UserModals3));
                throw new ArgumentOutOfRangeException("level");
            } finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
        }
    }
}
'@
    }
    [CSA.Native.PasswordPolicy]::Read([uint32]$Level)
}

function Get-CSAPasswordPolicyEvidence {
    param([scriptblock]$Provider = $null)
    $settings = @()
    $errors = @()
    $levels = @(
        @{ Level = 0; Fields = @(
            @{ Id = "PASSWORD_POLICY_MINIMUM_LENGTH"; Name = "MinimumLength"; Divisor = 1 },
            @{ Id = "PASSWORD_POLICY_MIN_LENGTH"; Name = "MinimumLength"; Divisor = 1 },
            @{ Id = "PASSWORD_POLICY_MINIMUM_AGE_DAYS"; Name = "MinimumAge"; Divisor = 86400 },
            @{ Id = "PASSWORD_POLICY_MAXIMUM_AGE_DAYS"; Name = "MaximumAge"; Divisor = 86400 },
            @{ Id = "PASSWORD_POLICY_HISTORY"; Name = "HistoryLength"; Divisor = 1 }
        ) },
        @{ Level = 3; Fields = @(
            @{ Id = "ACCOUNT_LOCKOUT_THRESHOLD"; Name = "LockoutThreshold"; Divisor = 1 },
            @{ Id = "ACCOUNT_LOCKOUT_DURATION_MINUTES"; Name = "LockoutDuration"; Divisor = 60 },
            @{ Id = "ACCOUNT_LOCKOUT_OBSERVATION_WINDOW_MINUTES"; Name = "ObservationWindow"; Divisor = 60 }
        ) }
    )
    foreach ($spec in $levels) {
        try {
            $policy = if ($null -ne $Provider) { & $Provider $spec.Level } else { Invoke-CSANetUserModals -Level $spec.Level }
            $levelSettings = @()
            foreach ($field in $spec.Fields) {
                $raw = $policy.($field.Name)
                if ($null -eq $raw -or $raw -is [bool] -or $raw -is [string] -or [double]$raw -lt 0 -or [double]$raw -gt [uint32]::MaxValue) { throw "Invalid structured policy value" }
                $forever = ([uint64]$raw -eq [uint32]::MaxValue)
                $value = if ($forever) { 0 } else { [double]$raw / $field.Divisor }
                $levelSettings += New-CSASetting $field.Id "Accounts" $value "LOCAL_POLICY" "SUCCESS" 95 "NetUserModalsGet" ("Level{0}/{1}" -f $spec.Level, $field.Name) -Metadata @{ rawValue = [uint64]$raw; timeForever = $forever; scope = "Local account password policy, not actual password strength" }
            }
            $settings += $levelSettings
        } catch {
            $status = Resolve-CSAExceptionStatus $_
            if ($status -eq "FAILED") { $status = "NOT_AVAILABLE" }
            $errors += New-CSACollectionError "Accounts" $status "CSA-PASSWORD-POLICY-UNAVAILABLE" ("Structured password policy level {0} unavailable; no localized-text inference used." -f $spec.Level)
            foreach ($field in $spec.Fields) {
                $settings += New-CSASetting $field.Id "Accounts" $null "LOCAL_POLICY" $status 0 "NetUserModalsGet" ("Level{0}/{1}" -f $spec.Level, $field.Name)
            }
        }
    }
    return @{ Settings = $settings; Errors = $errors }
}

Export-ModuleMember -Function Get-CSAAccountsEvidence, Get-CSAPasswordPolicyEvidence
