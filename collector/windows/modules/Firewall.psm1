Import-Module (Join-Path $PSScriptRoot "General.psm1")

function Get-CSAFirewallEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $moduleStatus = ""
    if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        $errorItem = New-CSACollectionError "Firewall" "NOT_SUPPORTED" "CSA-FIREWALL-NOT-SUPPORTED" "NetSecurity firewall cmdlets are unavailable."
        return New-CSAModuleResult -Module "Firewall" -Errors @($errorItem) -StartedAt $startedAt -Status "NOT_SUPPORTED"
    }

    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        foreach ($profile in $profiles) {
            $profileName = ([string]$profile.Name).ToUpperInvariant()
            $prefix = "WINDOWS_FIREWALL_$profileName"
            $sourcePath = "MSFT_NetFirewallProfile/$($profile.Name)"
            $values = [ordered]@{
                ENABLED = [bool]$profile.Enabled
                DEFAULT_INBOUND_ACTION = [string]$profile.DefaultInboundAction
                DEFAULT_OUTBOUND_ACTION = [string]$profile.DefaultOutboundAction
                NOTIFY_ON_LISTEN = [bool]$profile.NotifyOnListen
                ALLOW_INBOUND_RULES = [bool]$profile.AllowInboundRules
                ALLOW_LOCAL_FIREWALL_RULES = [bool]$profile.AllowLocalFirewallRules
                ALLOW_LOCAL_IPSEC_RULES = [bool]$profile.AllowLocalIPsecRules
                LOG_ALLOWED = [bool]$profile.LogAllowed
                LOG_BLOCKED = [bool]$profile.LogBlocked
                LOG_IGNORED = [bool]$profile.LogIgnored
                LOG_FILE_NAME = Protect-CSAPath $profile.LogFileName $PrivacyMode
                LOG_MAX_SIZE_KILOBYTES = [int]$profile.LogMaxSizeKilobytes
            }
            foreach ($name in $values.Keys) {
                $settings += New-CSASetting "$prefix`_$name" "Firewall" $values[$name] "RUNTIME_STATE" "SUCCESS" 90 "Get-NetFirewallProfile" "$sourcePath/$name"
            }
        }

        $settings += New-CSASetting "WINDOWS_FIREWALL_INBOUND_DEFAULT_BLOCK" "Firewall" (@($profiles | Where-Object { [string]$_.DefaultInboundAction -ne "Block" }).Count -eq 0) "RUNTIME_STATE" "SUCCESS" 90 "Get-NetFirewallProfile" "AllProfiles.DefaultInboundAction"
        $settings += New-CSASetting "WINDOWS_FIREWALL_LOG_BLOCKED_ENABLED" "Firewall" (@($profiles | Where-Object { -not [bool]$_.LogBlocked }).Count -eq 0) "RUNTIME_STATE" "SUCCESS" 90 "Get-NetFirewallProfile" "AllProfiles.LogBlocked"

        $service = Get-Service -Name MpsSvc -ErrorAction Stop
        $serviceEnabled = ([string]$service.StartType -ne "Disabled")
        $settings += New-CSASetting "WINDOWS_FIREWALL_SERVICE_ENABLED" "Firewall" $serviceEnabled "RUNTIME_STATE" "SUCCESS" 90 "Get-Service" "MpsSvc.StartType"

        $activeProfiles = @()
        if (Get-Command Get-NetConnectionProfile -ErrorAction SilentlyContinue) {
            $activeProfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.NetworkCategory } | Select-Object -Unique)
        }
        $settings += New-CSASetting "ACTIVE_FIREWALL_PROFILE" "Firewall" $activeProfiles "RUNTIME_STATE" "SUCCESS" 85 "Get-NetConnectionProfile" "NetworkCategory"
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "Firewall" "ACCESS_DENIED" "CSA-FIREWALL-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "Firewall" -Settings $settings -Errors $errors -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "Firewall" $moduleStatus "CSA-FIREWALL-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "Firewall" -Settings $settings -Errors $errors -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSAFirewallEvidence
