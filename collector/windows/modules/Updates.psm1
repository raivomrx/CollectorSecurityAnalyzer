Import-Module (Join-Path $PSScriptRoot "General.psm1")

function Get-CSAUpdatesEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $warnings = @()
    $moduleStatus = ""
    $now = (Get-Date).ToUniversalTime()
    try {
        $lastScan = $null
        $lastInstall = $null
        try {
            $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
            $lastScan = $autoUpdate.Results.LastSearchSuccessDate
            $lastInstall = $autoUpdate.Results.LastInstallationSuccessDate
        } catch {
            $warnings += "Windows Update COM history was not available."
        }
        $scanAge = if ($null -ne $lastScan -and [datetime]$lastScan -gt [datetime]::MinValue) { [math]::Max(0, [int](($now - ([datetime]$lastScan).ToUniversalTime()).TotalDays)) } else { $null }
        $installAge = if ($null -ne $lastInstall -and [datetime]$lastInstall -gt [datetime]::MinValue) { [math]::Max(0, [int](($now - ([datetime]$lastInstall).ToUniversalTime()).TotalDays)) } else { $null }
        $historyStatus = if ($null -ne $lastScan -or $null -ne $lastInstall) { "SUCCESS" } else { "NOT_AVAILABLE" }
        $historyConfidence = if ($historyStatus -eq "SUCCESS") { 85 } else { 0 }
        $settings += New-CSASetting "UPDATE_LAST_SCAN_AT" "Updates" $(if ($null -ne $lastScan) { ([datetime]$lastScan).ToUniversalTime().ToString("o") } else { $null }) "RUNTIME_STATE" $historyStatus $historyConfidence "Microsoft.Update.AutoUpdate" "Results.LastSearchSuccessDate"
        $settings += New-CSASetting "UPDATE_LAST_INSTALL_AT" "Updates" $(if ($null -ne $lastInstall) { ([datetime]$lastInstall).ToUniversalTime().ToString("o") } else { $null }) "RUNTIME_STATE" $historyStatus $historyConfidence "Microsoft.Update.AutoUpdate" "Results.LastInstallationSuccessDate"
        $settings += New-CSASetting "UPDATE_SCAN_AGE_DAYS" "Updates" $scanAge "RUNTIME_STATE" $historyStatus $historyConfidence "Microsoft.Update.AutoUpdate" "Results.LastSearchSuccessDate"
        $settings += New-CSASetting "UPDATE_INSTALL_AGE_DAYS" "Updates" $installAge "RUNTIME_STATE" $historyStatus $historyConfidence "Microsoft.Update.AutoUpdate" "Results.LastInstallationSuccessDate"
        $settings += New-CSASetting "WINDOWS_UPDATE_LAST_SCAN_AGE_DAYS" "Updates" $scanAge "RUNTIME_STATE" $historyStatus $historyConfidence "Microsoft.Update.AutoUpdate" "Results.LastSearchSuccessDate"
        $settings += New-CSASetting "WINDOWS_UPDATE_LAST_INSTALL_AGE_DAYS" "Updates" $installAge "RUNTIME_STATE" $historyStatus $historyConfidence "Microsoft.Update.AutoUpdate" "Results.LastInstallationSuccessDate"

        $pendingPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        )
        $pendingReboot = @($pendingPaths | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0
        $pendingSince = $null
        $pendingAge = $null
        $pendingAgeStatus = if ($pendingReboot) { "NOT_AVAILABLE" } else { "SUCCESS" }
        if (-not $pendingReboot) { $pendingAge = 0 }
        $settings += New-CSASetting "PENDING_REBOOT" "Updates" $pendingReboot "REGISTRY" "SUCCESS" 90 "Registry" "RebootPending keys"
        $settings += New-CSASetting "WINDOWS_UPDATE_PENDING_REBOOT" "Updates" $pendingReboot "REGISTRY" "SUCCESS" 90 "Registry" "RebootPending keys"
        $settings += New-CSASetting "PENDING_REBOOT_SINCE" "Updates" $pendingSince "REGISTRY" $pendingAgeStatus $(if ($pendingReboot) { 0 } else { 90 }) "Registry" "RebootPending keys"
        $settings += New-CSASetting "PENDING_REBOOT_AGE_DAYS" "Updates" $pendingAge "REGISTRY" $pendingAgeStatus $(if ($pendingReboot) { 0 } else { 90 }) "Registry" "RebootPending keys"
        $settings += New-CSASetting "WINDOWS_UPDATE_PENDING_REBOOT_AGE_DAYS" "Updates" $pendingAge "REGISTRY" $pendingAgeStatus $(if ($pendingReboot) { 0 } else { 90 }) "Registry" "RebootPending keys"

        $wuauserv = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        $usoSvc = Get-Service -Name UsoSvc -ErrorAction SilentlyContinue
        $settings += New-CSASetting "WINDOWS_UPDATE_SERVICE_ENABLED" "Updates" ($null -ne $wuauserv -and [string]$wuauserv.StartType -ne "Disabled") "RUNTIME_STATE" "SUCCESS" 90 "Get-Service" "wuauserv.StartType"
        $settings += New-CSASetting "UPDATE_ORCHESTRATOR_SERVICE_ENABLED" "Updates" ($null -ne $usoSvc -and [string]$usoSvc.StartType -ne "Disabled") "RUNTIME_STATE" "SUCCESS" 90 "Get-Service" "UsoSvc.StartType"

        $wuPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $auPolicy = "$wuPolicy\AU"
        $wsusServer = Get-CSARegistryValue $wuPolicy "WUServer" $null
        $useWuserver = Get-CSARegistryValue $auPolicy "UseWUServer" 0
        $wsusConfigured = ($null -ne $wsusServer -and [int]$useWuserver -eq 1)
        $settings += New-CSASetting "WSUS_CONFIGURED" "Updates" $wsusConfigured "GROUP_POLICY" "SUCCESS" 85 "Registry" "WindowsUpdate/WUServer"
        $settings += New-CSASetting "MICROSOFT_UPDATE_ENABLED" "Updates" (-not $wsusConfigured) "GROUP_POLICY" "SUCCESS" 70 "Registry" "WindowsUpdate/AU/UseWUServer"
        $targetRelease = Get-CSARegistryValue $wuPolicy "TargetReleaseVersionInfo" $null
        $currentRelease = Get-CSARegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "DisplayVersion" $null
        $targetMatch = if ($null -eq $targetRelease) { $true } else { [string]$targetRelease -eq [string]$currentRelease }
        $settings += New-CSASetting "TARGET_RELEASE_VERSION" "Updates" $targetRelease "GROUP_POLICY" "SUCCESS" 85 "Registry" "WindowsUpdate/TargetReleaseVersionInfo"
        $settings += New-CSASetting "WINDOWS_RELEASE_TARGET_MATCH" "Updates" $targetMatch "GROUP_POLICY" "SUCCESS" 80 "Registry" "TargetReleaseVersionInfo vs DisplayVersion" -Metadata @{ currentRelease = $currentRelease }
        $settings += New-CSASetting "QUALITY_UPDATE_DEFERRAL_DAYS" "Updates" ([int](Get-CSARegistryValue $wuPolicy "DeferQualityUpdatesPeriodInDays" 0)) "GROUP_POLICY" "SUCCESS" 85 "Registry" "WindowsUpdate/DeferQualityUpdatesPeriodInDays"
        $settings += New-CSASetting "FEATURE_UPDATE_DEFERRAL_DAYS" "Updates" ([int](Get-CSARegistryValue $wuPolicy "DeferFeatureUpdatesPeriodInDays" 0)) "GROUP_POLICY" "SUCCESS" 85 "Registry" "WindowsUpdate/DeferFeatureUpdatesPeriodInDays"
        $pauseStart = Get-CSARegistryValue $wuPolicy "PauseUpdatesStartTime" $null
        $settings += New-CSASetting "UPDATE_PAUSED" "Updates" ($null -ne $pauseStart) "GROUP_POLICY" "SUCCESS" 80 "Registry" "WindowsUpdate/PauseUpdatesStartTime"
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "Updates" "ACCESS_DENIED" "CSA-UPDATES-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "Updates" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "Updates" $moduleStatus "CSA-UPDATES-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "Updates" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSAUpdatesEvidence
