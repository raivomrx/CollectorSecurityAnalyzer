Import-Module (Join-Path $PSScriptRoot "General.psm1")
Import-Module (Join-Path $PSScriptRoot "SecurityCenter.psm1")

function Get-CSADefenderEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $moduleStatus = ""
    try {
        $products = @(Get-CSARegisteredAntivirusProducts)
        $settings += New-CSASetting "ANTIVIRUS_REGISTERED_PRODUCTS" "Defender" $products "SECURITY_PRODUCT" "SUCCESS" 90 "IWSCProductList" "AntivirusProducts"
    } catch {
        $errors += New-CSACollectionError "Defender" "NOT_AVAILABLE" "CSA-AV-REGISTRATION-UNAVAILABLE" "Windows Security Center antivirus product state could not be read."
        $settings += New-CSASetting "ANTIVIRUS_REGISTERED_PRODUCTS" "Defender" $null "SECURITY_PRODUCT" "NOT_AVAILABLE" 0 "IWSCProductList" "AntivirusProducts" "CSA-AV-REGISTRATION-UNAVAILABLE"
    }
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        $errorItem = New-CSACollectionError "Defender" "NOT_SUPPORTED" "CSA-DEFENDER-NOT-SUPPORTED" "Microsoft Defender cmdlets are unavailable."
        return New-CSAModuleResult -Module "Defender" -Settings $settings -Errors @($errors + $errorItem) -StartedAt $startedAt -Status "PARTIAL"
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $now = (Get-Date).ToUniversalTime()
        $signatureUpdatedAt = $status.AntivirusSignatureLastUpdated
        $signatureAgeDays = if ($null -ne $signatureUpdatedAt) { [math]::Max(0, [int](($now - ([datetime]$signatureUpdatedAt).ToUniversalTime()).TotalDays)) } else { $null }
        $values = [ordered]@{
            DEFENDER_ENABLED = if ($status.AMServiceEnabled -is [bool] -and $status.AntivirusEnabled -is [bool]) { [bool]$status.AMServiceEnabled -and [bool]$status.AntivirusEnabled } else { $null }
            DEFENDER_REALTIME_PROTECTION_ENABLED = if ($status.RealTimeProtectionEnabled -is [bool]) { [bool]$status.RealTimeProtectionEnabled } else { $null }
            DEFENDER_BEHAVIOR_MONITORING_ENABLED = [bool]$status.BehaviorMonitorEnabled
            DEFENDER_IOAV_PROTECTION_ENABLED = [bool]$status.IoavProtectionEnabled
            DEFENDER_TAMPER_PROTECTION_ENABLED = [bool]$status.IsTamperProtected
            DEFENDER_SIGNATURE_VERSION = [string]$status.AntivirusSignatureVersion
            DEFENDER_SIGNATURE_UPDATED_AT = if ($null -ne $signatureUpdatedAt) { ([datetime]$signatureUpdatedAt).ToUniversalTime().ToString("o") } else { $null }
            DEFENDER_SIGNATURE_AGE_DAYS = $signatureAgeDays
            DEFENDER_LAST_FULL_SCAN_AT = if ($null -ne $status.FullScanEndTime) { ([datetime]$status.FullScanEndTime).ToUniversalTime().ToString("o") } else { $null }
            DEFENDER_LAST_QUICK_SCAN_AT = if ($null -ne $status.QuickScanEndTime) { ([datetime]$status.QuickScanEndTime).ToUniversalTime().ToString("o") } else { $null }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$status.AMRunningMode)) {
            $values.DEFENDER_RUNNING_MODE = [string]$status.AMRunningMode
        }
        foreach ($name in $values.Keys) {
            $collectionStatus = if ($null -eq $values[$name]) { "PARTIAL" } else { "SUCCESS" }
            $settings += New-CSASetting $name "Defender" $values[$name] "SECURITY_PRODUCT" $collectionStatus 90 "Get-MpComputerStatus" $name
        }
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "Defender" "ACCESS_DENIED" "CSA-DEFENDER-ACCESS-DENIED" $_.Exception.Message
        $moduleStatus = "PARTIAL"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "Defender" $moduleStatus "CSA-DEFENDER-COLLECTION-FAILED" $_.Exception.Message
    }
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        try {
            $preference = Get-MpPreference -ErrorAction Stop
            $exclusions = @($preference.ExclusionPath) + @($preference.ExclusionExtension) + @($preference.ExclusionProcess)
            $riskyExclusions = @($exclusions | Where-Object {
                $value = [string]$_
                $value -match '^(?i)[A-Z]:\\?$|\\Users(\\|$)|\\Temp(\\|$)|^\*$|^\.'
            })
            $preferenceValues = [ordered]@{
                DEFENDER_SCRIPT_SCANNING_ENABLED = if ($null -ne $preference.DisableScriptScanning) { -not [bool]$preference.DisableScriptScanning } else { $null }
                DEFENDER_CLOUD_PROTECTION_ENABLED = if ($null -ne $preference.MAPSReporting) { [int]$preference.MAPSReporting -gt 0 } else { $null }
                DEFENDER_SAMPLE_SUBMISSION = if ($null -ne $preference.SubmitSamplesConsent) { [int]$preference.SubmitSamplesConsent -ne 0 } else { $null }
                DEFENDER_PUA_PROTECTION_ENABLED = if ($null -ne $preference.PUAProtection) { [int]$preference.PUAProtection -eq 1 } else { $null }
                DEFENDER_NETWORK_PROTECTION_ENABLED = if ($null -ne $preference.EnableNetworkProtection) { [int]$preference.EnableNetworkProtection -eq 1 } else { $null }
                DEFENDER_CONTROLLED_FOLDER_ACCESS_ENABLED = if ($null -ne $preference.EnableControlledFolderAccess) { [int]$preference.EnableControlledFolderAccess -eq 1 } else { $null }
                DEFENDER_EXCLUSION_COUNT = @($exclusions | Where-Object { $null -ne $_ }).Count
                DEFENDER_EXCLUSION_RISKY_COUNT = $riskyExclusions.Count
            }
            foreach ($name in $preferenceValues.Keys) {
                $metadata = if ($name -eq "DEFENDER_EXCLUSION_RISKY_COUNT") { @{ exclusionDetailsSuppressed = $true; privacyMode = $PrivacyMode } } else { @{} }
                $collectionStatus = if ($null -eq $preferenceValues[$name]) { "PARTIAL" } else { "SUCCESS" }
                $settings += New-CSASetting $name "Defender" $preferenceValues[$name] "SECURITY_PRODUCT" $collectionStatus 90 "Get-MpPreference" $name -Metadata $metadata
            }
        } catch {
            $errors += New-CSACollectionError "Defender" (Resolve-CSAExceptionStatus $_) "CSA-DEFENDER-PREFERENCE-FAILED" $_.Exception.Message
        }
    } else {
        $errors += New-CSACollectionError "Defender" "NOT_SUPPORTED" "CSA-DEFENDER-PREFERENCE-UNAVAILABLE" "Microsoft Defender preferences could not be read."
    }
    New-CSAModuleResult -Module "Defender" -Settings $settings -Errors $errors -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSADefenderEvidence
