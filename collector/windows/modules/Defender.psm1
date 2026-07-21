Import-Module (Join-Path $PSScriptRoot "General.psm1")

function Get-CSADefenderEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $moduleStatus = ""
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        $errorItem = New-CSACollectionError "Defender" "NOT_SUPPORTED" "CSA-DEFENDER-NOT-SUPPORTED" "Microsoft Defender cmdlets are unavailable."
        return New-CSAModuleResult -Module "Defender" -Errors @($errorItem) -StartedAt $startedAt -Status "NOT_SUPPORTED"
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $preference = Get-MpPreference -ErrorAction Stop
        $now = (Get-Date).ToUniversalTime()
        $signatureUpdatedAt = $status.AntivirusSignatureLastUpdated
        $signatureAgeDays = if ($null -ne $signatureUpdatedAt) { [math]::Max(0, [int](($now - ([datetime]$signatureUpdatedAt).ToUniversalTime()).TotalDays)) } else { $null }
        $networkProtection = ([int]$preference.EnableNetworkProtection -eq 1)
        $controlledFolderAccess = ([int]$preference.EnableControlledFolderAccess -eq 1)
        $cloudProtection = ([int]$preference.MAPSReporting -gt 0)
        $sampleSubmission = ([int]$preference.SubmitSamplesConsent -ne 0)
        $puaProtection = ([int]$preference.PUAProtection -eq 1)
        $exclusions = @($preference.ExclusionPath) + @($preference.ExclusionExtension) + @($preference.ExclusionProcess)
        $riskyExclusions = @($exclusions | Where-Object {
            $value = [string]$_
            $value -match '^(?i)[A-Z]:\\?$|\\Users(\\|$)|\\Temp(\\|$)|^\*$|^\.'
        })

        $values = [ordered]@{
            DEFENDER_ENABLED = ([bool]$status.AMServiceEnabled -and [bool]$status.AntivirusEnabled)
            DEFENDER_REALTIME_PROTECTION_ENABLED = [bool]$status.RealTimeProtectionEnabled
            DEFENDER_BEHAVIOR_MONITORING_ENABLED = [bool]$status.BehaviorMonitorEnabled
            DEFENDER_IOAV_PROTECTION_ENABLED = [bool]$status.IoavProtectionEnabled
            DEFENDER_SCRIPT_SCANNING_ENABLED = (-not [bool]$preference.DisableScriptScanning)
            DEFENDER_CLOUD_PROTECTION_ENABLED = $cloudProtection
            DEFENDER_SAMPLE_SUBMISSION = $sampleSubmission
            DEFENDER_TAMPER_PROTECTION_ENABLED = [bool]$status.IsTamperProtected
            DEFENDER_PUA_PROTECTION_ENABLED = $puaProtection
            DEFENDER_NETWORK_PROTECTION_ENABLED = $networkProtection
            DEFENDER_CONTROLLED_FOLDER_ACCESS_ENABLED = $controlledFolderAccess
            DEFENDER_SIGNATURE_VERSION = [string]$status.AntivirusSignatureVersion
            DEFENDER_SIGNATURE_UPDATED_AT = if ($null -ne $signatureUpdatedAt) { ([datetime]$signatureUpdatedAt).ToUniversalTime().ToString("o") } else { $null }
            DEFENDER_SIGNATURE_AGE_DAYS = $signatureAgeDays
            DEFENDER_LAST_FULL_SCAN_AT = if ($null -ne $status.FullScanEndTime) { ([datetime]$status.FullScanEndTime).ToUniversalTime().ToString("o") } else { $null }
            DEFENDER_LAST_QUICK_SCAN_AT = if ($null -ne $status.QuickScanEndTime) { ([datetime]$status.QuickScanEndTime).ToUniversalTime().ToString("o") } else { $null }
            DEFENDER_EXCLUSION_COUNT = @($exclusions | Where-Object { $null -ne $_ }).Count
            DEFENDER_EXCLUSION_RISKY_COUNT = $riskyExclusions.Count
        }
        foreach ($name in $values.Keys) {
            $provider = if ($name -match 'CLOUD|SAMPLE|PUA|NETWORK|FOLDER|EXCLUSION|SCRIPT') { "Get-MpPreference" } else { "Get-MpComputerStatus" }
            $metadata = @{}
            if ($name -eq "DEFENDER_EXCLUSION_RISKY_COUNT") {
                $metadata = @{ exclusionDetailsSuppressed = $true; privacyMode = $PrivacyMode }
            }
            $settings += New-CSASetting $name "Defender" $values[$name] "SECURITY_PRODUCT" "SUCCESS" 90 $provider $name -Metadata $metadata
        }
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "Defender" "ACCESS_DENIED" "CSA-DEFENDER-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "Defender" -Settings $settings -Errors $errors -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "Defender" $moduleStatus "CSA-DEFENDER-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "Defender" -Settings $settings -Errors $errors -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSADefenderEvidence
