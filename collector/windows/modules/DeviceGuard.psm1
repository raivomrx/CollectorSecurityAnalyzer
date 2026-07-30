Import-Module (Join-Path $PSScriptRoot "General.psm1")

function ConvertTo-CSANullableBoolean {
    param($Value)

    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]) {
        if ([int64]$Value -eq 0) { return $false }
        if ([int64]$Value -eq 1) { return $true }
    }
    $text = [string]$Value
    if ($text -match '^(?i:true|false)$') {
        return [System.Convert]::ToBoolean($text)
    }
    return $null
}

function Get-CSATpmToolState {
    param([scriptblock]$Provider = $null)

    $lines = if ($null -ne $Provider) {
        @(& $Provider)
    } else {
        $tool = Join-Path $env:SystemRoot "System32\tpmtool.exe"
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { return $null }
        @(& $tool getdeviceinformation 2>$null)
    }
    $text = $lines -join "`n"
    $presentMatch = [regex]::Match(
        $text,
        '(?im)^\s*-?\s*TPM\s+Present\s*:\s*(True|False)\s*$'
    )
    $readyMatch = [regex]::Match(
        $text,
        '(?im)^\s*-?\s*TPM\s+Ready\s+for\s+Storage\s*:\s*(True|False)\s*$'
    )
    if (-not $presentMatch.Success -or -not $readyMatch.Success) {
        return $null
    }
    return [ordered]@{
        TpmPresent = [System.Convert]::ToBoolean($presentMatch.Groups[1].Value)
        TpmReady = [System.Convert]::ToBoolean($readyMatch.Groups[1].Value)
        TpmEnabled = $null
        TpmActivated = $null
        Provider = "tpmtool.exe"
        Confidence = 85
    }
}

function Get-CSADeviceGuardEvidence {
    param(
        [string]$PrivacyMode = "Standard",
        [scriptblock]$SecureBootProvider = $null,
        [scriptblock]$SecureBootRegistryProvider = $null,
        [scriptblock]$TpmProvider = $null,
        [scriptblock]$TpmFallbackProvider = $null
    )

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $warnings = @()

    try {
        $secureBoot = $null
        $secureBootError = $null
        $secureBootAttempted = $false
        try {
            if ($null -ne $SecureBootProvider) {
                $secureBootAttempted = $true
                $secureBoot = ConvertTo-CSANullableBoolean (& $SecureBootProvider)
            } elseif (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
                $secureBootAttempted = $true
                $secureBoot = ConvertTo-CSANullableBoolean (
                    Confirm-SecureBootUEFI -ErrorAction Stop
                )
            }
            if ($secureBootAttempted -and $null -eq $secureBoot) {
                throw "Secure Boot runtime state was unavailable."
            }
        } catch {
            $secureBootError = $_
        }
        if ($null -ne $secureBoot) {
            $settings += New-CSASetting "SECURE_BOOT_ENABLED" "Device Security" $secureBoot "RUNTIME_STATE" "SUCCESS" 95 "Confirm-SecureBootUEFI" "SecureBoot"
        } else {
            $primaryErrorStatus = if ($null -ne $secureBootError) {
                Resolve-CSAExceptionStatus $secureBootError
            } else {
                "NOT_AVAILABLE"
            }
            $registryAllowed = $null -eq $secureBootError -or (
                $primaryErrorStatus -notin @("ACCESS_DENIED", "NOT_SUPPORTED")
            )
            $registryState = if ($registryAllowed) {
                if ($null -ne $SecureBootRegistryProvider) {
                    ConvertTo-CSANullableBoolean (& $SecureBootRegistryProvider)
                } else {
                    ConvertTo-CSANullableBoolean (
                        Get-CSARegistryValue `
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" `
                            "UEFISecureBootEnabled" `
                            $null
                    )
                }
            } else {
                $null
            }
            if ($null -ne $registryState) {
                $settings += New-CSASetting "SECURE_BOOT_ENABLED" "Device Security" $registryState "REGISTRY" "SUCCESS" 80 "Windows Registry" "SecureBoot.State.UEFISecureBootEnabled"
            } else {
                $message = if ($null -ne $secureBootError) {
                    [string]$secureBootError.Exception.Message
                } else {
                    "Secure Boot state was unavailable."
                }
                $status = if ($null -ne $secureBootError) {
                    Resolve-CSAExceptionStatus $secureBootError
                } else {
                    "NOT_AVAILABLE"
                }
                if ($status -eq "FAILED") { $status = "NOT_AVAILABLE" }
                $settings += New-CSASetting "SECURE_BOOT_ENABLED" "Device Security" $null "RUNTIME_STATE" $status 0 "Confirm-SecureBootUEFI/Registry" "SecureBoot" "CSA-SECURE-BOOT-NOT-EVALUATED" $message
            }
        }

        $tpm = $null
        $tpmError = $null
        try {
            if ($null -ne $TpmProvider) {
                $tpm = & $TpmProvider
            } elseif (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
                $tpm = Get-Tpm -ErrorAction Stop
            }
        } catch {
            $tpmError = $_
        }
        $tpmValues = [ordered]@{
            TPM_PRESENT = if ($null -ne $tpm) { ConvertTo-CSANullableBoolean $tpm.TpmPresent } else { $null }
            TPM_READY = if ($null -ne $tpm) { ConvertTo-CSANullableBoolean $tpm.TpmReady } else { $null }
            TPM_ENABLED = if ($null -ne $tpm) { ConvertTo-CSANullableBoolean $tpm.TpmEnabled } else { $null }
            TPM_ACTIVATED = if ($null -ne $tpm) { ConvertTo-CSANullableBoolean $tpm.TpmActivated } else { $null }
        }
        $primaryComplete = @($tpmValues.Values | Where-Object { $null -eq $_ }).Count -eq 0
        $primaryAllFalse = $primaryComplete -and @($tpmValues.Values | Where-Object { $_ -eq $true }).Count -eq 0
        $fallback = $null
        $explicitTpmProvider = $PSBoundParameters.ContainsKey("TpmProvider")
        if (
            (-not $explicitTpmProvider -or $null -ne $TpmFallbackProvider) -and
            (-not $primaryComplete -or $primaryAllFalse)
        ) {
            try {
                $fallback = Get-CSATpmToolState -Provider $TpmFallbackProvider
            } catch {
                if ($null -eq $tpmError) { $tpmError = $_ }
            }
        }
        $provider = "Get-Tpm"
        $confidence = 95
        if ($null -ne $fallback -and (
            -not $primaryComplete -or
            [bool]$fallback.TpmPresent -ne [bool]$tpmValues.TPM_PRESENT -or
            [bool]$fallback.TpmReady -ne [bool]$tpmValues.TPM_READY
        )) {
            $tpmValues.TPM_PRESENT = ConvertTo-CSANullableBoolean $fallback.TpmPresent
            $tpmValues.TPM_READY = ConvertTo-CSANullableBoolean $fallback.TpmReady
            if ($null -ne $fallback.TpmEnabled) {
                $tpmValues.TPM_ENABLED = ConvertTo-CSANullableBoolean $fallback.TpmEnabled
            }
            if ($null -ne $fallback.TpmActivated) {
                $tpmValues.TPM_ACTIVATED = ConvertTo-CSANullableBoolean $fallback.TpmActivated
            }
            $provider = [string]$fallback.Provider
            $confidence = [int]$fallback.Confidence
        }
        $sourcePaths = @{
            TPM_PRESENT = "TpmPresent"
            TPM_READY = "TpmReady"
            TPM_ENABLED = "TpmEnabled"
            TPM_ACTIVATED = "TpmActivated"
        }
        foreach ($id in $tpmValues.Keys) {
            $value = $tpmValues[$id]
            if ($null -ne $value) {
                $settings += New-CSASetting $id "Device Security" $value "RUNTIME_STATE" "SUCCESS" $confidence $provider $sourcePaths[$id]
            } else {
                $status = if ($null -ne $tpmError -and (Resolve-CSAExceptionStatus $tpmError) -eq "ACCESS_DENIED") {
                    "ACCESS_DENIED"
                } else {
                    "PARTIAL"
                }
                $message = if ($null -ne $tpmError) {
                    [string]$tpmError.Exception.Message
                } else {
                    "TPM provider returned an incomplete result."
                }
                $settings += New-CSASetting $id "Device Security" $null "RUNTIME_STATE" $status 0 $provider $sourcePaths[$id] "CSA-TPM-NOT-EVALUATED" $message
            }
        }
        $tpmSpec = $null
        try {
            $tpmWmi = Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
            $tpmSpec = [string]$tpmWmi.SpecVersion
        } catch { $warnings += "TPM specification version was not available." }
        $settings += New-CSASetting "TPM_SPEC_VERSION" "Device Security" $tpmSpec "RUNTIME_STATE" $(if ($null -ne $tpmSpec) { "SUCCESS" } else { "NOT_AVAILABLE" }) $(if ($null -ne $tpmSpec) { 85 } else { 0 }) "Win32_Tpm" "SpecVersion"

        try {
            $deviceGuard = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard -ErrorAction Stop
            $configured = @($deviceGuard.SecurityServicesConfigured)
            $running = @($deviceGuard.SecurityServicesRunning)
            $vbsStatus = switch ([int]$deviceGuard.VirtualizationBasedSecurityStatus) { 2 { "RUNNING" } 1 { "CONFIGURED_NOT_RUNNING" } default { "DISABLED" } }
            $credentialConfigured = $configured -contains 1
            $credentialRunning = $running -contains 1
            $memoryIntegrityConfigured = $configured -contains 2
            $memoryIntegrityRunning = $running -contains 2
            $secureLaunchRunning = $running -contains 3
            $settings += New-CSASetting "VBS_STATUS" "Device Security" $vbsStatus "RUNTIME_STATE" "SUCCESS" 90 "Win32_DeviceGuard" "VirtualizationBasedSecurityStatus"
            $settings += New-CSASetting "VBS_RUNNING" "Device Security" ($vbsStatus -eq "RUNNING") "RUNTIME_STATE" "SUCCESS" 90 "Win32_DeviceGuard" "VirtualizationBasedSecurityStatus" -ConfiguredValue ($vbsStatus -ne "DISABLED")
            $settings += New-CSASetting "CREDENTIAL_GUARD_STATUS" "Device Security" $(if ($credentialRunning) { "RUNNING" } elseif ($credentialConfigured) { "CONFIGURED_NOT_RUNNING" } else { "DISABLED" }) "RUNTIME_STATE" "SUCCESS" 90 "Win32_DeviceGuard" "SecurityServicesRunning/1"
            $settings += New-CSASetting "CREDENTIAL_GUARD_RUNNING" "Device Security" $credentialRunning "RUNTIME_STATE" "SUCCESS" 90 "Win32_DeviceGuard" "SecurityServicesRunning/1" -ConfiguredValue $credentialConfigured
            $settings += New-CSASetting "MEMORY_INTEGRITY_ENABLED" "Device Security" $memoryIntegrityRunning "RUNTIME_STATE" "SUCCESS" 90 "Win32_DeviceGuard" "SecurityServicesRunning/2" -ConfiguredValue $memoryIntegrityConfigured
            $settings += New-CSASetting "SYSTEM_GUARD_SECURE_LAUNCH" "Device Security" $secureLaunchRunning "RUNTIME_STATE" "SUCCESS" 85 "Win32_DeviceGuard" "SecurityServicesRunning/3"
        } catch [System.UnauthorizedAccessException] {
            $errors += New-CSACollectionError "DeviceGuard" "ACCESS_DENIED" "CSA-DEVICE-GUARD-ACCESS-DENIED" $_.Exception.Message
        } catch {
            $errors += New-CSACollectionError "DeviceGuard" "PARTIAL" "CSA-DEVICE-GUARD-NOT-AVAILABLE" $_.Exception.Message
        }
    } catch {
        $errors += New-CSACollectionError "DeviceGuard" "FAILED" "CSA-DEVICE-GUARD-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "DeviceGuard" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt
}

Export-ModuleMember -Function Get-CSADeviceGuardEvidence
