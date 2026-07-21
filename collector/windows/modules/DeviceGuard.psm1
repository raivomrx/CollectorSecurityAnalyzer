Import-Module (Join-Path $PSScriptRoot "General.psm1") -Force

function Get-CSADeviceGuardEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $warnings = @()

    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            try {
                $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
                $settings += New-CSASetting "SECURE_BOOT_ENABLED" "Device Security" $secureBoot "RUNTIME_STATE" "SUCCESS" 95 "Confirm-SecureBootUEFI" "SecureBoot"
            } catch [System.PlatformNotSupportedException] {
                $settings += New-CSASetting "SECURE_BOOT_ENABLED" "Device Security" $null "RUNTIME_STATE" "NOT_SUPPORTED" 0 "Confirm-SecureBootUEFI" "SecureBoot" "CSA-SECURE-BOOT-NOT-SUPPORTED" $_.Exception.Message
            } catch [System.UnauthorizedAccessException] {
                $settings += New-CSASetting "SECURE_BOOT_ENABLED" "Device Security" $null "RUNTIME_STATE" "ACCESS_DENIED" 0 "Confirm-SecureBootUEFI" "SecureBoot" "CSA-SECURE-BOOT-ACCESS-DENIED" $_.Exception.Message
            }
        } else {
            $settings += New-CSASetting "SECURE_BOOT_ENABLED" "Device Security" $null "RUNTIME_STATE" "NOT_SUPPORTED" 0 "Confirm-SecureBootUEFI" "SecureBoot" "CSA-SECURE-BOOT-NOT-SUPPORTED" "Secure Boot cmdlet is unavailable."
        }

        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
            try {
                $tpm = Get-Tpm -ErrorAction Stop
                $settings += New-CSASetting "TPM_PRESENT" "Device Security" ([bool]$tpm.TpmPresent) "RUNTIME_STATE" "SUCCESS" 95 "Get-Tpm" "TpmPresent"
                $settings += New-CSASetting "TPM_READY" "Device Security" ([bool]$tpm.TpmReady) "RUNTIME_STATE" "SUCCESS" 95 "Get-Tpm" "TpmReady"
                $settings += New-CSASetting "TPM_ENABLED" "Device Security" ([bool]$tpm.TpmEnabled) "RUNTIME_STATE" "SUCCESS" 95 "Get-Tpm" "TpmEnabled"
                $settings += New-CSASetting "TPM_ACTIVATED" "Device Security" ([bool]$tpm.TpmActivated) "RUNTIME_STATE" "SUCCESS" 95 "Get-Tpm" "TpmActivated"
            } catch [System.UnauthorizedAccessException] {
                foreach ($id in @("TPM_PRESENT", "TPM_READY", "TPM_ENABLED", "TPM_ACTIVATED")) {
                    $settings += New-CSASetting $id "Device Security" $null "RUNTIME_STATE" "ACCESS_DENIED" 0 "Get-Tpm" $id "CSA-TPM-ACCESS-DENIED" $_.Exception.Message
                }
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
    New-CSAModuleResult -Module "DeviceGuard" -Settings $settings -Errors $errors -Warnings $warnings -ExpectedEvidenceCount 11 -StartedAt $startedAt
}

Export-ModuleMember -Function Get-CSADeviceGuardEvidence
