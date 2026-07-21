Import-Module (Join-Path $PSScriptRoot "General.psm1")

function Get-CSABitLockerEvidence {
    param(
        [string]$PrivacyMode = "Standard",
        [scriptblock]$VolumeProvider = $null,
        $BitLockerSupported = $null
    )

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $moduleStatus = ""
    $supported = if ($null -ne $BitLockerSupported) {
        [bool]$BitLockerSupported
    } else {
        [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
    }
    if (-not $supported) {
        $errorItem = New-CSACollectionError "BitLocker" "NOT_SUPPORTED" "CSA-BITLOCKER-NOT-SUPPORTED" "BitLocker cmdlets are unavailable."
        return New-CSAModuleResult -Module "BitLocker" -Errors @($errorItem) -StartedAt $startedAt -Status "NOT_SUPPORTED"
    }

    try {
        $rawVolumes = if ($null -ne $VolumeProvider) { & $VolumeProvider } else { Get-BitLockerVolume -ErrorAction Stop }
        $volumes = @($rawVolumes | Where-Object { $_.VolumeType -eq "OperatingSystem" -or $_.MountPoint })
        foreach ($volume in $volumes) {
            $volumeId = ([string]$volume.MountPoint).TrimEnd(':', '\').ToUpperInvariant()
            if ([string]::IsNullOrWhiteSpace($volumeId)) { $volumeId = "VOLUME" }
            $prefix = "BITLOCKER_$volumeId"
            $protectorTypes = @($volume.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
            $protectionStatus = [string]$volume.ProtectionStatus
            $protectionEnabled = ($protectionStatus -eq "On" -or $protectionStatus -eq "1")
            $metadata = @{ volumeType = [string]$volume.VolumeType; mountPoint = [string]$volume.MountPoint }
            $values = [ordered]@{
                PROTECTION_STATUS = $protectionEnabled
                ENCRYPTION_PERCENTAGE = [int]$volume.EncryptionPercentage
                ENCRYPTION_METHOD = [string]$volume.EncryptionMethod
                LOCK_STATUS = [string]$volume.LockStatus
                AUTO_UNLOCK_ENABLED = [bool]$volume.AutoUnlockEnabled
                TPM_PROTECTOR_PRESENT = (@($protectorTypes | Where-Object { $_ -match "Tpm" }).Count -gt 0)
                PIN_PROTECTOR_PRESENT = (@($protectorTypes | Where-Object { $_ -match "Pin" }).Count -gt 0)
                RECOVERY_PASSWORD_PRESENT = (@($protectorTypes | Where-Object { $_ -eq "RecoveryPassword" }).Count -gt 0)
            }
            foreach ($name in $values.Keys) {
                $settings += New-CSASetting "$prefix`_$name" "Encryption" $values[$name] "RUNTIME_STATE" "SUCCESS" 90 "Get-BitLockerVolume" "$($volume.MountPoint).$name" -Metadata $metadata
            }
            if ([string]$volume.VolumeType -eq "OperatingSystem") {
                $settings += New-CSASetting "BITLOCKER_OS_PROTECTION" "Encryption" $protectionEnabled "RUNTIME_STATE" "SUCCESS" 95 "Get-BitLockerVolume" "$($volume.MountPoint).ProtectionStatus" -Metadata $metadata
            }
        }
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "BitLocker" "ACCESS_DENIED" "CSA-BITLOCKER-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "BitLocker" -Settings $settings -Errors $errors -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "BitLocker" $moduleStatus "CSA-BITLOCKER-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "BitLocker" -Settings $settings -Errors $errors -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSABitLockerEvidence
