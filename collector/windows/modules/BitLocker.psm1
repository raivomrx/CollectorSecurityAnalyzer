Import-Module (Join-Path $PSScriptRoot "General.psm1")

function ConvertTo-CSABitLockerState {
    param(
        [Parameter(Mandatory = $true)]$Volume,
        [Parameter(Mandatory = $true)][string]$Provider,
        [Parameter(Mandatory = $true)][int]$Confidence
    )

    $mountPoint = [string]$Volume.MountPoint
    $volumeType = [string]$Volume.VolumeType
    $protectionStatus = [string]$Volume.ProtectionStatus
    $protectionEnabled = if (
        $Volume.PSObject.Properties.Name -contains "ProtectionEnabled" -and
        $null -eq $Volume.ProtectionEnabled
    ) { $null } else {
        [bool](
            $Volume.ProtectionEnabled -eq $true -or
            $protectionStatus -eq "On" -or
            $protectionStatus -eq "1"
        )
    }
    $percentage = if ($null -ne $Volume.EncryptionPercentage) {
        [int]$Volume.EncryptionPercentage
    } else {
        $null
    }
    $encryptionState = if (-not [string]::IsNullOrWhiteSpace([string]$Volume.EncryptionState)) {
        [string]$Volume.EncryptionState
    } elseif ($percentage -eq 100) {
        "FULLY_ENCRYPTED"
    } elseif ($percentage -eq 0) {
        "FULLY_DECRYPTED"
    } else {
        "UNKNOWN"
    }
    $configured = if ($null -ne $Volume.Configured) {
        [bool]$Volume.Configured
    } else {
        $protectionEnabled -or
        ($null -ne $percentage -and $percentage -gt 0) -or
        [string]$Volume.EncryptionMethod -notin @("", "None", "0")
    }
    $collectionStatus = if ($Volume.PSObject.Properties.Name -contains "CollectionStatus") { [string]$Volume.CollectionStatus } else { "SUCCESS" }
    $rawEvidence = if ($Volume.PSObject.Properties.Name -contains "RawEvidence") { $Volume.RawEvidence } else { $null }
    return [ordered]@{
        MountPoint = $mountPoint
        VolumeType = $volumeType
        ProtectionEnabled = $protectionEnabled
        ProtectionStatus = $protectionStatus
        Configured = [bool]$configured
        EncryptionState = $encryptionState
        EncryptionPercentage = $percentage
        EncryptionMethod = [string]$Volume.EncryptionMethod
        LockStatus = [string]$Volume.LockStatus
        AutoUnlockEnabled = if ($null -ne $Volume.AutoUnlockEnabled) {
            [bool]$Volume.AutoUnlockEnabled
        } else {
            $false
        }
        KeyProtector = @($Volume.KeyProtector)
        Provider = $Provider
        Confidence = $Confidence
        CollectionStatus = $collectionStatus
        RawEvidence = $rawEvidence
        ProviderAttempts = @()
    }
}

function Get-CSABitLockerWmiVolumes {
    $raw = @(
        Get-CimInstance `
            -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" `
            -ClassName Win32_EncryptableVolume `
            -ErrorAction Stop
    )
    $values = @()
    foreach ($volume in $raw) {
        if ([string]::IsNullOrWhiteSpace([string]$volume.DriveLetter)) {
            continue
        }
        $conversion = Invoke-CimMethod `
            -InputObject $volume `
            -MethodName GetConversionStatus `
            -ErrorAction Stop
        $protection = Invoke-CimMethod `
            -InputObject $volume `
            -MethodName GetProtectionStatus `
            -ErrorAction Stop
        $conversionStatus = [int]$conversion.ConversionStatus
        $values += [pscustomobject]@{
            MountPoint = [string]$volume.DriveLetter
            VolumeType = if (
                [string]$volume.DriveLetter -eq [string]$env:SystemDrive
            ) { "OperatingSystem" } else { "FixedData" }
            ProtectionStatus = if ([int]$protection.ProtectionStatus -eq 1) {
                "On"
            } else {
                "Off"
            }
            ProtectionEnabled = [int]$protection.ProtectionStatus -eq 1
            EncryptionPercentage = [int]$conversion.EncryptionPercentage
            EncryptionState = switch ($conversionStatus) {
                0 { "FULLY_DECRYPTED" }
                1 { "FULLY_ENCRYPTED" }
                2 { "ENCRYPTION_IN_PROGRESS" }
                3 { "DECRYPTION_IN_PROGRESS" }
                4 { "ENCRYPTION_PAUSED" }
                5 { "DECRYPTION_PAUSED" }
                default { "UNKNOWN" }
            }
            EncryptionMethod = [string]$conversion.EncryptionMethod
            LockStatus = "UNKNOWN"
            AutoUnlockEnabled = $false
            KeyProtector = @()
        }
    }
    return $values
}

function ConvertFrom-CSAManageBdeOutput {
    param(
        [Parameter(Mandatory = $true)][object[]]$Lines,
        [Parameter(Mandatory = $true)][int]$ProtectionExitCode,
        [string]$MountPoint = $env:SystemDrive
    )

    if ($ProtectionExitCode -notin @(0, 1)) { return @() }
    $text = $Lines -join "`n"
    $percentage = [regex]::Match($text, '(?im)^\s*[^:\r\n%]+:\s*(\d+(?:[\.,]\d+)?)\s*%\s*$')
    $percentageValue = if ($percentage.Success) {
        [int][math]::Round([double]::Parse($percentage.Groups[1].Value.Replace(',', '.'), [Globalization.CultureInfo]::InvariantCulture))
    } else { $null }
    $protected = $ProtectionExitCode -eq 0
    return @([pscustomobject]@{
        MountPoint = [string]$MountPoint
        VolumeType = if ([string]$MountPoint -eq [string]$env:SystemDrive) { "OperatingSystem" } else { "FixedData" }
        ProtectionStatus = if ($protected) { "On" } else { "Off" }
        ProtectionEnabled = $protected
        Configured = $protected -or ($null -ne $percentageValue -and $percentageValue -gt 0)
        EncryptionPercentage = $percentageValue
        EncryptionState = if ($percentageValue -eq 100) { "FULLY_ENCRYPTED" } elseif ($percentageValue -eq 0) { "FULLY_DECRYPTED" } else { "UNKNOWN" }
        EncryptionMethod = ""
        LockStatus = "UNKNOWN"
        AutoUnlockEnabled = $false
        KeyProtector = @()
        CollectionStatus = if ($null -ne $percentageValue) { "SUCCESS" } else { "PARTIAL" }
        RawEvidence = [ordered]@{ protectionExitCode = $ProtectionExitCode; percentageParsed = $percentage.Success }
    })
}

function Get-CSABitLockerManageBdeVolumes {
    $tool = Join-Path $env:SystemRoot "System32\manage-bde.exe"
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { return @() }
    $output = @(& $tool -status $env:SystemDrive 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join "`n")
    }
    $null = & $tool -status $env:SystemDrive -protectionaserrorlevel 2>$null
    $protectionExitCode = $LASTEXITCODE
    return ConvertFrom-CSAManageBdeOutput -Lines $output -ProtectionExitCode $protectionExitCode
}

function ConvertFrom-CSAShellBitLockerValue {
    param(
        [Parameter(Mandatory = $true)]$RawValue,
        [string]$MountPoint = $env:SystemDrive,
        [string]$VolumeType = "OperatingSystem"
    )

    $numeric = 0
    if (-not [int]::TryParse(([string]$RawValue).Trim(), [ref]$numeric)) { return $null }
    # Values are the Windows Property System enum from propsys.dll. States
    # that do not prove active protection remain PARTIAL rather than PASS/FAIL.
    $mapping = @{
        1 = @{ Protection = $true; Configured = $true; State = "FULLY_ENCRYPTED"; Status = "SUCCESS" }
        2 = @{ Protection = $false; Configured = $false; State = "FULLY_DECRYPTED"; Status = "SUCCESS" }
        3 = @{ Protection = $false; Configured = $true; State = "ENCRYPTION_IN_PROGRESS"; Status = "PARTIAL" }
        4 = @{ Protection = $false; Configured = $true; State = "DECRYPTION_IN_PROGRESS"; Status = "PARTIAL" }
        5 = @{ Protection = $false; Configured = $true; State = "SUSPENDED"; Status = "SUCCESS" }
        6 = @{ Protection = $null; Configured = $true; State = "LOCKED"; Status = "PARTIAL" }
        7 = @{ Protection = $false; Configured = $false; State = "OFF_NO_TURN_ON"; Status = "SUCCESS" }
        8 = @{ Protection = $null; Configured = $true; State = "PRE_PROVISIONED"; Status = "PARTIAL" }
    }
    if (-not $mapping.ContainsKey($numeric)) { return $null }
    $item = $mapping[$numeric]
    return [pscustomobject]@{
        MountPoint = $MountPoint
        VolumeType = $VolumeType
        ProtectionStatus = if ($item.Protection -eq $true) { "On" } elseif ($item.Protection -eq $false) { "Off" } else { "Unknown" }
        ProtectionEnabled = $item.Protection
        Configured = [bool]$item.Configured
        EncryptionPercentage = if ($numeric -in @(1, 5, 6, 8)) { 100 } elseif ($numeric -in @(2, 7)) { 0 } else { $null }
        EncryptionState = [string]$item.State
        EncryptionMethod = ""
        LockStatus = if ($numeric -eq 6) { "LOCKED" } else { "UNKNOWN" }
        AutoUnlockEnabled = $false
        KeyProtector = @()
        CollectionStatus = [string]$item.Status
        RawEvidence = [ordered]@{ property = "System.Volume.BitLockerProtection"; value = $numeric }
    }
}

function Get-CSABitLockerShellVolumes {
    $shell = New-Object -ComObject Shell.Application
    $values = @()
    $fixedDrives = @(
        [System.IO.DriveInfo]::GetDrives() |
            Where-Object {
                $_.DriveType -eq [System.IO.DriveType]::Fixed -and
                $_.IsReady
            }
    )
    foreach ($drive in $fixedDrives) {
        $mount = ([string]$drive.Name).TrimEnd('\')
        $folder = $shell.NameSpace($mount)
        if ($null -eq $folder -or $null -eq $folder.Self) { continue }
        $raw = $folder.Self.ExtendedProperty("System.Volume.BitLockerProtection")
        $mapped = ConvertFrom-CSAShellBitLockerValue -RawValue $raw -MountPoint $mount -VolumeType $(if ($mount -eq $env:SystemDrive) { "OperatingSystem" } else { "FixedData" })
        if ($null -ne $mapped) { $values += $mapped }
    }
    return $values
}

function Get-CSABitLockerRegistryIndicator {
    $value = Get-CSARegistryValue `
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker" `
        "RequireDeviceEncryption" `
        $null
    if ($null -eq $value) { return $null }
    return [bool]([int]$value -eq 1)
}

function Add-CSABitLockerVolumeSettings {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Settings
    )

    $volumeId = ([string]$State.MountPoint).TrimEnd(':', '\').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($volumeId)) { $volumeId = "VOLUME" }
    $prefix = "BITLOCKER_$volumeId"
    $protectorTypes = @(
        $State.KeyProtector |
            ForEach-Object { [string]$_.KeyProtectorType }
    )
    $metadata = @{
        volumeType = [string]$State.VolumeType
        mountPoint = [string]$State.MountPoint
        provider = [string]$State.Provider
        collectionStatus = [string]$State.CollectionStatus
        confidence = [int]$State.Confidence
        configured = [bool]$State.Configured
        protectionEnabled = [bool]$State.ProtectionEnabled
        encryptionState = [string]$State.EncryptionState
        encryptionPercentage = $State.EncryptionPercentage
        rawEvidence = $State.RawEvidence
        fallbacksAttempted = @($State.ProviderAttempts)
    }
    $values = [ordered]@{
        PROTECTION_STATUS = $State.ProtectionEnabled
        ENCRYPTION_PERCENTAGE = $State.EncryptionPercentage
        ENCRYPTION_METHOD = [string]$State.EncryptionMethod
        LOCK_STATUS = [string]$State.LockStatus
        AUTO_UNLOCK_ENABLED = [bool]$State.AutoUnlockEnabled
        TPM_PROTECTOR_PRESENT = (
            @($protectorTypes | Where-Object { $_ -match "Tpm" }).Count -gt 0
        )
        PIN_PROTECTOR_PRESENT = (
            @($protectorTypes | Where-Object { $_ -match "Pin" }).Count -gt 0
        )
        RECOVERY_PASSWORD_PRESENT = (
            @($protectorTypes | Where-Object { $_ -eq "RecoveryPassword" }).Count -gt 0
        )
    }
    foreach ($name in $values.Keys) {
        $Settings.Add(
            (New-CSASetting "$prefix`_$name" "Encryption" $values[$name] "RUNTIME_STATE" ([string]$State.CollectionStatus) ([int]$State.Confidence) ([string]$State.Provider) "$($State.MountPoint).$name" -Metadata $metadata)
        )
    }
    if ([string]$State.VolumeType -eq "OperatingSystem") {
        $Settings.Add(
            (New-CSASetting "BITLOCKER_OS_PROTECTION" "Encryption" $State.ProtectionEnabled "RUNTIME_STATE" ([string]$State.CollectionStatus) ([int]$State.Confidence) ([string]$State.Provider) "$($State.MountPoint).ProtectionStatus" -ConfiguredValue ([bool]$State.Configured) -Metadata $metadata)
        )
    }
}

function Get-CSABitLockerEvidence {
    param(
        [string]$PrivacyMode = "Standard",
        [scriptblock]$VolumeProvider = $null,
        $BitLockerSupported = $null,
        [scriptblock]$WmiProvider = $null,
        [scriptblock]$ManageBdeProvider = $null,
        [scriptblock]$ShellProvider = $null,
        [scriptblock]$RegistryProvider = $null
    )

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = New-Object System.Collections.Generic.List[object]
    $errors = @()
    $providers = @()
    $attempts = @()
    $explicitPrimary = $PSBoundParameters.ContainsKey("VolumeProvider")
    $explicitSupport = $PSBoundParameters.ContainsKey("BitLockerSupported")
    $supported = if ($null -ne $BitLockerSupported) {
        [bool]$BitLockerSupported
    } else {
        [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
    }
    if ($supported -or $null -ne $VolumeProvider) {
        $providers += [ordered]@{
            Name = "Get-BitLockerVolume"
            Confidence = 95
            Invoke = if ($null -ne $VolumeProvider) {
                $VolumeProvider
            } else {
                { Get-BitLockerVolume -ErrorAction Stop }
            }
        }
    }
    if (
        (-not $explicitPrimary -and -not ($explicitSupport -and -not $supported)) -or
        $null -ne $WmiProvider
    ) {
        $providers += [ordered]@{
            Name = "WIN32_ENCRYPTABLE_VOLUME"
            Confidence = 90
            Invoke = if ($null -ne $WmiProvider) {
                $WmiProvider
            } else {
                { Get-CSABitLockerWmiVolumes }
            }
        }
    }
    if (
        (-not $explicitPrimary -and -not ($explicitSupport -and -not $supported)) -or
        $null -ne $ManageBdeProvider
    ) {
        $providers += [ordered]@{
            Name = "MANAGE_BDE"
            Confidence = 85
            Invoke = if ($null -ne $ManageBdeProvider) {
                $ManageBdeProvider
            } else {
                { Get-CSABitLockerManageBdeVolumes }
            }
        }
    }
    if (
        (-not $explicitPrimary -and -not ($explicitSupport -and -not $supported)) -or
        $null -ne $ShellProvider
    ) {
        $providers += [ordered]@{
            Name = "SHELL_VOLUME_BITLOCKER_PROPERTY"
            Confidence = 75
            Invoke = if ($null -ne $ShellProvider) { $ShellProvider } else { { Get-CSABitLockerShellVolumes } }
        }
    }

    foreach ($provider in $providers) {
        try {
            $providerName = [string]$provider["Name"]
            $providerConfidence = [int]$provider["Confidence"]
            $providerInvocation = [scriptblock]$provider["Invoke"]
            $rawVolumes = @(& $providerInvocation)
            $volumes = @(
                $rawVolumes |
                    Where-Object {
                        $_.VolumeType -eq "OperatingSystem" -or $_.MountPoint
                    }
            )
            if ($volumes.Count -eq 0) {
                $attempts += [ordered]@{ provider = $providerName; status = "NOT_AVAILABLE" }
                continue
            }
            $attempts += [ordered]@{ provider = $providerName; status = "SUCCESS" }
            foreach ($volume in $volumes) {
                $state = ConvertTo-CSABitLockerState `
                    -Volume $volume `
                    -Provider $providerName `
                    -Confidence $providerConfidence
                $state.ProviderAttempts = @($attempts)
                Add-CSABitLockerVolumeSettings -State $state -Settings $settings
            }
            $resultStatus = if (@($settings | Where-Object { $_.collectionStatus -eq "PARTIAL" }).Count -gt 0) { "PARTIAL" } else { "SUCCESS" }
            return New-CSAModuleResult `
                -Module "BitLocker" `
                -Settings $settings.ToArray() `
                -Errors $errors `
                -StartedAt $startedAt `
                -Status $resultStatus
        } catch [System.UnauthorizedAccessException] {
            $attempts += [ordered]@{ provider = $providerName; status = "ACCESS_DENIED" }
            $errors += New-CSACollectionError `
                "BitLocker" `
                "ACCESS_DENIED" `
                "CSA-BITLOCKER-PROVIDER-ACCESS-DENIED" `
                "$providerName`: $($_.Exception.Message)"
        } catch {
            $status = Resolve-CSAExceptionStatus $_
            $attempts += [ordered]@{ provider = $providerName; status = $status }
            $errors += New-CSACollectionError `
                "BitLocker" `
                $status `
                "CSA-BITLOCKER-PROVIDER-FAILED" `
                "$providerName`: $($_.Exception.Message)"
        }
    }

    $configured = $null
    try {
        $configured = if ($null -ne $RegistryProvider) {
            & $RegistryProvider
        } elseif (-not $explicitPrimary) {
            Get-CSABitLockerRegistryIndicator
        } else {
            $null
        }
    } catch {
        $errors += New-CSACollectionError `
            "BitLocker" `
            (Resolve-CSAExceptionStatus $_) `
            "CSA-BITLOCKER-REGISTRY-FAILED" `
            $_.Exception.Message
    }
    if ($null -ne $configured) {
        $metadata = @{
            volumeType = "OperatingSystem"
            mountPoint = [string]$env:SystemDrive
            provider = "DEVICE_ENCRYPTION_POLICY"
            collectionStatus = "PARTIAL"
            confidence = 60
            configured = [bool]$configured
            protectionEnabled = $null
            encryptionState = "UNKNOWN"
            encryptionPercentage = $null
        }
        $settings.Add(
            (New-CSASetting "BITLOCKER_OS_PROTECTION" "Encryption" $null "REGISTRY" "PARTIAL" 60 "DEVICE_ENCRYPTION_POLICY" "BitLocker.RequireDeviceEncryption" -ConfiguredValue ([bool]$configured) -Metadata $metadata)
        )
        return New-CSAModuleResult `
            -Module "BitLocker" `
            -Settings $settings.ToArray() `
            -Errors $errors `
            -StartedAt $startedAt `
            -Status "PARTIAL"
    }

    $finalStatus = if (@($errors | Where-Object { $_.status -eq "ACCESS_DENIED" }).Count -gt 0) {
        "ACCESS_DENIED"
    } elseif (-not $supported -and $providers.Count -eq 0) {
        "NOT_SUPPORTED"
    } else {
        "NOT_AVAILABLE"
    }
    if ($errors.Count -eq 0) {
        $errors += New-CSACollectionError `
            "BitLocker" `
            $finalStatus `
            "CSA-BITLOCKER-NOT-EVALUATED" `
            "No provider returned reliable BitLocker protection evidence."
    }
    return New-CSAModuleResult `
        -Module "BitLocker" `
        -Settings $settings.ToArray() `
        -Errors $errors `
        -StartedAt $startedAt `
        -Status $finalStatus
}

Export-ModuleMember -Function Get-CSABitLockerEvidence, ConvertFrom-CSAManageBdeOutput, ConvertFrom-CSAShellBitLockerValue
