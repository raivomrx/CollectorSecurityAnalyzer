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
    $protectionEnabled = if ($Volume.PSObject.Properties.Name -contains "ProtectionEnabled") {
        if ($Volume.ProtectionEnabled -is [bool]) { $Volume.ProtectionEnabled } else { $null }
    } elseif ($protectionStatus -in @("On", "1")) {
        $true
    } elseif ($protectionStatus -in @("Off", "0")) {
        $false
    } else { $null }
    $percentage = if ($null -ne $Volume.EncryptionPercentage) {
        [double]$Volume.EncryptionPercentage
    } else {
        $null
    }
    $encryptionState = if (-not [string]::IsNullOrWhiteSpace([string]$Volume.EncryptionState)) {
        [string]$Volume.EncryptionState
    } elseif ([string]$Volume.VolumeStatus -in @('EncryptionInProgress', 'DecryptionInProgress', 'EncryptionPaused', 'DecryptionPaused')) {
        @{ EncryptionInProgress='ENCRYPTION_IN_PROGRESS'; DecryptionInProgress='DECRYPTION_IN_PROGRESS'; EncryptionPaused='ENCRYPTION_PAUSED'; DecryptionPaused='DECRYPTION_PAUSED' }[[string]$Volume.VolumeStatus]
    } elseif ($percentage -eq 100 -and $protectionEnabled -eq $false) {
        "SUSPENDED"
    } elseif ($percentage -eq 100) {
        "FULLY_ENCRYPTED"
    } elseif ($percentage -eq 0) {
        "FULLY_DECRYPTED"
    } else {
        "UNKNOWN"
    }
    if ($encryptionState -eq 'FULLY_ENCRYPTED' -and $protectionEnabled -eq $false) { $encryptionState = 'SUSPENDED' }
    if ([string]$Volume.LockStatus -eq 'Locked') { $encryptionState = 'LOCKED' }
    $configured = if ($null -ne $Volume.Configured) {
        [bool]$Volume.Configured
    } else {
        $protectionEnabled -or
        ($null -ne $percentage -and $percentage -gt 0) -or
        [string]$Volume.EncryptionMethod -notin @("", "None", "0")
    }
    $collectionStatus = if ($Volume.PSObject.Properties.Name -contains "CollectionStatus") { [string]$Volume.CollectionStatus } else { "SUCCESS" }
    if ($protectionEnabled -eq $true -and $encryptionState -eq 'FULLY_DECRYPTED') {
        $encryptionState = 'SOURCE_CONFLICT'; $protectionEnabled = $null; $collectionStatus = 'PARTIAL'
    }
    if ($null -eq $protectionEnabled -and $collectionStatus -eq "SUCCESS") {
        $collectionStatus = "PARTIAL"
    }
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
        if ($protection.ReturnValue -ne 0 -or $conversion.ReturnValue -ne 0) {
            throw "BitLocker WMI method returned an unsuccessful result."
        }
        $conversionStatus = [int]$conversion.ConversionStatus
        $values += [pscustomobject]@{
            MountPoint = [string]$volume.DriveLetter
            VolumeType = if (
                [string]$volume.DriveLetter -eq [string]$env:SystemDrive
            ) { "OperatingSystem" } else { "FixedData" }
            ProtectionStatus = if ($protection.ProtectionStatus -eq 1) {
                "On"
            } elseif ($protection.ProtectionStatus -eq 0) {
                "Off"
            } else { "Unknown" }
            ProtectionEnabled = if ($protection.ProtectionStatus -eq 1) { $true } elseif ($protection.ProtectionStatus -eq 0) { $false } else { $null }
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
        [int]$ProtectionExitCode = -1,
        [string]$MountPoint = $env:SystemDrive,
        [int]$StatusExitCode = 0
    )

    $text = $Lines -join "`n"
    $percentages = [regex]::Matches($text, '(?im)^\s*[^:\r\n%]+:\s*(\d+(?:[\.,]\d+)?)\s*%\s*$')
    $percentageValue = if ($percentages.Count -eq 1) {
        [double]::Parse($percentages[0].Groups[1].Value.Replace(',', '.'), [Globalization.CultureInfo]::InvariantCulture)
    } else { $null }
    # Parse only bounded status values, never volume labels, protectors or keys.
    # Unsupported locales remain unknown unless the documented numeric protection
    # exit code and percentage independently establish protection.
    $conversion = 'UNKNOWN'; $textProtection = $null; $locale = 'UNRECOGNIZED'
    $lock = 'UNKNOWN'; $method = ''
    $formats = @(
        @{ Locale='en'; Conversion='Conversion Status'; Protection='Protection Status'; Lock='Lock Status'; Method='Encryption Method'; Off='Protection Off'; On='Protection On'; Decrypted='Fully Decrypted'; Encrypted='Fully Encrypted'; Encrypting='Encryption in Progress'; Decrypting='Decryption in Progress' },
        @{ Locale='de'; Conversion='Konvertierungsstatus'; Protection='Schutzstatus'; Lock='Sperrstatus'; Method='Verschlüsselungsmethode'; Off='Schutz deaktiviert'; On='Schutz aktiviert'; Decrypted='Vollständig entschlüsselt'; Encrypted='Vollständig verschlüsselt'; Encrypting='Verschlüsselung wird durchgeführt'; Decrypting='Entschlüsselung wird durchgeführt' },
        @{ Locale='fr'; Conversion='État de la conversion'; Protection='État de la protection'; Lock='État du verrouillage'; Method='Méthode de chiffrement'; Off='Protection désactivée'; On='Protection activée'; Decrypted='Intégralement déchiffré'; Encrypted='Intégralement chiffré'; Encrypting='Chiffrement en cours'; Decrypting='Déchiffrement en cours' }
    )
    foreach ($format in $formats) {
        $match = [regex]::Match($text, '(?im)^\s*' + [regex]::Escape($format.Conversion) + '\s*:\s*([^\r\n]+)\s*$')
        if (-not $match.Success) { continue }
        $locale = $format.Locale
        $rawConversion = $match.Groups[1].Value.Trim()
        foreach ($pair in @(@('Decrypted','FULLY_DECRYPTED'), @('Encrypted','FULLY_ENCRYPTED'), @('Encrypting','ENCRYPTION_IN_PROGRESS'), @('Decrypting','DECRYPTION_IN_PROGRESS'))) {
            if ($rawConversion -eq $format[$pair[0]]) { $conversion = $pair[1] }
        }
        $match = [regex]::Match($text, '(?im)^\s*' + [regex]::Escape($format.Protection) + '\s*:\s*([^\r\n]+)\s*$')
        if ($match.Success) {
            if ($match.Groups[1].Value.Trim() -eq $format.Off) { $textProtection = $false }
            if ($match.Groups[1].Value.Trim() -eq $format.On) { $textProtection = $true }
        }
        $match = [regex]::Match($text, '(?im)^\s*' + [regex]::Escape($format.Method) + '\s*:\s*([\w -]{1,40})\s*$')
        if ($match.Success) { $method = $match.Groups[1].Value.Trim() }
        $match = [regex]::Match($text, '(?im)^\s*' + [regex]::Escape($format.Lock) + '\s*:\s*([\w -]{1,40})\s*$')
        if ($match.Success) { $lock = $match.Groups[1].Value.Trim() }
        break
    }
    $protected = if ($ProtectionExitCode -in @(0,1)) { $ProtectionExitCode -eq 0 } else { $textProtection }
    $rejection = $null
    if ($StatusExitCode -ne 0) { $rejection = 'STATUS_COMMAND_FAILED' }
    elseif ($null -eq $percentageValue -or $percentageValue -lt 0 -or $percentageValue -gt 100) { $rejection = 'PERCENTAGE_UNRECOGNIZED' }
    elseif ($null -ne $textProtection -and $null -ne $protected -and $textProtection -ne $protected) { $rejection = 'PROTECTION_SOURCE_CONFLICT' }
    elseif (($conversion -eq 'FULLY_DECRYPTED' -and ($percentageValue -ne 0 -or $protected -eq $true)) -or ($conversion -eq 'FULLY_ENCRYPTED' -and $percentageValue -ne 100)) { $rejection = 'CONVERSION_SOURCE_CONFLICT' }
    elseif ($null -eq $protected) { $rejection = 'PROTECTION_UNRECOGNIZED' }
    elseif ($protected -eq $false -and $conversion -eq 'UNKNOWN') { $rejection = 'CONVERSION_UNRECOGNIZED' }
    if ($null -ne $rejection) { $protected = $null }
    if ($conversion -eq 'UNKNOWN' -and $protected -eq $true -and $percentageValue -eq 100) { $conversion = 'FULLY_ENCRYPTED' }
    if ($conversion -eq 'FULLY_ENCRYPTED' -and $protected -eq $false) { $conversion = 'SUSPENDED' }
    if ($rejection -like '*SOURCE_CONFLICT') { $conversion = 'SOURCE_CONFLICT' }
    return @([pscustomobject]@{
        MountPoint = [string]$MountPoint
        VolumeType = if ([string]$MountPoint -eq [string]$env:SystemDrive) { "OperatingSystem" } else { "FixedData" }
        ProtectionStatus = if ($protected -eq $true) { "On" } elseif ($protected -eq $false) { "Off" } else { "Unknown" }
        ProtectionEnabled = $protected
        Configured = $protected -or ($null -ne $percentageValue -and $percentageValue -gt 0)
        EncryptionPercentage = $percentageValue
        EncryptionState = $conversion
        EncryptionMethod = $method
        LockStatus = $lock
        AutoUnlockEnabled = $false
        KeyProtector = @()
        CollectionStatus = if ($StatusExitCode -ne 0) { 'FAILED' } elseif ($null -eq $rejection) { "SUCCESS" } else { "PARTIAL" }
        RawEvidence = [ordered]@{ statusExitCode=$StatusExitCode; protectionExitCode = $ProtectionExitCode; percentageParsed = ($percentages.Count -eq 1); percentage=$percentageValue; conversion=$conversion; protection=$textProtection; localeFormat=$locale; parserVersion='5.6'; rejectionReason=$rejection }
    })
}

function Get-CSABitLockerManageBdeVolumes {
    $tool = Join-Path $env:SystemRoot "System32\manage-bde.exe"
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { return @() }
    $output = @(& $tool -status $env:SystemDrive 2>&1)
    $statusExitCode = $LASTEXITCODE
    if ($statusExitCode -ne 0) { return ConvertFrom-CSAManageBdeOutput -Lines $output -StatusExitCode $statusExitCode }
    $null = & $tool -status $env:SystemDrive -protectionaserrorlevel 2>$null
    $protectionExitCode = $LASTEXITCODE
    return ConvertFrom-CSAManageBdeOutput -Lines $output -ProtectionExitCode $protectionExitCode -StatusExitCode $statusExitCode
}

function ConvertFrom-CSAShellBitLockerValue {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()]$RawValue,
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
    $item = if ($mapping.ContainsKey($numeric)) { $mapping[$numeric] } else {
        @{ Protection = $null; Configured = $false; State = "UNKNOWN"; Status = "PARTIAL" }
    }
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
        protectionEnabled = $State.ProtectionEnabled
        encryptionState = [string]$State.EncryptionState
        encryptionPercentage = $State.EncryptionPercentage
        protectionStatus = $State.ProtectionStatus
        lockStatus = $State.LockStatus
        encryptionMethod = $State.EncryptionMethod
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
    $partialStates = @()
    $reliableStates = @()
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
    } else {
        $attempts += New-CSABitLockerAttempt "Get-BitLockerVolume" "NOT_AVAILABLE"
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
                $attempts += New-CSABitLockerAttempt $providerName "NOT_AVAILABLE"
                continue
            }
            $states = @()
            foreach ($volume in $volumes) {
                $state = ConvertTo-CSABitLockerState `
                    -Volume $volume `
                    -Provider $providerName `
                    -Confidence $providerConfidence
                $states += $state
            }
            $systemStates = @($states | Where-Object { $_.VolumeType -eq "OperatingSystem" })
            $authoritative = @($systemStates | Where-Object { $_.CollectionStatus -eq "SUCCESS" -and $_.ProtectionEnabled -is [bool] })
            $attemptStatus = if ($authoritative.Count -gt 0) { "SUCCESS" } elseif (@($systemStates | Where-Object { $_.CollectionStatus -eq 'FAILED' }).Count -gt 0) { 'FAILED' } else { "PARTIAL" }
            $attempts += New-CSABitLockerAttempt $providerName $attemptStatus -States $states -Confidence $providerConfidence
            if ($authoritative.Count -eq 0) {
                $partialStates += @($states | Where-Object { $_.CollectionStatus -ne 'FAILED' })
                continue
            }
            $reliableStates += @($states | Where-Object { $_.CollectionStatus -eq 'SUCCESS' -and $_.ProtectionEnabled -is [bool] })
            $partialStates += @($states | Where-Object { $_.CollectionStatus -eq 'PARTIAL' })
        } catch [System.UnauthorizedAccessException] {
            $attempts += New-CSABitLockerAttempt $providerName "ACCESS_DENIED"
            $errors += New-CSACollectionError `
                "BitLocker" `
                "ACCESS_DENIED" `
                "CSA-BITLOCKER-PROVIDER-ACCESS-DENIED" `
                "$providerName`: access denied"
        } catch {
            $status = Resolve-CSAExceptionStatus $_
            $attempts += New-CSABitLockerAttempt $providerName $status
            $errors += New-CSACollectionError `
                "BitLocker" `
                $status `
                "CSA-BITLOCKER-PROVIDER-FAILED" `
                "$providerName`: provider failed"
        }
    }

    if ($reliableStates.Count -gt 0) {
        foreach ($mount in @($reliableStates | ForEach-Object { $_.MountPoint } | Select-Object -Unique)) {
            $observations = @($reliableStates | Where-Object { $_.MountPoint -eq $mount })
            $selected = $observations[0]
            $conflicting = @($observations | Where-Object { $_.ProtectionEnabled -is [bool] -and ($_.ProtectionEnabled -ne $selected.ProtectionEnabled -or ($_.EncryptionState -ne 'UNKNOWN' -and $selected.EncryptionState -ne 'UNKNOWN' -and $_.EncryptionState -ne $selected.EncryptionState)) })
            # Explicit transitional observations are meaningful even when they
            # cannot establish active protection. Unknown Shell 0 is not.
            $partialConflicts = @($partialStates | Where-Object {
                $_.MountPoint -eq $mount -and
                ($_.EncryptionState -eq 'SOURCE_CONFLICT' -or
                 ($_.EncryptionState -in @('ENCRYPTION_IN_PROGRESS', 'DECRYPTION_IN_PROGRESS', 'ENCRYPTION_PAUSED', 'DECRYPTION_PAUSED', 'SUSPENDED', 'LOCKED') -and
                  $selected.EncryptionState -ne 'UNKNOWN' -and $_.EncryptionState -ne $selected.EncryptionState))
            })
            if ($conflicting.Count -gt 0 -or $partialConflicts.Count -gt 0) {
                $selected.EncryptionState = 'SOURCE_CONFLICT'; $selected.ProtectionEnabled = $null; $selected.CollectionStatus = 'PARTIAL'
                foreach ($attempt in $attempts) { $attempt.conflictReason = 'PROVIDER_STATE_DISAGREEMENT' }
            } else {
                foreach ($attempt in $attempts) { if ($attempt.provider -eq $selected.Provider) { $attempt.selectedAsAuthoritative = $true } }
            }
            $selected.ProviderAttempts = @($attempts)
            Add-CSABitLockerVolumeSettings -State $selected -Settings $settings
        }
        $resultStatus = if (@($settings | Where-Object { $_.collectionStatus -ne 'SUCCESS' }).Count -gt 0) { 'PARTIAL' } else { 'SUCCESS' }
        return New-CSAModuleResult -Module 'BitLocker' -Settings $settings.ToArray() -Errors $errors -StartedAt $startedAt -Status $resultStatus
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
        $attempts += New-CSABitLockerAttempt "DEVICE_ENCRYPTION_POLICY" $(if ($null -eq $configured) { "NOT_AVAILABLE" } else { "PARTIAL" })
    } catch {
        $attempts += New-CSABitLockerAttempt "DEVICE_ENCRYPTION_POLICY" (Resolve-CSAExceptionStatus $_)
        $errors += New-CSACollectionError `
            "BitLocker" `
            (Resolve-CSAExceptionStatus $_) `
            "CSA-BITLOCKER-REGISTRY-FAILED" `
            "Device encryption policy could not be read."
    }
    if ($partialStates.Count -gt 0) {
        # Preserve the best observed transitional/unknown state without turning
        # it into authoritative protection or blocking subsequent providers.
        $partial = @($partialStates | Where-Object { $_.VolumeType -eq "OperatingSystem" } | Select-Object -First 1)
        if ($partial.Count -gt 0) {
            $partial[0].ProviderAttempts = @($attempts)
            Add-CSABitLockerVolumeSettings -State $partial[0] -Settings $settings
            return New-CSAModuleResult -Module "BitLocker" -Settings $settings.ToArray() -Errors $errors -StartedAt $startedAt -Status "PARTIAL"
        }
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
            fallbacksAttempted = @($attempts)
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
    $settings.Add((New-CSASetting "BITLOCKER_OS_PROTECTION" "Encryption" $null "RUNTIME_STATE" $finalStatus 0 "CSA provider chain" "ProviderAttempts" -Metadata @{
        volumeType = "OperatingSystem"; mountPoint = [string]$env:SystemDrive
        protectionEnabled = $null; encryptionState = "UNKNOWN"; fallbacksAttempted = @($attempts)
    }))
    return New-CSAModuleResult `
        -Module "BitLocker" `
        -Settings $settings.ToArray() `
        -Errors $errors `
        -StartedAt $startedAt `
        -Status $finalStatus
}

function New-CSABitLockerAttempt {
    param([string]$Provider, [string]$Status, [object[]]$States = @(), [int]$Confidence = 0, [bool]$Selected = $false)
    $system = @($States | Where-Object { $_.VolumeType -eq "OperatingSystem" } | Select-Object -First 1)
    $raw = if ($system.Count -gt 0) { $system[0].RawEvidence } else { $null }
    [ordered]@{
        provider = $Provider; status = $Status
        executionStatus = if ($Status -in @('SUCCESS', 'PARTIAL')) { 'SUCCESS' } else { $Status }
        rawStateAvailable = ($system.Count -gt 0)
        rawState = if ($null -ne $raw) { $raw } else { $null }
        parsedState = if ($system.Count -gt 0) { $system[0].EncryptionState } else { "UNKNOWN" }
        protectionEnabled = if ($system.Count -gt 0) { $system[0].ProtectionEnabled } else { $null }
        volume = if ($system.Count -gt 0) { $system[0].MountPoint } else { $env:SystemDrive }
        encryptionPercentage = if ($system.Count -gt 0) { $system[0].EncryptionPercentage } else { $null }
        protectionStatus = if ($system.Count -gt 0) { $system[0].ProtectionStatus } else { 'Unknown' }
        lockStatus = if ($system.Count -gt 0) { $system[0].LockStatus } else { 'Unknown' }
        encryptionMethod = if ($system.Count -gt 0) { $system[0].EncryptionMethod } else { '' }
        errorCategory = if ($Status -in @("SUCCESS", "PARTIAL")) { $null } else { $Status }
        confidence = $Confidence; selectedAsAuthoritative = $Selected
    }
}

Export-ModuleMember -Function Get-CSABitLockerEvidence, ConvertFrom-CSAManageBdeOutput, ConvertFrom-CSAShellBitLockerValue
