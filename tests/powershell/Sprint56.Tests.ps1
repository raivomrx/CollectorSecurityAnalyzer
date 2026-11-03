BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../collector/windows/modules/BitLocker.psm1') -Force
}

Describe 'Sprint 5.6 authoritative BitLocker state' {
    It 'uses structured conversion after primary access denial' {
        $denied = { throw [UnauthorizedAccessException]::new('denied') }
        $wmi = { [pscustomobject]@{ MountPoint=$env:SystemDrive; VolumeType='OperatingSystem'; EncryptionState='FULLY_DECRYPTED'; ProtectionStatus='Off'; EncryptionPercentage=0 } }
        $result = Get-CSABitLockerEvidence -VolumeProvider $denied -WmiProvider $wmi -ShellProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 0 }
        $setting = $result.Settings | Where-Object settingId -eq BITLOCKER_OS_PROTECTION
        $setting.effectiveValue | Should -BeFalse
        $setting.metadata.authority | Should -Be AUTHORITATIVE
        $setting.metadata.encryptionState | Should -Be FULLY_DECRYPTED
        $setting.metadata.encryptionPercentage | Should -Be 0
        $setting.metadata.fallbacksAttempted[0].status | Should -Be ACCESS_DENIED
    }
    It 'parses explicit German status without assuming an English locale' {
        # Construct Unicode independently of this script's file encoding so a
        # mojibake parser and mojibake fixture cannot accidentally agree.
        $conversion = 'Konvertierungsstatus: Vollst' + [char]0x00e4 + 'ndig entschl' + [char]0x00fc + 'sselt'
        $percentage = 'Verschl' + [char]0x00fc + 'sselt (Prozent): 0,0%'
        $row = ConvertFrom-CSAManageBdeOutput -Lines @($conversion,$percentage,'Schutzstatus: Schutz deaktiviert')
        $row.EncryptionState | Should -Be FULLY_DECRYPTED
        $row.ProtectionEnabled | Should -BeFalse
        $row.CollectionStatus | Should -Be SUCCESS
        $row.RawEvidence.localeFormat | Should -Be de
    }
    It 'does not infer disabled from zero percent without explicit conversion' {
        $row = ConvertFrom-CSAManageBdeOutput -Lines @('Percentage Encrypted: 0%') -ProtectionExitCode 1
        $row.CollectionStatus | Should -Be PARTIAL
        $null -eq $row.ProtectionEnabled | Should -BeTrue
    }
    It 'rejects failed execution and contradictory protection indicators' {
        $lines = @('Conversion Status: Fully Decrypted','Percentage Encrypted: 0%','Protection Status: Protection Off')
        $failed = ConvertFrom-CSAManageBdeOutput -Lines $lines -StatusExitCode 5 -ProtectionExitCode 1
        $failed.CollectionStatus | Should -Be FAILED
        $null -eq $failed.ProtectionEnabled | Should -BeTrue
        $conflict = ConvertFrom-CSAManageBdeOutput -Lines $lines -ProtectionExitCode 0
        $conflict.EncryptionState | Should -Be SOURCE_CONFLICT
        $null -eq $conflict.ProtectionEnabled | Should -BeTrue
    }
    It 'continues after success and exposes disagreement between reliable providers' {
        $result = Get-CSABitLockerEvidence -VolumeProvider { [pscustomobject]@{ MountPoint=$env:SystemDrive; VolumeType='OperatingSystem'; VolumeStatus='FullyEncrypted'; ProtectionStatus='On'; EncryptionPercentage=100 } } -WmiProvider { [pscustomobject]@{ MountPoint=$env:SystemDrive; VolumeType='OperatingSystem'; EncryptionState='FULLY_DECRYPTED'; ProtectionStatus='Off'; EncryptionPercentage=0 } }
        $setting = @($result.Settings | Where-Object settingId -eq BITLOCKER_OS_PROTECTION)[0]
        $setting.metadata.encryptionState | Should -Be SOURCE_CONFLICT
        $setting.collectionStatus | Should -Be PARTIAL
        $null -eq $setting.effectiveValue | Should -BeTrue
        @($setting.metadata.fallbacksAttempted | Where-Object selectedAsAuthoritative).Count | Should -Be 0
    }
    It 'exposes conflicting structured conversion states with unknown protection' {
        $result = Get-CSABitLockerEvidence -VolumeProvider {
            [pscustomobject]@{ MountPoint=$env:SystemDrive; VolumeType='OperatingSystem'; VolumeStatus='EncryptionSuspended'; ProtectionStatus='Unknown'; EncryptionPercentage=42 }
        } -WmiProvider {
            [pscustomobject]@{ MountPoint=$env:SystemDrive; VolumeType='OperatingSystem'; EncryptionState='DECRYPTION_IN_PROGRESS'; ProtectionStatus='Unknown'; EncryptionPercentage=42 }
        }
        $setting = $result.Settings | Where-Object settingId -eq BITLOCKER_OS_PROTECTION
        $setting.metadata.encryptionState | Should -Be SOURCE_CONFLICT
        $setting.metadata.encryptionPercentage | Should -BeNullOrEmpty
        $setting.effectiveValue | Should -BeNullOrEmpty
    }
    It 'preserves encryption and decryption in progress separately' {
        foreach ($state in @('Encryption','Decryption')) {
            $row = ConvertFrom-CSAManageBdeOutput -Lines @("Conversion Status: $state in Progress",'Percentage Encrypted: 42%','Protection Status: Protection Off') -ProtectionExitCode 1
            $row.EncryptionState | Should -Be ($state.ToUpperInvariant() + '_IN_PROGRESS')
        }
    }
    It 'keeps native progress and pause states even at a rounded 100 percent' {
        foreach ($case in @(
            @{Native='EncryptionInProgress'; Expected='ENCRYPTION_IN_PROGRESS'},
            @{Native='DecryptionInProgress'; Expected='DECRYPTION_IN_PROGRESS'},
            @{Native='EncryptionSuspended'; Expected='ENCRYPTION_PAUSED'},
            @{Native='DecryptionSuspended'; Expected='DECRYPTION_PAUSED'},
            @{Native='WipeInProgress'; Expected='WIPE_IN_PROGRESS_OR_PAUSED'},
            @{Native='Unexpected'; Expected='UNKNOWN'}
        )) {
            $result = Get-CSABitLockerEvidence -VolumeProvider {
                [pscustomobject]@{ MountPoint=$env:SystemDrive; VolumeType='OperatingSystem'; VolumeStatus=$case.Native; ProtectionStatus='On'; EncryptionPercentage=100 }
            }
            ($result.Settings | Where-Object settingId -eq BITLOCKER_OS_PROTECTION).metadata.encryptionState | Should -Be $case.Expected
        }
    }
    It 'rejects a provider OS volume on a different mount point' {
        $other = if ($env:SystemDrive -eq 'Z:') { 'Y:' } else { 'Z:' }
        $result = Get-CSABitLockerEvidence -VolumeProvider {
            [pscustomobject]@{ MountPoint=$other; VolumeType='OperatingSystem'; VolumeStatus='FullyEncrypted'; ProtectionStatus='On'; EncryptionPercentage=100 }
        }
        $result.Settings[0].effectiveValue | Should -BeNullOrEmpty
    }
}
