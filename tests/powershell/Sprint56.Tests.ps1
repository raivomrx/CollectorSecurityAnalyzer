BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../collector/windows/modules/BitLocker.psm1') -Force
}

Describe 'Sprint 5.6 authoritative BitLocker state' {
    It 'uses explicit fully decrypted status after primary access denial even when the second command fails' {
        $denied = { throw [UnauthorizedAccessException]::new('denied') }
        $bde = { ConvertFrom-CSAManageBdeOutput -Lines @('Conversion Status: Fully Decrypted','Percentage Encrypted: 0.0%','Protection Status: Protection Off','Encryption Method: None','Lock Status: Unlocked') -ProtectionExitCode -1 }
        $result = Get-CSABitLockerEvidence -VolumeProvider $denied -WmiProvider $denied -ManageBdeProvider $bde -ShellProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 0 }
        $setting = @($result.Settings | Where-Object settingId -eq BITLOCKER_OS_PROTECTION)[0]
        $setting.effectiveValue | Should -BeFalse
        $setting.collectionStatus | Should -Be SUCCESS
        $setting.metadata.encryptionState | Should -Be FULLY_DECRYPTED
        $setting.metadata.encryptionPercentage | Should -Be 0
        $setting.metadata.provider | Should -Be MANAGE_BDE
        $setting.metadata.fallbacksAttempted.Count | Should -Be 4
        $setting.metadata.rawEvidence.localeFormat | Should -Be en
    }
    It 'parses explicit German status without assuming an English locale' {
        $row = ConvertFrom-CSAManageBdeOutput -Lines @('Konvertierungsstatus: Vollständig entschlüsselt','Verschlüsselt (Prozent): 0,0%','Schutzstatus: Schutz deaktiviert')
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
        $result = Get-CSABitLockerEvidence -VolumeProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 1 } -ShellProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 2 }
        $setting = @($result.Settings | Where-Object settingId -eq BITLOCKER_OS_PROTECTION)[0]
        $setting.metadata.encryptionState | Should -Be SOURCE_CONFLICT
        $setting.collectionStatus | Should -Be PARTIAL
        $null -eq $setting.effectiveValue | Should -BeTrue
        @($setting.metadata.fallbacksAttempted | Where-Object selectedAsAuthoritative).Count | Should -Be 0
    }
    It 'preserves encryption and decryption in progress separately' {
        foreach ($state in @('Encryption','Decryption')) {
            $row = ConvertFrom-CSAManageBdeOutput -Lines @("Conversion Status: $state in Progress",'Percentage Encrypted: 42%','Protection Status: Protection Off') -ProtectionExitCode 1
            $row.EncryptionState | Should -Be ($state.ToUpperInvariant() + '_IN_PROGRESS')
        }
    }
    It 'does not discard a conflicting explicit transitional observation' {
        $result = Get-CSABitLockerEvidence -VolumeProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 2 } -ShellProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 3 }
        $setting = @($result.Settings | Where-Object settingId -eq BITLOCKER_OS_PROTECTION)[0]
        $setting.metadata.encryptionState | Should -Be SOURCE_CONFLICT
        $setting.collectionStatus | Should -Be PARTIAL
        $setting.metadata.fallbacksAttempted[1].executionStatus | Should -Be SUCCESS
        $setting.metadata.fallbacksAttempted[1].status | Should -Be PARTIAL
    }
    It 'retains suspended and locked states' {
        (ConvertFrom-CSAManageBdeOutput -Lines @('Conversion Status: Fully Encrypted','Percentage Encrypted: 100%','Protection Status: Protection Off') -ProtectionExitCode 1).EncryptionState | Should -Be SUSPENDED
        (ConvertFrom-CSAShellBitLockerValue -RawValue 6).EncryptionState | Should -Be LOCKED
    }
}
