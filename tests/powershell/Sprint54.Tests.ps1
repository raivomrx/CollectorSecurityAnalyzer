BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '..\..\collector\windows\modules'
    Import-Module (Join-Path $moduleRoot 'BitLocker.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'Accounts.psm1') -Force
    Import-Module (Join-Path $moduleRoot 'Protocols.psm1') -Force
}

Describe 'Sprint 5.4 BitLocker provider truth' {
    It 'records Shell values without inferring conversion or percentage' {
        $indications=@('OFF','ON','OFF','TRANSITIONING','TRANSITIONING','SUSPENDED','LOCKED')
        foreach ($raw in @(0,1,2,3,4,5,6,7,8,$null,99,'0',[long]0,'')) {
            $row = ConvertFrom-CSAShellBitLockerValue -RawValue $raw
            $isInt = $raw -is [int]
            $row.RawEvidence.value | Should -Be $(if ($isInt) { $raw } else { $null })
            $row.RawEvidence.shellReadStatus | Should -Be $(if ($isInt) { 'SUCCESS' } else { 'UNAVAILABLE' })
            $expected = if ($isInt -and $raw -lt $indications.Count) { $indications[$raw] } else { 'UNKNOWN' }
            $row.RawEvidence.shellProtectionIndication | Should -Be $expected
            if ($isInt -and $raw -eq 0) { $row.RawEvidence.shellInterpretationMethod | Should -Be 'FIELD_HEURISTIC' }
            $row.EncryptionState | Should -Be UNKNOWN
            $row.EncryptionPercentage | Should -BeNullOrEmpty
            $row.EncryptionMethod | Should -BeNullOrEmpty
            $row.ProtectionEnabled | Should -BeNullOrEmpty
        }
        (ConvertFrom-CSAShellBitLockerValue -RawValue $null -ReadError).RawEvidence.shellReadStatus | Should -Be 'ERROR'
    }
    It 'retains the full failed chain and unknown OS state' {
        $denied = { throw [UnauthorizedAccessException]::new('denied') }
        $result = Get-CSABitLockerEvidence -VolumeProvider $denied -WmiProvider $denied -ManageBdeProvider { throw 'unavailable' } -ShellProvider { ConvertFrom-CSAShellBitLockerValue -RawValue $null } -RegistryProvider { $null }
        $os = @($result.Settings | Where-Object settingId -eq 'BITLOCKER_OS_PROTECTION')[0]
        $os.effectiveValue | Should -BeNullOrEmpty
        $os.metadata.fallbacksAttempted.Count | Should -Be 5
        $os.metadata.fallbacksAttempted[3].status | Should -Be 'UNAVAILABLE'
        @($os.metadata.fallbacksAttempted | Where-Object selectedAsAuthoritative).Count | Should -Be 0
    }
    It 'uses Shell after earlier access denial and retains the protection indication' {
        $denied = { throw [UnauthorizedAccessException]::new('denied') }
        $result = Get-CSABitLockerEvidence -VolumeProvider $denied -WmiProvider $denied -ManageBdeProvider { @() } -ShellProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 2 }
        $os = @($result.Settings | Where-Object settingId -eq 'BITLOCKER_OS_PROTECTION')[0]
        $os.effectiveValue | Should -BeNullOrEmpty
        $attempts = @($os.metadata.fallbacksAttempted)
        $attempts.Count | Should -Be 5
        $attempts[3].rawState.value | Should -Be 2
        $attempts[3].selectedAsAuthoritative | Should -BeFalse
        $attempts[0].errorCategory | Should -Be 'ACCESS_DENIED'
    }
    It 'continues after an unknown Shell-equivalent primary state' {
        $result = Get-CSABitLockerEvidence -VolumeProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 99 } -ShellProvider { ConvertFrom-CSAShellBitLockerValue -RawValue 1 }
        $os = @($result.Settings | Where-Object settingId -eq 'BITLOCKER_OS_PROTECTION')[0]
        $os.effectiveValue | Should -BeNullOrEmpty
        $os.metadata.fallbacksAttempted[0].status | Should -Be 'PARTIAL'
    }
    It 'preserves a Shell exception as an auditable error' {
        $result = Get-CSABitLockerEvidence -VolumeProvider { @() } -ShellProvider { throw 'COM failure' } -RegistryProvider { $null }
        $os = @($result.Settings | Where-Object settingId -eq 'BITLOCKER_OS_PROTECTION')[0]
        $os.metadata.fallbacksAttempted[1].status | Should -Be 'FAILED'
        $os.effectiveValue | Should -BeNullOrEmpty
    }
}

Describe 'Sprint 5.4 structured password policy' {
    It 'converts API numeric values independently of UI language' {
        $provider = { param($level)
            if ($level -eq 0) { [pscustomobject]@{ MinimumLength=14; MaximumAge=7776000; MinimumAge=86400; HistoryLength=24 } }
            else { [pscustomobject]@{ LockoutThreshold=5; LockoutDuration=1800; ObservationWindow=1200 } }
        }
        $result = Get-CSAPasswordPolicyEvidence -Provider $provider
        $byId = @{}
        foreach ($setting in $result.Settings) { $byId[$setting.settingId] = $setting }
        $byId.PASSWORD_POLICY_MIN_LENGTH.effectiveValue | Should -Be 14
        $byId.PASSWORD_POLICY_MAXIMUM_AGE_DAYS.effectiveValue | Should -Be 90
        $byId.PASSWORD_POLICY_MINIMUM_AGE_DAYS.effectiveValue | Should -Be 1
        $byId.PASSWORD_POLICY_HISTORY.effectiveValue | Should -Be 24
        $byId.ACCOUNT_LOCKOUT_THRESHOLD.effectiveValue | Should -Be 5
        $byId.ACCOUNT_LOCKOUT_DURATION_MINUTES.effectiveValue | Should -Be 30
        $byId.ACCOUNT_LOCKOUT_OBSERVATION_WINDOW_MINUTES.effectiveValue | Should -Be 20
        @($result.Settings | Where-Object provider -ne 'NetUserModalsGet').Count | Should -Be 0
    }
    It 'keeps an unavailable lockout API independent of password length' {
        $result = Get-CSAPasswordPolicyEvidence -Provider { param($level)
            if ($level -eq 3) { throw [UnauthorizedAccessException]::new('denied') }
            [pscustomobject]@{ MinimumLength=12; MaximumAge=[uint32]::MaxValue; MinimumAge=0; HistoryLength=10 }
        }
        @($result.Settings | Where-Object settingId -eq 'PASSWORD_POLICY_MIN_LENGTH')[0].collectionStatus | Should -Be 'SUCCESS'
        @($result.Settings | Where-Object settingId -eq 'ACCOUNT_LOCKOUT_THRESHOLD')[0].collectionStatus | Should -Be 'ACCESS_DENIED'
        @($result.Settings | Where-Object settingId -eq 'PASSWORD_POLICY_MAXIMUM_AGE_DAYS')[0].metadata.timeForever | Should -BeTrue
    }
    It 'falls back to explicit unavailable evidence rather than localized text guesses' {
        $result = Get-CSAPasswordPolicyEvidence -Provider { throw 'API unavailable' }
        $result.Settings.Count | Should -Be 8
        @($result.Settings | Where-Object collectionStatus -eq 'SUCCESS').Count | Should -Be 0
        @($result.Settings | Where-Object { $null -ne $_.effectiveValue }).Count | Should -Be 0
    }
}

Describe 'Sprint 5.4 protocol provider isolation' {
    BeforeEach {
        Mock Get-SmbServerConfiguration { throw [UnauthorizedAccessException]::new('denied') } -ModuleName Protocols
        Mock Get-SmbClientConfiguration { [pscustomobject]@{ RequireSecuritySignature=$true; EnableInsecureGuestLogons=$false } } -ModuleName Protocols
        Mock Get-WindowsOptionalFeature { throw [UnauthorizedAccessException]::new('denied') } -ModuleName Protocols
        Mock Get-CSAProtocolRegistryValue { param($Path,$Name,$Default) @{Value=$Default;Source='DEFAULT'} } -ModuleName Protocols
        Mock Get-CimInstance { [pscustomobject]@{ InterfaceIndex=1; TcpipNetbiosOptions=0 } } -ModuleName Protocols
    }
    It 'collects LLMNR NTLM WPAD and adapters after SMB server denial' {
        $result = Get-CSAProtocolsEvidence
        $result.Status | Should -Be 'PARTIAL'
        foreach ($id in @('LLMNR_ENABLED','NTLM_RESTRICTION_LEVEL','WPAD_RELEVANT_STATE')) {
            @($result.Settings | Where-Object settingId -eq $id)[0].collectionStatus | Should -Be 'SUCCESS'
        }
        @($result.Settings | Where-Object settingId -eq 'SMB_SERVER_SIGNING_REQUIRED')[0].collectionStatus | Should -Be 'ACCESS_DENIED'
        $signing = @($result.Settings | Where-Object settingId -eq 'SMB_SIGNING_REQUIRED')[0]
        $null -eq $signing.effectiveValue | Should -BeTrue
        $signing.collectionStatus | Should -Be 'PARTIAL'
    }
    It 'continues when SMB client is also unavailable' {
        Mock Get-SmbClientConfiguration { throw [System.Management.Automation.CommandNotFoundException]::new('missing') } -ModuleName Protocols
        $result = Get-CSAProtocolsEvidence
        $result.Status | Should -Be 'PARTIAL'
        @($result.Settings | Where-Object settingId -eq 'LLMNR_ENABLED')[0].effectiveValue | Should -BeTrue
        @($result.Settings | Where-Object settingId -eq 'SMB_CLIENT_SIGNING_REQUIRED')[0].collectionStatus | Should -Be 'NOT_AVAILABLE'
    }
    It 'does not convert null SMB configuration into disabled' {
        Mock Get-SmbClientConfiguration { [pscustomobject]@{ RequireSecuritySignature=$null; EnableInsecureGuestLogons=$null } } -ModuleName Protocols
        $result = Get-CSAProtocolsEvidence
        $signing = @($result.Settings | Where-Object settingId -eq 'SMB_CLIENT_SIGNING_REQUIRED')[0]
        $null -eq $signing.effectiveValue | Should -BeTrue
        $signing.collectionStatus | Should -Not -Be 'SUCCESS'
        @($result.Settings | Where-Object settingId -eq 'LLMNR_ENABLED')[0].collectionStatus | Should -Be 'SUCCESS'
    }
    It 'does not treat registry access denial as a documented default' {
        Mock Get-CSAProtocolRegistryValue { throw [UnauthorizedAccessException]::new('denied') } -ModuleName Protocols
        $result = Get-CSAProtocolsEvidence
        @($result.Settings | Where-Object settingId -eq 'LLMNR_ENABLED')[0].collectionStatus | Should -Be 'ACCESS_DENIED'
        @($result.Settings | Where-Object settingId -eq 'SMB_CLIENT_SIGNING_REQUIRED')[0].collectionStatus | Should -Be 'SUCCESS'
        $result.Status | Should -Be 'PARTIAL'
    }
}
