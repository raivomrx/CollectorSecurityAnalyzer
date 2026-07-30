BeforeAll {
    $collectorRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\collector\windows")).Path
    $moduleRoot = Join-Path $collectorRoot "modules"
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $collectorRoot "evidence-manifest.json") | ConvertFrom-Json
    Import-Module (Join-Path $moduleRoot "General.psm1") -Force

    function Resolve-TestModuleResult {
        param([string]$Module, $Result)

        $manifestModule = @($manifest.modules | Where-Object { $_.module -eq $Module })[0]
        Resolve-CSAModuleEvidence -Result $Result -ManifestModule $manifestModule
    }
}

Describe "CSA Windows Collector runtime evidence contracts" {
    Context "Defender" {
        It "collects all canonical settings and suppresses exclusion details" {
            Import-Module (Join-Path $moduleRoot "Defender.psm1") -Force
            Mock Get-MpComputerStatus {
                [pscustomobject]@{
                    AMServiceEnabled = $true; AntivirusEnabled = $true
                    RealTimeProtectionEnabled = $true; BehaviorMonitorEnabled = $true
                    IoavProtectionEnabled = $true; IsTamperProtected = $true
                    AntivirusSignatureVersion = "1.2.3.4"
                    AntivirusSignatureLastUpdated = (Get-Date).AddDays(-2)
                    FullScanEndTime = (Get-Date).AddDays(-4)
                    QuickScanEndTime = (Get-Date).AddHours(-3)
                }
            } -ModuleName Defender
            Mock Get-MpPreference {
                [pscustomobject]@{
                    DisableScriptScanning = $false; EnableNetworkProtection = 1
                    EnableControlledFolderAccess = 1; MAPSReporting = 2
                    SubmitSamplesConsent = 1; PUAProtection = 1
                    ExclusionPath = @("C:\Sensitive\Client"); ExclusionExtension = @("tmp")
                    ExclusionProcess = @("tool.exe")
                }
            } -ModuleName Defender

            $result = Resolve-TestModuleResult "Defender" (Get-CSADefenderEvidence -PrivacyMode Strict)
            $result.Status | Should -Be "SUCCESS"
            $result.Settings.Count | Should -Be 18
            $result.ExpectedEvidenceCount | Should -Be 18
            $result.CollectedEvidenceCount | Should -Be 18
            ($result.Settings | ConvertTo-Json -Depth 8) | Should -Not -Match 'Sensitive|Client'
            @($result.Settings | Where-Object { $_.settingId -eq "DEFENDER_SIGNATURE_AGE_DAYS" }).Count | Should -Be 1
            @($result.Settings | Where-Object { $_.settingId -eq "DEFENDER_EXCLUSION_COUNT" }).Count | Should -Be 1
        }
    }

    Context "Firewall" {
        BeforeAll {
            Get-Module Firewall -All | Remove-Module -Force -ErrorAction SilentlyContinue
            Import-Module (Join-Path $moduleRoot "Firewall.psm1") -Force
        }

        BeforeEach {
            Mock Get-Service { [pscustomobject]@{ StartType = "Automatic" } } -ModuleName Firewall
            Mock Get-NetConnectionProfile { @([pscustomobject]@{ NetworkCategory = "Private" }) } -ModuleName Firewall
        }

        It "uses three runtime profiles and 40 evidence units" {
            Mock Get-NetFirewallProfile { @(
                [pscustomobject]@{ Name="Domain"; Enabled=$true; DefaultInboundAction="Block"; DefaultOutboundAction="Allow"; NotifyOnListen=$true; AllowInboundRules=$true; AllowLocalFirewallRules=$true; AllowLocalIPsecRules=$true; LogAllowed=$true; LogBlocked=$true; LogIgnored=$false; LogFileName="C:\Windows\pfirewall.log"; LogMaxSizeKilobytes=4096 },
                [pscustomobject]@{ Name="Private"; Enabled=$true; DefaultInboundAction="Block"; DefaultOutboundAction="Allow"; NotifyOnListen=$true; AllowInboundRules=$true; AllowLocalFirewallRules=$true; AllowLocalIPsecRules=$true; LogAllowed=$true; LogBlocked=$true; LogIgnored=$false; LogFileName="C:\Windows\pfirewall.log"; LogMaxSizeKilobytes=4096 },
                [pscustomobject]@{ Name="Public"; Enabled=$false; DefaultInboundAction="Block"; DefaultOutboundAction="Allow"; NotifyOnListen=$true; AllowInboundRules=$true; AllowLocalFirewallRules=$true; AllowLocalIPsecRules=$true; LogAllowed=$true; LogBlocked=$true; LogIgnored=$false; LogFileName="C:\Windows\pfirewall.log"; LogMaxSizeKilobytes=4096 }
            ) } -ModuleName Firewall

            $result = Resolve-TestModuleResult "Firewall" (Get-CSAFirewallEvidence -PrivacyMode Strict)
            $result.Status | Should -Be "SUCCESS"
            $result.Settings.Count | Should -Be 40
            $result.ExpectedEvidenceCount | Should -Be 40
            $result.CollectedEvidenceCount | Should -Be 40
            @($result.Settings | Where-Object { $_.settingId -eq "WINDOWS_FIREWALL_PUBLIC_ENABLED" -and $_.effectiveValue -eq $false }).Count | Should -Be 1
        }

        It "marks a missing standard profile as PARTIAL" {
            Mock Get-NetFirewallProfile { @(
                [pscustomobject]@{ Name="Domain"; Enabled=$true; DefaultInboundAction="Block"; DefaultOutboundAction="Allow"; NotifyOnListen=$true; AllowInboundRules=$true; AllowLocalFirewallRules=$true; AllowLocalIPsecRules=$true; LogAllowed=$true; LogBlocked=$true; LogIgnored=$false; LogFileName="x"; LogMaxSizeKilobytes=4096 },
                [pscustomobject]@{ Name="Private"; Enabled=$true; DefaultInboundAction="Block"; DefaultOutboundAction="Allow"; NotifyOnListen=$true; AllowInboundRules=$true; AllowLocalFirewallRules=$true; AllowLocalIPsecRules=$true; LogAllowed=$true; LogBlocked=$true; LogIgnored=$false; LogFileName="x"; LogMaxSizeKilobytes=4096 }
            ) } -ModuleName Firewall

            $result = Resolve-TestModuleResult "Firewall" (Get-CSAFirewallEvidence)
            $result.Status | Should -Be "PARTIAL"
            $result.ExpectedEvidenceCount | Should -Be 40
            $result.CollectedEvidenceCount | Should -Be 28
        }
    }

    Context "Updates" {
        It "returns all 20 settings without a false PARTIAL result" {
            Import-Module (Join-Path $moduleRoot "Updates.psm1") -Force
            Mock New-Object {
                [pscustomobject]@{ Results = [pscustomobject]@{
                    LastSearchSuccessDate = (Get-Date).AddDays(-1)
                    LastInstallationSuccessDate = (Get-Date).AddDays(-2)
                } }
            } -ModuleName Updates -ParameterFilter { $ComObject -eq "Microsoft.Update.AutoUpdate" }
            Mock Test-Path { $false } -ModuleName Updates
            Mock Get-Service { [pscustomobject]@{ StartType = "Manual" } } -ModuleName Updates
            Mock Get-CSARegistryValue { $DefaultValue } -ModuleName Updates

            $result = Resolve-TestModuleResult "Updates" (Get-CSAUpdatesEvidence)
            $result.Status | Should -Be "SUCCESS"
            $result.Settings.Count | Should -Be 20
            $result.ExpectedEvidenceCount | Should -Be 16
            $result.CollectedEvidenceCount | Should -Be 16
        }
    }

    Context "Device Guard" {
        BeforeAll {
            Get-Module DeviceGuard -All | Remove-Module -Force -ErrorAction SilentlyContinue
            Import-Module (Join-Path $moduleRoot "DeviceGuard.psm1") -Force
        }

        BeforeEach {
            Mock Get-CimInstance {
                if ($ClassName -eq "Win32_Tpm") {
                    return [pscustomobject]@{ SpecVersion = "2.0" }
                }
                [pscustomobject]@{
                    SecurityServicesConfigured = @(1,2,3)
                    SecurityServicesRunning = @(1,2,3)
                    VirtualizationBasedSecurityStatus = 2
                }
            } -ModuleName DeviceGuard
        }

        It "collects all 12 declared settings" {
            Mock Confirm-SecureBootUEFI { $true } -ModuleName DeviceGuard
            Mock Get-Tpm { [pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmEnabled=$true; TpmActivated=$true } } -ModuleName DeviceGuard

            $result = Resolve-TestModuleResult "DeviceGuard" (Get-CSADeviceGuardEvidence)
            $result.Status | Should -Be "SUCCESS"
            $result.Settings.Count | Should -Be 12
            $result.ExpectedEvidenceCount | Should -Be 12
            $result.CollectedMandatoryEvidenceCount | Should -Be 5
        }

        It "normalizes TPM present and ready as reliable success" {
            $tpm = { [pscustomobject]@{
                TpmPresent=$true; TpmReady=$true
                TpmEnabled=$true; TpmActivated=$true
            } }
            $result = Get-CSADeviceGuardEvidence `
                -SecureBootProvider { $true } `
                -TpmProvider $tpm
            $ready = @($result.Settings | Where-Object {
                $_.settingId -eq "TPM_READY"
            })[0]
            $ready.collectionStatus | Should -Be "SUCCESS"
            $ready.effectiveValue | Should -BeTrue
        }

        It "preserves TPM present but not ready as reliable false" {
            $tpm = { [pscustomobject]@{
                TpmPresent=$true; TpmReady=$false
                TpmEnabled=$true; TpmActivated=$true
            } }
            $result = Get-CSADeviceGuardEvidence `
                -SecureBootProvider { $true } `
                -TpmProvider $tpm
            $present = @($result.Settings | Where-Object {
                $_.settingId -eq "TPM_PRESENT"
            })[0]
            $ready = @($result.Settings | Where-Object {
                $_.settingId -eq "TPM_READY"
            })[0]
            $present.effectiveValue | Should -BeTrue
            $ready.collectionStatus | Should -Be "SUCCESS"
            $ready.effectiveValue | Should -BeFalse
        }

        It "preserves a reliable absent TPM result" {
            $tpm = { [pscustomobject]@{
                TpmPresent=$false; TpmReady=$false
                TpmEnabled=$false; TpmActivated=$false
            } }
            $result = Get-CSADeviceGuardEvidence `
                -SecureBootProvider { $true } `
                -TpmProvider $tpm
            $present = @($result.Settings | Where-Object {
                $_.settingId -eq "TPM_PRESENT"
            })[0]
            $present.collectionStatus | Should -Be "SUCCESS"
            $present.effectiveValue | Should -BeFalse
        }

        It "does not turn TPM provider access denied into false" {
            $tpm = {
                throw (New-Object System.UnauthorizedAccessException "denied")
            }
            $result = Get-CSADeviceGuardEvidence `
                -SecureBootProvider { $true } `
                -TpmProvider $tpm
            $ready = @($result.Settings | Where-Object {
                $_.settingId -eq "TPM_READY"
            })[0]
            $ready.collectionStatus | Should -Be "ACCESS_DENIED"
            $null -eq $ready.effectiveValue | Should -BeTrue
        }

        It "marks incomplete TPM provider output as partial" {
            $tpm = { [pscustomobject]@{
                TpmPresent=$true; TpmReady=$true
                TpmEnabled=$null; TpmActivated=$null
            } }
            $result = Get-CSADeviceGuardEvidence `
                -SecureBootProvider { $true } `
                -TpmProvider $tpm
            @($result.Settings | Where-Object {
                $_.settingId -eq "TPM_READY"
            })[0].collectionStatus | Should -Be "SUCCESS"
            @($result.Settings | Where-Object {
                $_.settingId -eq "TPM_ENABLED"
            })[0].collectionStatus | Should -Be "PARTIAL"
        }

        It "marks malformed TPM provider output as partial" {
            $tpm = { [pscustomobject]@{
                TpmPresent="maybe"; TpmReady="unknown"
                TpmEnabled=2; TpmActivated=@()
            } }
            $result = Get-CSADeviceGuardEvidence `
                -SecureBootProvider { $true } `
                -TpmProvider $tpm
            @($result.Settings | Where-Object {
                $_.settingId -like "TPM_*" -and
                $_.settingId -ne "TPM_SPEC_VERSION"
            } | Where-Object {
                $_.collectionStatus -eq "PARTIAL"
            }).Count | Should -Be 4
        }

        It "uses tpmtool when medium-integrity Get-Tpm returns all false" {
            $tpm = { [pscustomobject]@{
                TpmPresent=$false; TpmReady=$false
                TpmEnabled=$false; TpmActivated=$false
            } }
            $fallback = {
                @("TPM Present: True", "TPM Ready for Storage: True")
            }
            $result = Get-CSADeviceGuardEvidence `
                -SecureBootProvider { $true } `
                -TpmProvider $tpm `
                -TpmFallbackProvider $fallback
            $ready = @($result.Settings | Where-Object {
                $_.settingId -eq "TPM_READY"
            })[0]
            $ready.collectionStatus | Should -Be "SUCCESS"
            $ready.effectiveValue | Should -BeTrue
            $ready.provider | Should -Be "tpmtool.exe"
        }

        It "does not use registry to override unsupported Secure Boot" {
            $secureBoot = { throw "Secure Boot is not supported" }
            $result = Get-CSADeviceGuardEvidence `
                -SecureBootProvider $secureBoot `
                -SecureBootRegistryProvider { $true } `
                -TpmProvider { [pscustomobject]@{
                    TpmPresent=$true; TpmReady=$true
                    TpmEnabled=$true; TpmActivated=$true
                } }
            $setting = @($result.Settings | Where-Object {
                $_.settingId -eq "SECURE_BOOT_ENABLED"
            })[0]
            $setting.collectionStatus | Should -Be "NOT_SUPPORTED"
            $null -eq $setting.effectiveValue | Should -BeTrue
        }
    }

    Context "Remote Access" {
        It "collects all 15 settings and resolves the canonical alias once" {
            Import-Module (Join-Path $moduleRoot "RemoteAccess.psm1") -Force
            Mock Get-CSARegistryValue { $DefaultValue } -ModuleName RemoteAccess
            Mock Get-Service { [pscustomobject]@{ StartType = "Disabled" } } -ModuleName RemoteAccess
            Mock Test-Path { $false } -ModuleName RemoteAccess
            Mock Get-ItemProperty { @() } -ModuleName RemoteAccess

            $result = Resolve-TestModuleResult "RemoteAccess" (Get-CSARemoteAccessEvidence)
            $result.Status | Should -Be "SUCCESS"
            $result.Settings.Count | Should -Be 15
            $result.ExpectedEvidenceCount | Should -Be 14
            $result.CollectedEvidenceCount | Should -Be 13
        }
    }

    Context "BitLocker" {
        BeforeAll {
            Get-Module BitLocker -All | Remove-Module -Force -ErrorAction SilentlyContinue
            Import-Module (Join-Path $moduleRoot "BitLocker.psm1") -Force
        }

        It "counts one operating-system volume as eight canonical units" {
            $provider = { @([pscustomobject]@{ MountPoint="C:"; VolumeType="OperatingSystem"; ProtectionStatus="On"; EncryptionPercentage=100; EncryptionMethod="XtsAes256"; LockStatus="Unlocked"; AutoUnlockEnabled=$false; KeyProtector=@([pscustomobject]@{KeyProtectorType="Tpm"}) }) }
            $result = Resolve-TestModuleResult "BitLocker" (Get-CSABitLockerEvidence -VolumeProvider $provider -BitLockerSupported $true)
            $result.Status | Should -Be "SUCCESS"
            $result.Settings.Count | Should -Be 9
            $result.ExpectedEvidenceCount | Should -Be 8
            $result.CollectedEvidenceCount | Should -Be 8
        }

        It "expands cardinality for an OS and a data volume" {
            $provider = { @(
                [pscustomobject]@{ MountPoint="C:"; VolumeType="OperatingSystem"; ProtectionStatus="On"; EncryptionPercentage=100; EncryptionMethod="XtsAes256"; LockStatus="Unlocked"; AutoUnlockEnabled=$false; KeyProtector=@() },
                [pscustomobject]@{ MountPoint="D:"; VolumeType="FixedData"; ProtectionStatus="Off"; EncryptionPercentage=0; EncryptionMethod="None"; LockStatus="Unlocked"; AutoUnlockEnabled=$false; KeyProtector=@() }
            ) }
            $result = Resolve-TestModuleResult "BitLocker" (Get-CSABitLockerEvidence -VolumeProvider $provider -BitLockerSupported $true)
            $result.Settings.Count | Should -Be 17
            $result.ExpectedEvidenceCount | Should -Be 16
            $result.CollectedEvidenceCount | Should -Be 16
        }

        It "returns NOT_AVAILABLE when no fixed volumes apply" {
            $result = Resolve-TestModuleResult "BitLocker" (Get-CSABitLockerEvidence -VolumeProvider { @() } -BitLockerSupported $true)
            $result.Status | Should -Be "NOT_AVAILABLE"
            $result.ExpectedEvidenceCount | Should -Be 0
        }

        It "preserves NOT_SUPPORTED" {
            $result = Resolve-TestModuleResult "BitLocker" (Get-CSABitLockerEvidence -BitLockerSupported $false)
            $result.Status | Should -Be "NOT_SUPPORTED"
        }

        It "preserves ACCESS_DENIED" {
            $provider = { throw (New-Object System.UnauthorizedAccessException "denied") }
            $result = Resolve-TestModuleResult "BitLocker" (Get-CSABitLockerEvidence -VolumeProvider $provider -BitLockerSupported $true)
            $result.Status | Should -Be "ACCESS_DENIED"
        }

        It "uses WMI after the primary provider is denied" {
            $primary = {
                throw (New-Object System.UnauthorizedAccessException "denied")
            }
            $wmi = { @([pscustomobject]@{
                MountPoint="C:"; VolumeType="OperatingSystem"
                ProtectionStatus="On"; ProtectionEnabled=$true
                EncryptionPercentage=100
                EncryptionState="FULLY_ENCRYPTED"
                EncryptionMethod="XtsAes256"; LockStatus="UNKNOWN"
                AutoUnlockEnabled=$false; KeyProtector=@()
            }) }
            $result = Get-CSABitLockerEvidence `
                -VolumeProvider $primary `
                -BitLockerSupported $true `
                -WmiProvider $wmi
            $setting = @($result.Settings | Where-Object {
                $_.settingId -eq "BITLOCKER_OS_PROTECTION"
            })[0]
            $result.Status | Should -Be "SUCCESS"
            $setting.effectiveValue | Should -BeTrue
            $setting.provider | Should -Be "WIN32_ENCRYPTABLE_VOLUME"
            $setting.confidence | Should -Be 90
        }

        It "keeps a registry-only indicator partial" {
            $result = Get-CSABitLockerEvidence `
                -VolumeProvider { @() } `
                -BitLockerSupported $true `
                -RegistryProvider { $true }
            $setting = @($result.Settings | Where-Object {
                $_.settingId -eq "BITLOCKER_OS_PROTECTION"
            })[0]
            $result.Status | Should -Be "PARTIAL"
            $setting.collectionStatus | Should -Be "PARTIAL"
            $setting.configuredValue | Should -BeTrue
            $null -eq $setting.effectiveValue | Should -BeTrue
        }
    }
}
