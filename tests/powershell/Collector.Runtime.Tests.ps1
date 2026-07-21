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
        It "collects all 12 declared settings" {
            Import-Module (Join-Path $moduleRoot "DeviceGuard.psm1") -Force
            Mock Confirm-SecureBootUEFI { $true } -ModuleName DeviceGuard
            Mock Get-Tpm { [pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmEnabled=$true; TpmActivated=$true } } -ModuleName DeviceGuard
            Mock Get-CimInstance {
                if ($ClassName -eq "Win32_Tpm") { return [pscustomobject]@{ SpecVersion = "2.0" } }
                [pscustomobject]@{ SecurityServicesConfigured=@(1,2,3); SecurityServicesRunning=@(1,2,3); VirtualizationBasedSecurityStatus=2 }
            } -ModuleName DeviceGuard

            $result = Resolve-TestModuleResult "DeviceGuard" (Get-CSADeviceGuardEvidence)
            $result.Status | Should -Be "SUCCESS"
            $result.Settings.Count | Should -Be 12
            $result.ExpectedEvidenceCount | Should -Be 12
            $result.CollectedMandatoryEvidenceCount | Should -Be 5
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
    }
}
