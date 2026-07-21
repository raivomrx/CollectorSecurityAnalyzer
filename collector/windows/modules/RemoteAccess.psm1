Import-Module (Join-Path $PSScriptRoot "General.psm1") -Force

function Get-CSARemoteAccessEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $warnings = @()
    $moduleStatus = ""
    try {
        $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        $rdpTcpPath = "$rdpPath\WinStations\RDP-Tcp"
        $rdpEnabled = ([int](Get-CSARegistryValue $rdpPath "fDenyTSConnections" 1) -eq 0)
        $nlaRequired = ([int](Get-CSARegistryValue $rdpTcpPath "UserAuthentication" 0) -eq 1)
        $securityLayer = [int](Get-CSARegistryValue $rdpTcpPath "SecurityLayer" 0)
        $encryptionLevel = [int](Get-CSARegistryValue $rdpTcpPath "MinEncryptionLevel" 1)
        $settings += New-CSASetting "RDP_ENABLED" "Remote Access" $rdpEnabled "REGISTRY" "SUCCESS" 90 "Registry" "Terminal Server/fDenyTSConnections"
        $settings += New-CSASetting "RDP_NLA_REQUIRED" "Remote Access" $nlaRequired "REGISTRY" "SUCCESS" 90 "Registry" "RDP-Tcp/UserAuthentication"
        $settings += New-CSASetting "RDP_SECURITY_LAYER" "Remote Access" $securityLayer "REGISTRY" "SUCCESS" 85 "Registry" "RDP-Tcp/SecurityLayer"
        $settings += New-CSASetting "RDP_SECURITY_LAYER_WEAK" "Remote Access" ($securityLayer -lt 2) "REGISTRY" "SUCCESS" 85 "Registry" "RDP-Tcp/SecurityLayer"
        $settings += New-CSASetting "RDP_ENCRYPTION_LEVEL" "Remote Access" $encryptionLevel "REGISTRY" "SUCCESS" 85 "Registry" "RDP-Tcp/MinEncryptionLevel"
        $remoteAssistance = ([int](Get-CSARegistryValue "$rdpPath\Remote Assistance" "fAllowToGetHelp" 0) -eq 1)
        $settings += New-CSASetting "REMOTE_ASSISTANCE_ENABLED" "Remote Access" $remoteAssistance "REGISTRY" "SUCCESS" 85 "Registry" "Remote Assistance/fAllowToGetHelp"

        $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        $winrmEnabled = ($null -ne $winrm -and [string]$winrm.StartType -ne "Disabled")
        $settings += New-CSASetting "WINRM_SERVICE_ENABLED" "Remote Access" $winrmEnabled "RUNTIME_STATE" "SUCCESS" 90 "Get-Service" "WinRM.StartType"
        $listeners = @()
        if (Test-Path "WSMan:\localhost\Listener") {
            $listeners = @(Get-ChildItem "WSMan:\localhost\Listener" -ErrorAction SilentlyContinue)
        }
        $settings += New-CSASetting "WINRM_LISTENER_COUNT" "Remote Access" $listeners.Count "RUNTIME_STATE" "SUCCESS" 85 "WSMan provider" "localhost/Listener"
        $allowUnencrypted = ([string](Get-CSARegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic" 0) -eq "1")
        $basicAuth = ([string](Get-CSARegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\Auth" "Basic" 0) -eq "1")
        $settings += New-CSASetting "WINRM_UNENCRYPTED_TRAFFIC_ALLOWED" "Remote Access" $allowUnencrypted "GROUP_POLICY" "SUCCESS" 85 "Registry" "WinRM/Service/AllowUnencryptedTraffic"
        $settings += New-CSASetting "WINRM_ALLOW_UNENCRYPTED" "Remote Access" $allowUnencrypted "GROUP_POLICY" "SUCCESS" 85 "Registry" "WinRM/Service/AllowUnencryptedTraffic"
        $settings += New-CSASetting "WINRM_BASIC_AUTH_ENABLED" "Remote Access" $basicAuth "GROUP_POLICY" "SUCCESS" 85 "Registry" "WinRM/Service/Auth/Basic"

        $remoteRegistry = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
        $remoteRegistryEnabled = ($null -ne $remoteRegistry -and [string]$remoteRegistry.StartType -ne "Disabled")
        $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue
        $sshEnabled = ($null -ne $sshd -and [string]$sshd.StartType -ne "Disabled")
        $settings += New-CSASetting "REMOTE_REGISTRY_ENABLED" "Remote Access" $remoteRegistryEnabled "RUNTIME_STATE" "SUCCESS" 90 "Get-Service" "RemoteRegistry.StartType"
        $settings += New-CSASetting "OPENSSH_SERVER_ENABLED" "Remote Access" $sshEnabled "RUNTIME_STATE" "SUCCESS" 90 "Get-Service" "sshd.StartType"

        $remoteProducts = @()
        $roots = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        foreach ($root in $roots) {
            foreach ($item in @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
                $name = [string]$item.DisplayName
                if ($name -match '(?i)AnyDesk|TeamViewer|ScreenConnect|ConnectWise Control|RustDesk|Splashtop|LogMeIn|GoTo Resolve|Remote Utilities|VNC|Atera|BeyondTrust|Bomgar') {
                    $remoteProducts += $name
                }
            }
        }
        $remoteProducts = @($remoteProducts | Sort-Object -Unique)
        $settings += New-CSASetting "REMOTE_ACCESS_PRODUCTS" "Remote Access" $remoteProducts "RUNTIME_STATE" "SUCCESS" 75 "Installed software inventory" "RemoteAccessProductCandidates" -Metadata @{ approvedStateEvaluatedBy = "Analyzer policy profile" }
        $settings += New-CSASetting "UNAPPROVED_REMOTE_ACCESS_PRODUCT_COUNT" "Remote Access" $null "UNKNOWN" "NOT_AVAILABLE" 0 "Analyzer policy profile" "Not evaluated by collector" "CSA-POLICY-REQUIRED" "Approval is organization-specific and is evaluated by Analyzer."
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "RemoteAccess" "ACCESS_DENIED" "CSA-REMOTE-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "RemoteAccess" -Settings $settings -Errors $errors -Warnings $warnings -ExpectedEvidenceCount 14 -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "RemoteAccess" $moduleStatus "CSA-REMOTE-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "RemoteAccess" -Settings $settings -Errors $errors -Warnings $warnings -ExpectedEvidenceCount 14 -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSARemoteAccessEvidence
