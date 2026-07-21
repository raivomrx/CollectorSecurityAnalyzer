Import-Module (Join-Path $PSScriptRoot "General.psm1") -Force

function Get-CSAProtocolsEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $moduleStatus = ""
    try {
        $smb1Client = $false
        $smb1Server = $false
        if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            $smb1Client = ($null -ne $feature -and [string]$feature.State -eq "Enabled")
        }
        if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            $server = Get-SmbServerConfiguration -ErrorAction Stop
            $smb1Server = [bool]$server.EnableSMB1Protocol
            $settings += New-CSASetting "SMBV1_SERVER_ENABLED" "Protocols" $smb1Server "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbServerConfiguration" "EnableSMB1Protocol"
            $settings += New-CSASetting "SMB_SERVER_SIGNING_REQUIRED" "Protocols" ([bool]$server.RequireSecuritySignature) "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbServerConfiguration" "RequireSecuritySignature"
        }
        if (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue) {
            $client = Get-SmbClientConfiguration -ErrorAction Stop
            if ($client.PSObject.Properties.Name -contains "EnableSMB1Protocol") { $smb1Client = [bool]$client.EnableSMB1Protocol }
            $settings += New-CSASetting "SMBV1_CLIENT_ENABLED" "Protocols" $smb1Client "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbClientConfiguration" "EnableSMB1Protocol"
            $settings += New-CSASetting "SMB_CLIENT_SIGNING_REQUIRED" "Protocols" ([bool]$client.RequireSecuritySignature) "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbClientConfiguration" "RequireSecuritySignature"
            $guestLogons = [bool]$client.EnableInsecureGuestLogons
            $settings += New-CSASetting "SMB_INSECURE_GUEST_LOGONS_ENABLED" "Protocols" $guestLogons "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbClientConfiguration" "EnableInsecureGuestLogons"
            $settings += New-CSASetting "INSECURE_GUEST_LOGONS_ENABLED" "Protocols" $guestLogons "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbClientConfiguration" "EnableInsecureGuestLogons"
        }
        $settings += New-CSASetting "SMBV1_ENABLED" "Protocols" ($smb1Client -or $smb1Server) "RUNTIME_STATE" "SUCCESS" 90 "SMB configuration" "ClientOrServerSMB1"
        $clientSigning = @($settings | Where-Object { $_.settingId -eq "SMB_CLIENT_SIGNING_REQUIRED" } | Select-Object -First 1)
        $serverSigning = @($settings | Where-Object { $_.settingId -eq "SMB_SERVER_SIGNING_REQUIRED" } | Select-Object -First 1)
        $signingRequired = ($clientSigning.Count -gt 0 -and $serverSigning.Count -gt 0 -and [bool]$clientSigning[0].effectiveValue -and [bool]$serverSigning[0].effectiveValue)
        $settings += New-CSASetting "SMB_SIGNING_REQUIRED" "Protocols" $signingRequired "RUNTIME_STATE" "SUCCESS" 90 "SMB configuration" "ClientAndServerSigning"

        $llmnrValue = Get-CSARegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" $null
        $llmnrEnabled = if ($null -eq $llmnrValue) { $true } else { [int]$llmnrValue -ne 0 }
        $llmnrSource = if ($null -eq $llmnrValue) { "DEFAULT" } else { "GROUP_POLICY" }
        $settings += New-CSASetting "LLMNR_ENABLED" "Protocols" $llmnrEnabled $llmnrSource "SUCCESS" 85 "Registry" "DNSClient/EnableMulticast"

        $adapters = @()
        foreach ($adapter in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop)) {
            $state = switch ([int]$adapter.TcpipNetbiosOptions) { 1 { "ENABLED" } 2 { "DISABLED" } default { "DEFAULT" } }
            $adapters += [ordered]@{
                InterfaceIndex = $adapter.InterfaceIndex
                Description = [string]$adapter.Description
                State = $state
            }
        }
        $enabledAdapterCount = @($adapters | Where-Object { $_.State -eq "ENABLED" }).Count
        $defaultAdapterCount = @($adapters | Where-Object { $_.State -eq "DEFAULT" }).Count
        $netbiosStatus = if ($defaultAdapterCount -gt 0) { "PARTIAL" } else { "SUCCESS" }
        $metadata = @{ adapters = $adapters; defaultStateAdapterCount = $defaultAdapterCount }
        $settings += New-CSASetting "NETBIOS_ENABLED_ADAPTER_COUNT" "Protocols" $enabledAdapterCount "RUNTIME_STATE" $netbiosStatus $(if ($netbiosStatus -eq "SUCCESS") { 90 } else { 60 }) "Win32_NetworkAdapterConfiguration" "TcpipNetbiosOptions" -Metadata $metadata
        $settings += New-CSASetting "NETBIOS_TCPIP_ENABLED" "Protocols" ($enabledAdapterCount -gt 0) "RUNTIME_STATE" $netbiosStatus $(if ($netbiosStatus -eq "SUCCESS") { 90 } else { 60 }) "Win32_NetworkAdapterConfiguration" "TcpipNetbiosOptions" -Metadata $metadata

        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $lmLevel = Get-CSARegistryValue $lsaPath "LmCompatibilityLevel" 3
        $ntlmRestriction = Get-CSARegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictSendingNTLMTraffic" 0
        $lmDescription = if ([int]$lmLevel -ge 5) { "NTLMV2_ONLY" } else { "LEGACY_ALLOWED" }
        $settings += New-CSASetting "NTLM_RESTRICTION_LEVEL" "Protocols" ([int]$ntlmRestriction) "REGISTRY" "SUCCESS" 85 "Registry" "MSV1_0/RestrictSendingNTLMTraffic"
        $settings += New-CSASetting "LAN_MANAGER_AUTHENTICATION_LEVEL" "Protocols" ([int]$lmLevel) "REGISTRY" "SUCCESS" 85 "Registry" "Lsa/LmCompatibilityLevel"
        $settings += New-CSASetting "LAN_MANAGER_AUTH_LEVEL" "Protocols" $lmDescription "REGISTRY" "SUCCESS" 85 "Registry" "Lsa/LmCompatibilityLevel"

        $wpadDisabled = Get-CSARegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad" 0
        $settings += New-CSASetting "WPAD_RELEVANT_STATE" "Protocols" $(if ([int]$wpadDisabled -eq 1) { "DISABLED" } else { "ENABLED_OR_DEFAULT" }) "REGISTRY" "SUCCESS" 75 "Registry" "WinHttp/DisableWpad"
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "Protocols" "ACCESS_DENIED" "CSA-PROTOCOLS-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "Protocols" -Settings $settings -Errors $errors -ExpectedEvidenceCount 15 -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "Protocols" $moduleStatus "CSA-PROTOCOLS-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "Protocols" -Settings $settings -Errors $errors -ExpectedEvidenceCount 15 -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSAProtocolsEvidence
