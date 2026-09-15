Import-Module (Join-Path $PSScriptRoot "General.psm1")

function Get-CSAProtocolRegistryValue {
    param([string]$Path, [string]$Name, $Default)
    # Missing policy means a documented default. An unreadable key does not.
    try { $key = Get-Item -LiteralPath $Path -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { return @{ Value = $Default; Source = "DEFAULT" } }
    if ($key.GetValueNames() -notcontains $Name) { return @{ Value = $Default; Source = "DEFAULT" } }
    $value = $key.GetValue($Name)
    if ($null -eq $value -or $value -is [string] -or $value -is [bool]) { throw "Policy value is not a registry integer" }
    return @{ Value = $value; Source = "REGISTRY" }
}

function Get-CSAProtocolsEvidence {
    param([string]$PrivacyMode = "Standard")
    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $attempts = @()
    $units = @(
        @{ Name = "SMB server"; Ids = @("SMBV1_SERVER_ENABLED", "SMB_SERVER_SIGNING_REQUIRED"); Read = {
            $server = Get-SmbServerConfiguration -ErrorAction Stop
            if ($server.EnableSMB1Protocol -isnot [bool] -or $server.RequireSecuritySignature -isnot [bool]) { throw "SMB server returned no reliable Boolean state" }
            New-CSASetting "SMBV1_SERVER_ENABLED" "Protocols" ([bool]$server.EnableSMB1Protocol) "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbServerConfiguration" "EnableSMB1Protocol"
            New-CSASetting "SMB_SERVER_SIGNING_REQUIRED" "Protocols" ([bool]$server.RequireSecuritySignature) "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbServerConfiguration" "RequireSecuritySignature"
        } },
        @{ Name = "SMB client"; Ids = @("SMB_CLIENT_SIGNING_REQUIRED", "SMB_INSECURE_GUEST_LOGONS_ENABLED", "INSECURE_GUEST_LOGONS_ENABLED"); Read = {
            $client = Get-SmbClientConfiguration -ErrorAction Stop
            if ($client.RequireSecuritySignature -isnot [bool] -or $client.EnableInsecureGuestLogons -isnot [bool]) { throw "SMB client returned no reliable Boolean state" }
            New-CSASetting "SMB_CLIENT_SIGNING_REQUIRED" "Protocols" ([bool]$client.RequireSecuritySignature) "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbClientConfiguration" "RequireSecuritySignature"
            foreach ($id in @("SMB_INSECURE_GUEST_LOGONS_ENABLED", "INSECURE_GUEST_LOGONS_ENABLED")) {
                New-CSASetting $id "Protocols" ([bool]$client.EnableInsecureGuestLogons) "RUNTIME_STATE" "SUCCESS" 90 "Get-SmbClientConfiguration" "EnableInsecureGuestLogons"
            }
        } },
        @{ Name = "SMBv1 client feature"; Ids = @("SMBV1_CLIENT_ENABLED"); Read = {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -ErrorAction Stop
            if ($null -eq $feature -or [string]$feature.State -notin @("Enabled", "Disabled", "DisabledWithPayloadRemoved")) { throw "SMBv1 feature state unavailable" }
            New-CSASetting "SMBV1_CLIENT_ENABLED" "Protocols" ([string]$feature.State -eq "Enabled") "RUNTIME_STATE" "SUCCESS" 90 "Get-WindowsOptionalFeature" "SMB1Protocol-Client"
        } },
        @{ Name = "LLMNR policy"; Ids = @("LLMNR_ENABLED"); Read = {
            $policy = Get-CSAProtocolRegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 1
            if ([int]$policy.Value -notin @(0, 1)) { throw "Unrecognized LLMNR policy" }
            New-CSASetting "LLMNR_ENABLED" "Protocols" ([int]$policy.Value -ne 0) $policy.Source "SUCCESS" 85 "Registry" "DNSClient/EnableMulticast"
        } },
        @{ Name = "NBT-NS adapters"; Ids = @("NETBIOS_ENABLED_ADAPTER_COUNT", "NETBIOS_TCPIP_ENABLED"); Read = {
            $adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop | ForEach-Object {
                $state = if ($null -eq $_.TcpipNetbiosOptions) { "UNKNOWN" } else { switch ([int]$_.TcpipNetbiosOptions) { 0 { "DEFAULT" } 1 { "ENABLED" } 2 { "DISABLED" } default { "UNKNOWN" } } }
                [ordered]@{ InterfaceIndex = $_.InterfaceIndex; State = $state }
            })
            $enabled = @($adapters | Where-Object { $_.State -eq "ENABLED" }).Count
            $defaults = @($adapters | Where-Object { $_.State -eq "DEFAULT" }).Count
            $unknown = @($adapters | Where-Object { $_.State -eq "UNKNOWN" }).Count
            $status = if ($adapters.Count -eq 0) { "NOT_AVAILABLE" } elseif ($defaults + $unknown -gt 0) { "PARTIAL" } else { "SUCCESS" }
            $metadata = @{ adapters = $adapters; defaultStateAdapterCount = $defaults; unknownStateAdapterCount = $unknown }
            New-CSASetting "NETBIOS_ENABLED_ADAPTER_COUNT" "Protocols" $enabled "RUNTIME_STATE" $status 85 "Win32_NetworkAdapterConfiguration" "TcpipNetbiosOptions" -Metadata $metadata
            New-CSASetting "NETBIOS_TCPIP_ENABLED" "Protocols" $(if ($enabled -gt 0) { $true } elseif ($status -eq "SUCCESS") { $false } else { $null }) "RUNTIME_STATE" $status 85 "Win32_NetworkAdapterConfiguration" "TcpipNetbiosOptions" -Metadata $metadata
        } },
        @{ Name = "NTLM outbound restriction"; Ids = @("NTLM_RESTRICTION_LEVEL"); Read = {
            $policy = Get-CSAProtocolRegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictSendingNTLMTraffic" 0
            if ([int]$policy.Value -notin @(0, 1, 2)) { throw "Unrecognized NTLM outbound policy" }
            New-CSASetting "NTLM_RESTRICTION_LEVEL" "Protocols" ([int]$policy.Value) $policy.Source "SUCCESS" 85 "Registry" "MSV1_0/RestrictSendingNTLMTraffic"
        } },
        @{ Name = "LM compatibility"; Ids = @("LAN_MANAGER_AUTHENTICATION_LEVEL", "LAN_MANAGER_AUTH_LEVEL"); Read = {
            $policy = Get-CSAProtocolRegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 3
            if ([int]$policy.Value -notin @(0, 1, 2, 3, 4, 5)) { throw "Unrecognized LM compatibility policy" }
            New-CSASetting "LAN_MANAGER_AUTHENTICATION_LEVEL" "Protocols" ([int]$policy.Value) $policy.Source "SUCCESS" 85 "Registry" "Lsa/LmCompatibilityLevel"
            New-CSASetting "LAN_MANAGER_AUTH_LEVEL" "Protocols" $(if ([int]$policy.Value -eq 5) { "NTLMV2_ONLY" } else { "LEGACY_ALLOWED" }) $policy.Source "SUCCESS" 85 "Registry" "Lsa/LmCompatibilityLevel"
        } },
        @{ Name = "WPAD policy"; Ids = @("WPAD_RELEVANT_STATE"); Read = {
            $policy = Get-CSAProtocolRegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad" 0
            if ([int]$policy.Value -notin @(0, 1)) { throw "Unrecognized WPAD policy" }
            New-CSASetting "WPAD_RELEVANT_STATE" "Protocols" $(if ([int]$policy.Value -eq 1) { "DISABLED" } else { "ENABLED_OR_DEFAULT" }) $policy.Source "SUCCESS" 75 "Registry" "WinHttp/DisableWpad" -Metadata @{ scope = "WinHTTP auto-proxy; other browser/proxy configuration is not established" }
        } }
    )
    foreach ($unit in $units) {
        try {
            $values = @(& $unit.Read)
            $settings += $values
            $status = if (@($values | Where-Object { $_.collectionStatus -ne "SUCCESS" }).Count -gt 0) { "PARTIAL" } else { "SUCCESS" }
            $attempts += @{ provider = $unit.Name; status = $status }
        } catch {
            $status = if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { "NOT_AVAILABLE" } else { Resolve-CSAExceptionStatus $_ }
            $attempts += @{ provider = $unit.Name; status = $status }
            $errors += New-CSACollectionError "Protocols" $status "CSA-PROTOCOL-PROVIDER-FAILED" "$($unit.Name): $status"
            foreach ($id in $unit.Ids) { $settings += New-CSASetting $id "Protocols" $null "RUNTIME_STATE" $status 0 $unit.Name }
        }
    }
    foreach ($aggregate in @(
        @{ Id = "SMBV1_ENABLED"; Inputs = @("SMBV1_CLIENT_ENABLED", "SMBV1_SERVER_ENABLED"); Any = $true },
        @{ Id = "SMB_SIGNING_REQUIRED"; Inputs = @("SMB_CLIENT_SIGNING_REQUIRED", "SMB_SERVER_SIGNING_REQUIRED"); Any = $false }
    )) {
        $inputs = @($settings | Where-Object { $_.settingId -in $aggregate.Inputs -and $_.collectionStatus -eq "SUCCESS" -and $_.effectiveValue -is [bool] })
        $value = $null
        $status = "PARTIAL"
        if ($aggregate.Any -and @($inputs | Where-Object { $_.effectiveValue }).Count -gt 0) { $value = $true; $status = "SUCCESS" }
        elseif ($inputs.Count -eq 2) { $value = if ($aggregate.Any) { $false } else { [bool]($inputs[0].effectiveValue -and $inputs[1].effectiveValue) }; $status = "SUCCESS" }
        $settings += New-CSASetting $aggregate.Id "Protocols" $value "RUNTIME_STATE" $status 90 "SMB configuration" "ClientAndServer"
    }
    $usable = @($attempts | Where-Object { $_.status -in @("SUCCESS", "PARTIAL") }).Count
    $moduleStatus = if (@($attempts | Where-Object { $_.status -ne "SUCCESS" }).Count -eq 0) { "SUCCESS" }
        elseif ($usable -gt 0) { "PARTIAL" }
        elseif (@($attempts | Where-Object { $_.status -ne "ACCESS_DENIED" }).Count -eq 0) { "ACCESS_DENIED" }
        else { "NOT_AVAILABLE" }
    New-CSAModuleResult -Module "Protocols" -Settings $settings -Errors $errors -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSAProtocolsEvidence
