Import-Module (Join-Path $PSScriptRoot "General.psm1") -Force

function Get-CSANetworkEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $moduleStatus = ""
    if (-not (Get-Command Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
        $errorItem = New-CSACollectionError "Network" "NOT_SUPPORTED" "CSA-NETWORK-NOT-SUPPORTED" "NetConnection profile cmdlets are unavailable."
        return New-CSAModuleResult -Module "Network" -Errors @($errorItem) -ExpectedEvidenceCount 5 -StartedAt $startedAt -Status "NOT_SUPPORTED"
    }
    try {
        $profiles = @(Get-NetConnectionProfile -ErrorAction Stop)
        $activeAdapters = @($profiles | ForEach-Object {
            [ordered]@{
                InterfaceAlias = [string]$_.InterfaceAlias
                InterfaceIndex = $_.InterfaceIndex
                NetworkCategory = [string]$_.NetworkCategory
                IPv4Connectivity = [string]$_.IPv4Connectivity
                IPv6Connectivity = [string]$_.IPv6Connectivity
            }
        })
        $categories = @($profiles | ForEach-Object { [string]$_.NetworkCategory } | Sort-Object -Unique)
        $profileNames = @($profiles | ForEach-Object { Protect-CSAIdentifier $_.Name $PrivacyMode })
        $settings += New-CSASetting "ACTIVE_NETWORK_PROFILE" "Network" $profileNames "RUNTIME_STATE" "SUCCESS" 90 "Get-NetConnectionProfile" "Name"
        $settings += New-CSASetting "ACTIVE_NETWORK_CATEGORY" "Network" $categories "RUNTIME_STATE" "SUCCESS" 90 "Get-NetConnectionProfile" "NetworkCategory"
        $settings += New-CSASetting "ACTIVE_NETWORK_ADAPTERS" "Network" $activeAdapters "RUNTIME_STATE" "SUCCESS" 90 "Get-NetConnectionProfile" "Interfaces"
        $settings += New-CSASetting "PUBLIC_NETWORK_ADAPTER_COUNT" "Network" (@($profiles | Where-Object { [string]$_.NetworkCategory -eq "Public" }).Count) "RUNTIME_STATE" "SUCCESS" 90 "Get-NetConnectionProfile" "Public.Count"

        $netbiosAdapters = @()
        foreach ($adapter in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop)) {
            $netbiosAdapters += [ordered]@{
                InterfaceIndex = $adapter.InterfaceIndex
                Description = [string]$adapter.Description
                State = switch ([int]$adapter.TcpipNetbiosOptions) { 1 { "ENABLED" } 2 { "DISABLED" } default { "DEFAULT" } }
            }
        }
        $settings += New-CSASetting "NETBIOS_STATE_PER_ADAPTER" "Network" $netbiosAdapters "RUNTIME_STATE" "SUCCESS" 85 "Win32_NetworkAdapterConfiguration" "TcpipNetbiosOptions"
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "Network" "ACCESS_DENIED" "CSA-NETWORK-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "Network" -Settings $settings -Errors $errors -ExpectedEvidenceCount 5 -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "Network" $moduleStatus "CSA-NETWORK-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "Network" -Settings $settings -Errors $errors -ExpectedEvidenceCount 5 -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSANetworkEvidence
