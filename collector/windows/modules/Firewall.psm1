Import-Module (Join-Path $PSScriptRoot "General.psm1") -Force

function Get-CSAFirewallEvidence {
    param([string]$PrivacyMode = "Standard")
    $settings = @()
    foreach ($profile in Get-NetFirewallProfile) {
        $settings += New-CSASetting "WINDOWS_FIREWALL_$($profile.Name.ToUpper())_ENABLED" "Firewall" ([bool]$profile.Enabled) "RUNTIME_STATE" "SUCCESS" 90 "Get-NetFirewallProfile" "$($profile.Name).Enabled"
    }
    @{ Settings = $settings }
}

Export-ModuleMember -Function Get-CSAFirewallEvidence
