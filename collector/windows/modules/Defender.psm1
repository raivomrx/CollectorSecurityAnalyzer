Import-Module (Join-Path $PSScriptRoot "General.psm1") -Force

function Get-CSADefenderEvidence {
    param([string]$PrivacyMode = "Standard")
    $settings = @()
    $status = Get-MpComputerStatus
    $settings += New-CSASetting "DEFENDER_REALTIME_PROTECTION_ENABLED" "Defender" ([bool]$status.RealTimeProtectionEnabled) "SECURITY_PRODUCT" "SUCCESS" 90 "Get-MpComputerStatus" "RealTimeProtectionEnabled"
    $settings += New-CSASetting "DEFENDER_TAMPER_PROTECTION_ENABLED" "Defender" ([bool]$status.IsTamperProtected) "SECURITY_PRODUCT" "SUCCESS" 90 "Get-MpComputerStatus" "IsTamperProtected"
    @{ Settings = $settings }
}

Export-ModuleMember -Function Get-CSADefenderEvidence
