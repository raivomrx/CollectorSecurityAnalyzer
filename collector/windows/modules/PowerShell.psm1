Import-Module (Join-Path $PSScriptRoot "General.psm1") -Force

function Get-CSAPowerShellEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $moduleStatus = ""
    try {
        $v2Feature = $null
        if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            $v2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
        }
        $v2Enabled = ($null -ne $v2Feature -and [string]$v2Feature.State -eq "Enabled")
        $settings += New-CSASetting "POWERSHELL_2_ENABLED" "PowerShell" $v2Enabled "RUNTIME_STATE" "SUCCESS" 90 "Get-WindowsOptionalFeature" "MicrosoftWindowsPowerShellV2Root"

        $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        $scriptBlock = ([int](Get-CSARegistryValue "$base\ScriptBlockLogging" "EnableScriptBlockLogging" 0) -eq 1)
        $moduleLogging = ([int](Get-CSARegistryValue "$base\ModuleLogging" "EnableModuleLogging" 0) -eq 1)
        $transcription = ([int](Get-CSARegistryValue "$base\Transcription" "EnableTranscripting" 0) -eq 1)
        $protected = ([int](Get-CSARegistryValue "$base\ProtectedEventLogging" "EnableProtectedEventLogging" 0) -eq 1)
        $settings += New-CSASetting "POWERSHELL_SCRIPT_BLOCK_LOGGING_ENABLED" "PowerShell" $scriptBlock "GROUP_POLICY" "SUCCESS" 90 "Registry" "PowerShell/ScriptBlockLogging"
        $settings += New-CSASetting "POWERSHELL_MODULE_LOGGING_ENABLED" "PowerShell" $moduleLogging "GROUP_POLICY" "SUCCESS" 90 "Registry" "PowerShell/ModuleLogging"
        $settings += New-CSASetting "POWERSHELL_TRANSCRIPTION_ENABLED" "PowerShell" $transcription "GROUP_POLICY" "SUCCESS" 90 "Registry" "PowerShell/Transcription"
        $settings += New-CSASetting "POWERSHELL_PROTECTED_EVENT_LOGGING_ENABLED" "PowerShell" $protected "GROUP_POLICY" "SUCCESS" 85 "Registry" "PowerShell/ProtectedEventLogging"

        $policies = [ordered]@{}
        foreach ($scope in @("MachinePolicy", "UserPolicy", "Process", "CurrentUser", "LocalMachine")) {
            try { $policies[$scope] = [string](Get-ExecutionPolicy -Scope $scope -ErrorAction Stop) } catch { $policies[$scope] = "UNKNOWN" }
        }
        $settings += New-CSASetting "POWERSHELL_EXECUTION_POLICY_BY_SCOPE" "PowerShell" $policies "RUNTIME_STATE" "SUCCESS" 80 "Get-ExecutionPolicy" "AllScopes" -Metadata @{ securityBoundary = $false }
        $settings += New-CSASetting "POWERSHELL_LANGUAGE_MODE" "PowerShell" ([string]$ExecutionContext.SessionState.LanguageMode) "RUNTIME_STATE" "SUCCESS" 90 "ExecutionContext" "SessionState.LanguageMode"

        $amsiAvailable = $false
        try { $amsiAvailable = ($null -ne [type]::GetType("System.Management.Automation.AmsiUtils, System.Management.Automation", $false)) } catch { $amsiAvailable = $false }
        $settings += New-CSASetting "AMSI_AVAILABLE" "PowerShell" $amsiAvailable "RUNTIME_STATE" "SUCCESS" 75 "System.Management.Automation" "AmsiUtils"
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "PowerShell" "ACCESS_DENIED" "CSA-POWERSHELL-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "PowerShell" -Settings $settings -Errors $errors -ExpectedEvidenceCount 8 -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "PowerShell" $moduleStatus "CSA-POWERSHELL-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "PowerShell" -Settings $settings -Errors $errors -ExpectedEvidenceCount 8 -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSAPowerShellEvidence
