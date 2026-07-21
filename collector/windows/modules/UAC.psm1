Import-Module (Join-Path $PSScriptRoot "General.psm1") -Force

function Get-CSAUACEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $moduleStatus = ""
    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $enableLua = [int](Get-CSARegistryValue $path "EnableLUA" 1)
        $adminPrompt = [int](Get-CSARegistryValue $path "ConsentPromptBehaviorAdmin" 5)
        $userPrompt = [int](Get-CSARegistryValue $path "ConsentPromptBehaviorUser" 3)
        $secureDesktop = [int](Get-CSARegistryValue $path "PromptOnSecureDesktop" 1)
        $filterAdmin = [int](Get-CSARegistryValue $path "FilterAdministratorToken" 0)
        $localTokenFilter = [int](Get-CSARegistryValue $path "LocalAccountTokenFilterPolicy" 0)
        $installerDetection = [int](Get-CSARegistryValue $path "EnableInstallerDetection" 1)
        $virtualization = [int](Get-CSARegistryValue $path "EnableVirtualization" 1)
        $values = [ordered]@{
            UAC_ENABLE_LUA = ($enableLua -eq 1)
            UAC_CONSENT_PROMPT_BEHAVIOR_ADMIN = $adminPrompt
            UAC_CONSENT_PROMPT_BEHAVIOR_USER = $userPrompt
            UAC_PROMPT_ON_SECURE_DESKTOP = ($secureDesktop -eq 1)
            UAC_FILTER_ADMINISTRATOR_TOKEN = ($filterAdmin -eq 1)
            UAC_LOCAL_ACCOUNT_TOKEN_FILTER_POLICY = $localTokenFilter
            UAC_ENABLE_INSTALLER_DETECTION = ($installerDetection -eq 1)
            UAC_ENABLE_VIRTUALIZATION = ($virtualization -eq 1)
            UAC_ADMIN_CONSENT_PROMPT_WEAK = ($adminPrompt -eq 0)
            LOCAL_ACCOUNT_TOKEN_FILTER_POLICY_WEAK = ($localTokenFilter -eq 1)
        }
        foreach ($name in $values.Keys) {
            $settings += New-CSASetting $name "UAC" $values[$name] "REGISTRY" "SUCCESS" 90 "Registry" "Policies/System/$name"
        }
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "UAC" "ACCESS_DENIED" "CSA-UAC-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "UAC" -Settings $settings -Errors $errors -ExpectedEvidenceCount 10 -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "UAC" $moduleStatus "CSA-UAC-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "UAC" -Settings $settings -Errors $errors -ExpectedEvidenceCount 10 -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function Get-CSAUACEvidence
