Import-Module (Join-Path $PSScriptRoot "General.psm1")

function ConvertFrom-CSAAuditSetting {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $text = $Value.ToLowerInvariant()
    $estonianSuccess = ([char]0x00F5) + "nnest"
    $estonianFailure = "nurjum|eba" + ([char]0x00F5) + "nnest"
    $recognized = $text -match "success|failure|no auditing|auditeer|$estonianSuccess|$estonianFailure"
    if (-not $recognized) { return $null }
    $isEstonianFailure = $text -match $estonianFailure
    [ordered]@{
        Success = ($text -match "success|$estonianSuccess" -and -not ($text -match "eba$estonianSuccess"))
        Failure = ($text -match "failure" -or $isEstonianFailure)
    }
}

function Get-CSAAuditSubcategory {
    param([string]$Guid)

    $rows = @(& auditpol.exe /get "/subcategory:$Guid" /r 2>$null | ConvertFrom-Csv)
    if ($rows.Count -eq 0) { return $null }
    $values = @($rows[0].PSObject.Properties | ForEach-Object { [string]$_.Value })
    $result = $null
    foreach ($value in $values) {
        $candidate = ConvertFrom-CSAAuditSetting $value
        if ($null -ne $candidate) { $result = $candidate }
    }
    return $result
}

function Get-CSAAuditPolicyEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $warnings = @()
    $moduleStatus = ""
    $subcategories = [ordered]@{
        LOGON = "{0CCE9215-69AE-11D9-BED3-505054503030}"
        USER_ACCOUNT_MANAGEMENT = "{0CCE9235-69AE-11D9-BED3-505054503030}"
        PROCESS_CREATION = "{0CCE922B-69AE-11D9-BED3-505054503030}"
        AUDIT_POLICY_CHANGE = "{0CCE922F-69AE-11D9-BED3-505054503030}"
    }
    try {
        if (-not (Get-Command auditpol.exe -ErrorAction SilentlyContinue)) {
            $errorItem = New-CSACollectionError "AuditPolicy" "NOT_SUPPORTED" "CSA-AUDITPOL-NOT-SUPPORTED" "auditpol.exe is unavailable."
            return New-CSAModuleResult -Module "AuditPolicy" -Errors @($errorItem) -StartedAt $startedAt -Status "NOT_SUPPORTED"
        }
        $results = @{}
        foreach ($name in $subcategories.Keys) {
            $results[$name] = Get-CSAAuditSubcategory $subcategories[$name]
            if ($null -eq $results[$name]) { $warnings += "Audit subcategory $name could not be parsed." }
        }
        $pairs = [ordered]@{
            AUDIT_LOGON_SUCCESS = @("LOGON", "Success")
            AUDIT_LOGON_FAILURE = @("LOGON", "Failure")
            AUDIT_ACCOUNT_MANAGEMENT_SUCCESS = @("USER_ACCOUNT_MANAGEMENT", "Success")
            AUDIT_ACCOUNT_MANAGEMENT_FAILURE = @("USER_ACCOUNT_MANAGEMENT", "Failure")
            AUDIT_PROCESS_CREATION_SUCCESS = @("PROCESS_CREATION", "Success")
            AUDIT_POLICY_CHANGE_SUCCESS = @("AUDIT_POLICY_CHANGE", "Success")
            AUDIT_POLICY_CHANGE_FAILURE = @("AUDIT_POLICY_CHANGE", "Failure")
        }
        foreach ($settingId in $pairs.Keys) {
            $pair = $pairs[$settingId]
            $auditResult = $results[$pair[0]]
            $value = if ($null -ne $auditResult) { [bool]$auditResult[$pair[1]] } else { $null }
            $status = if ($null -ne $auditResult) { "SUCCESS" } else { "NOT_AVAILABLE" }
            $settings += New-CSASetting $settingId "Audit" $value "LOCAL_POLICY" $status $(if ($status -eq "SUCCESS") { 85 } else { 0 }) "auditpol.exe" $subcategories[$pair[0]]
        }

        $forceSubcategory = ([int](Get-CSARegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" 0) -eq 1)
        $settings += New-CSASetting "AUDIT_FORCE_SUBCATEGORY_SETTINGS" "Audit" $forceSubcategory "REGISTRY" "SUCCESS" 90 "Registry" "Lsa/SCENoApplyLegacyAuditPolicy"
        $available = @($results.Values | Where-Object { $null -ne $_ }).Count
        $coverage = [math]::Round(($available / $subcategories.Count) * 100, 1)
        $settings += New-CSASetting "AUDIT_POLICY_COVERAGE_PERCENT" "Audit" $coverage "LOCAL_POLICY" "SUCCESS" 85 "auditpol.exe" "RequiredSubcategories"
        $settings += New-CSASetting "AUDIT_ADVANCED_POLICY_COVERAGE_PERCENT" "Audit" $coverage "LOCAL_POLICY" "SUCCESS" 85 "auditpol.exe" "RequiredSubcategories"
        $settings += New-CSASetting "AUDIT_LOGON_FAILURE_ENABLED" "Audit" $(if ($null -ne $results.LOGON) { [bool]$results.LOGON.Failure } else { $null }) "LOCAL_POLICY" $(if ($null -ne $results.LOGON) { "SUCCESS" } else { "NOT_AVAILABLE" }) 85 "auditpol.exe" $subcategories.LOGON
        $accountEnabled = ($null -ne $results.USER_ACCOUNT_MANAGEMENT -and ($results.USER_ACCOUNT_MANAGEMENT.Success -or $results.USER_ACCOUNT_MANAGEMENT.Failure))
        $settings += New-CSASetting "AUDIT_ACCOUNT_MANAGEMENT_ENABLED" "Audit" $accountEnabled "LOCAL_POLICY" $(if ($null -ne $results.USER_ACCOUNT_MANAGEMENT) { "SUCCESS" } else { "NOT_AVAILABLE" }) 85 "auditpol.exe" $subcategories.USER_ACCOUNT_MANAGEMENT
        $settings += New-CSASetting "AUDIT_PROCESS_CREATION_ENABLED" "Audit" $(if ($null -ne $results.PROCESS_CREATION) { [bool]$results.PROCESS_CREATION.Success } else { $null }) "LOCAL_POLICY" $(if ($null -ne $results.PROCESS_CREATION) { "SUCCESS" } else { "NOT_AVAILABLE" }) 85 "auditpol.exe" $subcategories.PROCESS_CREATION
        $policyEnabled = ($null -ne $results.AUDIT_POLICY_CHANGE -and ($results.AUDIT_POLICY_CHANGE.Success -or $results.AUDIT_POLICY_CHANGE.Failure))
        $settings += New-CSASetting "AUDIT_POLICY_CHANGE_ENABLED" "Audit" $policyEnabled "LOCAL_POLICY" $(if ($null -ne $results.AUDIT_POLICY_CHANGE) { "SUCCESS" } else { "NOT_AVAILABLE" }) 85 "auditpol.exe" $subcategories.AUDIT_POLICY_CHANGE
    } catch [System.UnauthorizedAccessException] {
        $errors += New-CSACollectionError "AuditPolicy" "ACCESS_DENIED" "CSA-AUDITPOL-ACCESS-DENIED" $_.Exception.Message
        return New-CSAModuleResult -Module "AuditPolicy" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status "ACCESS_DENIED"
    } catch {
        $moduleStatus = Resolve-CSAExceptionStatus $_
        $errors += New-CSACollectionError "AuditPolicy" $moduleStatus "CSA-AUDITPOL-COLLECTION-FAILED" $_.Exception.Message
    }
    New-CSAModuleResult -Module "AuditPolicy" -Settings $settings -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status $moduleStatus
}

Export-ModuleMember -Function ConvertFrom-CSAAuditSetting, Get-CSAAuditPolicyEvidence
