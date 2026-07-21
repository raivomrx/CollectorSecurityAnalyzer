$collectorRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\collector\windows")).Path
$moduleRoot = Join-Path $collectorRoot "modules"
$manifestPath = Join-Path $collectorRoot "evidence-manifest.json"
$collectorScript = Join-Path $collectorRoot "Collect-CSAWindowsEvidence.ps1"

Describe "CSA Windows Collector source contract" {
    It "parses every PowerShell source file" {
        $parseFailures = @()
        foreach ($file in @(Get-ChildItem -LiteralPath $collectorRoot -Recurse -File | Where-Object { $_.Extension -in @('.ps1', '.psm1') })) {
            $tokens = $null
            $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
            $parseFailures += @($parseErrors)
        }
        $parseFailures.Count | Should Be 0
    }

    It "imports every collector module" {
        foreach ($module in @(Get-ChildItem -LiteralPath $moduleRoot -Filter *.psm1 -File)) {
            { Import-Module $module.FullName -Force -ErrorAction Stop } | Should Not Throw
        }
    }

    It "uses the standard result contract and rejects an empty success" {
        Import-Module (Join-Path $moduleRoot "General.psm1") -Force
        $result = New-CSAModuleResult -Module "Test"
        $result.Status | Should Be "NOT_AVAILABLE"
        $result.Settings.Count | Should Be 0
        $result.CollectedEvidenceCount | Should Be 0
        $result.Contains("DurationMilliseconds") | Should Be $true
    }

    It "preserves explicit ACCESS_DENIED and NOT_SUPPORTED states" {
        Import-Module (Join-Path $moduleRoot "General.psm1") -Force
        (New-CSAModuleResult -Module "Test" -Status "ACCESS_DENIED").Status | Should Be "ACCESS_DENIED"
        (New-CSAModuleResult -Module "Test" -Status "NOT_SUPPORTED").Status | Should Be "NOT_SUPPORTED"
    }

    It "uses atomic output and module-level error isolation" {
        $source = Get-Content -Raw -LiteralPath $collectorScript
        $source | Should Match '\$tmpPath'
        $source | Should Match 'Move-Item -LiteralPath \$tmpPath'
        $source | Should Match 'foreach \(\$moduleName in \$modules\)'
        $source | Should Match 'catch \[System\.UnauthorizedAccessException\]'
    }

    It "does not collect BitLocker secrets" {
        $source = Get-Content -Raw -LiteralPath (Join-Path $moduleRoot "BitLocker.psm1")
        $source | Should Not Match '\.RecoveryPassword'
        $source | Should Not Match 'KeyProtectorId'
    }

    It "redacts paths and identifiers in strict privacy mode" {
        Import-Module (Join-Path $moduleRoot "General.psm1") -Force
        (Protect-CSAPath 'C:\Users\Alice\Desktop\a.txt' 'Strict') | Should Be 'C:\Users\<USER>\Desktop\a.txt'
        (Protect-CSAIdentifier 'EXAMPLE\Alice' 'Strict') | Should Match '^id-[0-9a-f]{12}$'
    }

    It "validates the evidence manifest contract" {
        Import-Module (Join-Path $moduleRoot "General.psm1") -Force
        $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        (Test-CSAEvidenceManifest -Manifest $manifest -ModuleRoot $moduleRoot) | Should Be $true
    }

    It "does not hard-code expected evidence counts in collector modules" {
        foreach ($module in @(Get-ChildItem -LiteralPath $moduleRoot -Filter *.psm1 -File)) {
            (Get-Content -Raw -LiteralPath $module.FullName) | Should Not Match '-ExpectedEvidenceCount\s+\d+'
        }
    }

    It "parses documented English and Estonian audit policy states" {
        Import-Module (Join-Path $moduleRoot "AuditPolicy.psm1") -Force
        foreach ($fixtureName in @("audit_policy_en.json", "audit_policy_et.json")) {
            $fixturePath = Join-Path $PSScriptRoot "..\fixtures\$fixtureName"
            $fixture = Get-Content -Raw -Encoding UTF8 -LiteralPath $fixturePath | ConvertFrom-Json
            foreach ($case in @($fixture.cases)) {
                $actual = ConvertFrom-CSAAuditSetting ([string]$case.text)
                $actual.Success | Should Be ([bool]$case.success)
                $actual.Failure | Should Be ([bool]$case.failure)
            }
        }
        (ConvertFrom-CSAAuditSetting "Erfolg") | Should Be $null
    }
}
