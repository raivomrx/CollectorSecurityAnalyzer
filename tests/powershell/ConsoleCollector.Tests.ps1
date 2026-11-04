BeforeAll {
    $collectorRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\collector\windows")).Path
    $runnerPath = Join-Path $collectorRoot "Invoke-CSACollector.ps1"
    $collectorPath = Join-Path $collectorRoot "Collect-CSAWindowsEvidence.ps1"
    $capabilityPath = Join-Path $collectorRoot "collection-capabilities.json"
    $profilePath = Join-Path $collectorRoot "profiles\windows-standard-v1.json"
    $privacyPath = Join-Path $collectorRoot "profiles\privacy-default.json"
}

Describe "CSA Sprint 5.0 standard-user Collector contract" {
    It "declares a unique capability registry" {
        $registry = Get-Content -Raw -LiteralPath $capabilityPath | ConvertFrom-Json
        $ids = @($registry.capabilities | ForEach-Object { [string]$_.capabilityId })
        $ids.Count | Should -BeGreaterOrEqual 16
        @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        foreach ($capability in @($registry.capabilities)) {
            [string]::IsNullOrWhiteSpace([string]$capability.name) | Should -BeFalse
            [string]::IsNullOrWhiteSpace([string]$capability.module) | Should -BeFalse
            [int]$capability.timeoutSeconds | Should -BeGreaterThan 0
            [string]$capability.minimumPrivilege | Should -BeIn @("STANDARD_USER", "ELEVATED_ADMINISTRATOR")
        }
    }

    It "uses STANDARD_USER_COLLECTION as the default profile" {
        $profile = Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json
        $profile.profileId | Should -Be "windows-standard-v1"
        $profile.collectorMode | Should -Be "STANDARD_USER_COLLECTION"
        @($profile.capabilities).Count | Should -BeGreaterOrEqual 16
        @($profile.capabilities | Select-Object -Unique).Count | Should -Be @($profile.capabilities).Count
    }

    It "uses privacy-preserving defaults" {
        $policy = Get-Content -Raw -LiteralPath $privacyPath | ConvertFrom-Json
        $policy.includeHostname | Should -BeFalse
        $policy.hashUsername | Should -BeTrue
        $policy.hashTenantId | Should -BeTrue
        $policy.includeIpAddresses | Should -BeFalse
        $policy.includeMacAddresses | Should -BeFalse
        $policy.includeBrowserExtensions | Should -BeFalse
        $policy.includeCertificateSubjects | Should -BeFalse
        $policy.includeLocalAdminNames | Should -BeFalse
        $policy.includeRawRegistryValues | Should -BeFalse
    }

    It "contains no privilege escalation or persistence mechanism" {
        $source = Get-Content -Raw -LiteralPath $runnerPath
        $source | Should -Not -Match '(?i)Start-Process\s+.*-Verb\s+RunAs'
        $source | Should -Not -Match '(?i)\bNew-Service\b'
        $source | Should -Not -Match '(?i)\bRegister-ScheduledTask\b'
        $source | Should -Not -Match '(?i)\bNew-NetFirewallRule\b'
        $source | Should -Not -Match '(?i)\bSet-ItemProperty\b'
        $source | Should -Match 'STANDARD_USER_COLLECTION refuses an elevated or SYSTEM process'
        $source | Should -Match 'requires a medium-integrity process'
    }

    It "requires HTTPS and certificate fingerprint pinning" {
        $source = Get-Content -Raw -LiteralPath $runnerPath
        $source | Should -Match 'SERVER_IDENTITY_VALIDATION_FAILED'
        $source | Should -Match 'ServerCertificateValidationCallback'
        $source | Should -Match 'GetNewClosure'
        $source | Should -Match 'GetRawCertData'
        $source | Should -Match 'serverCertificateFingerprint'
        $source | Should -Not -Match '(?i)-SkipCertificateCheck'
        $source | Should -Not -Match '(?i)http://'
    }

    It "keeps Active Validation outside standard collection" {
        $source = Get-Content -Raw -LiteralPath $runnerPath
        $source | Should -Match 'Active security testing: NO'
        $source | Should -Match 'Active validation is forbidden in standard collection'
        $source | Should -Not -Match 'Invoke-Responder'
        $source | Should -Not -Match 'Manage-ResponderFirewall'
    }

    It "uses unique restrictive temporary storage and cleanup" {
        $source = Get-Content -Raw -LiteralPath $runnerPath
        $source | Should -Match 'Join-Path \$env:TEMP "CSA"'
        $source | Should -Match '/inheritance:r'
        $source | Should -Match 'WindowsIdentity\]::GetCurrent\(\)\.User\.Value'
        $source | Should -Match '\*S-1-5-18:\(OI\)\(CI\)F'
        $source | Should -Match 'Remove-Item -LiteralPath \$temporaryDirectory -Recurse -Force'
        $source | Should -Match 'Local temporary data removed:'
    }

    It "does not use Win32_Product or collect prohibited credential stores" {
        $source = Get-Content -Raw -LiteralPath $collectorPath
        $moduleSource = @(
            Get-ChildItem -LiteralPath (Join-Path $collectorRoot "modules") -Filter *.psm1 -File |
                ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }
        ) -join "`n"
        ($source + $moduleSource) | Should -Not -Match '(?i)\bWin32_Product\b'
        ($source + $moduleSource) | Should -Not -Match '(?i)\b(mimikatz|sekurlsa|lsass\.dmp|ntds\.dit)\b'
        ($source + $moduleSource) | Should -Not -Match '(?i)Get-LsaSecret'
    }

    It "does not invoke elevated-only modules in a standard-user process" {
        $source = Get-Content -Raw -LiteralPath $collectorPath
        $source | Should -Match '\$skipForPrivilege'
        $source | Should -Match 'every selected capability requires elevation'
        $source | Should -Match 'NOT_COLLECTED_PRIVILEGE_REQUIRED'
    }
}

Describe 'CSA audit2 strict JSON decoding' {
    BeforeAll {
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw 'Collector runner has a syntax error.' }
        foreach ($name in 'ConvertFrom-CSAJsonText','Read-CSAJsonUtf8') {
            $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $false)
            . ([scriptblock]::Create($definition.Extent.Text))
        }
        Import-Module (Join-Path $collectorRoot 'modules/General.psm1') -Force
    }

    It 'preserves UTF-8 content with or without BOM in both Collector readers' {
        $expected = -join ([char[]](73,110,116,101,108,174,32,245,228,246,252,32,201,32,28450,23383))
        $path = Join-Path $TestDrive 'unicode.json'
        foreach ($bom in $false, $true) {
            $encoding = [Text.UTF8Encoding]::new($bom, $true)
            [IO.File]::WriteAllText($path, ('{"nested":{"name":"' + $expected + '"}}'), $encoding)
            (Read-CSAJsonUtf8 $path).nested.name | Should -BeExactly $expected
            (Read-CSACollectionJson $path).nested.name | Should -BeExactly $expected
        }
    }

    It 'rejects invalid UTF-8 and invalid JSON before returning any object' {
        $path = Join-Path $TestDrive 'invalid.json'
        [IO.File]::WriteAllBytes($path, [byte[]](123,34,120,34,58,34,195,40,34,125))
        { Read-CSAJsonUtf8 $path } | Should -Throw '*CSA-COL-INVALID-UTF8*'
        { Read-CSACollectionJson $path } | Should -Throw '*CSA-COL-INVALID-UTF8*'
        [IO.File]::WriteAllText($path, '{"broken":', [Text.UTF8Encoding]::new($false))
        { Read-CSAJsonUtf8 $path } | Should -Throw '*CSA-COL-INVALID-JSON*'
        { Read-CSACollectionJson $path } | Should -Throw '*CSA-COL-INVALID-JSON*'
    }
}
