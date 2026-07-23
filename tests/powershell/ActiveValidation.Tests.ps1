Describe "Active validation PowerShell contract" {
    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
        $scriptBlockPath = Join-Path $repoRoot "active_validation\powershell\Validate-ScriptBlockLogging.ps1"
        $defenderPath = Join-Path $repoRoot "active_validation\powershell\Validate-DefenderRuntime.ps1"
        $firewallPath = Join-Path $repoRoot "active_validation\powershell\Manage-ResponderFirewall.ps1"
        $triggerPath = Join-Path $repoRoot "active_validation\powershell\Invoke-ResponderMarkerLookup.ps1"

        function Invoke-ValidationContract {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ScriptPath,
                [Parameter(Mandatory = $true)]
                [string]$InputPath
            )

            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = "powershell.exe"
            $startInfo.Arguments = (
                "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                "-File `"$ScriptPath`" -InputPath `"$InputPath`""
            )
            $startInfo.UseShellExecute = $false
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            $null = $process.Start()
            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()
            $process.WaitForExit()
            $result = [ordered]@{
                ExitCode = $process.ExitCode
                Stdout = $stdout
                Stderr = $stderr
            }
            $process.Dispose()
            return $result
        }
    }

    It "parses the reviewed self-hosted transport scripts" {
        foreach ($path in @($firewallPath, $triggerPath)) {
            $tokens = $null
            $errors = $null
            $null = [Management.Automation.Language.Parser]::ParseFile(
                $path,
                [ref]$tokens,
                [ref]$errors
            )
            $errors.Count | Should -Be 0
        }
    }

    It "scopes firewall rules to exact program port address and profile" {
        $content = Get-Content -LiteralPath $firewallPath -Raw
        $content | Should -Match "CSA-VALIDATION-"
        $content | Should -Match "-LocalPort"
        $content | Should -Match "-LocalAddress"
        $content | Should -Match "-RemoteAddress"
        $content | Should -Match "-InterfaceAlias"
        $content | Should -Match "-Profile"
        $content | Should -Match "-Program"
        $content | Should -Match "Remove-NetFirewallRule"
        $content | Should -Not -Match "Any|0\.0\.0\.0"
    }

    It "uses an exact marker and default credentials without retaining them" {
        $content = Get-Content -LiteralPath $triggerPath -Raw
        $content | Should -Match "CSA-RSP-"
        $content | Should -Match "LlmnrOnly"
        $content | Should -Match "UseDefaultCredentials"
        $content | Should -Match "Invoke-Command"
        $content | Should -Not -Match "password|hash cracking|relay"
    }

    It "uses only the reviewed transport command allowlist" {
        $allowedCommands = @(
            "Get-NetFirewallRule",
            "Get-NetIPAddress",
            "Invoke-Command",
            "Invoke-WebRequest",
            "New-NetFirewallRule",
            "Out-Null",
            "Remove-NetFirewallRule",
            "Resolve-DnsName"
        )
        foreach ($path in @($firewallPath, $triggerPath)) {
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile(
                $path,
                [ref]$tokens,
                [ref]$errors
            )
            $errors.Count | Should -Be 0
            $commands = $ast.FindAll(
                { param($node) $node -is [Management.Automation.Language.CommandAst] },
                $true
            )
            foreach ($command in $commands) {
                $commandName = $command.GetCommandName()
                if ($null -ne $commandName) {
                    $commandName | Should -BeIn $allowedCommands
                }
            }
        }
    }

    It "uses only the reviewed command allowlist" {
        $allowedCommands = @(
            "ConvertFrom-Json",
            "ConvertTo-Json",
            "Get-Content",
            "Get-MpComputerStatus",
            "Get-WinEvent",
            "Out-Null",
            "Start-Sleep"
        )
        foreach ($path in @($scriptBlockPath, $defenderPath)) {
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile(
                $path,
                [ref]$tokens,
                [ref]$errors
            )
            $errors.Count | Should -Be 0
            $commands = $ast.FindAll(
                { param($node) $node -is [Management.Automation.Language.CommandAst] },
                $true
            )
            foreach ($command in $commands) {
                $commandName = $command.GetCommandName()
                if ($null -ne $commandName) {
                    $commandName | Should -BeIn $allowedCommands
                }
            }
        }
    }

    It "uses one JSON-only stdout write per script" {
        foreach ($path in @($scriptBlockPath, $defenderPath)) {
            $content = Get-Content -LiteralPath $path -Raw
            ([regex]::Matches($content, "\[Console\]::Out\.Write").Count) | Should -Be 1
            $content | Should -Not -Match "Write-Host|Write-Output"
        }
    }

    It "bounds the marker event query and stores no plaintext marker" {
        $content = Get-Content -LiteralPath $scriptBlockPath -Raw
        $content | Should -Match "StartTime"
        $content | Should -Match "MaxEvents 100"
        $content | Should -Match "markerHash"
        $content | Should -Not -Match "ScriptBlockText"
    }

    It "returns a bounded Script Block Logging result" {
        $inputPath = Join-Path $TestDrive "scriptblock-input.json"
        @{
            schemaVersion = "1.0"
            runId = "PESTER-SCRIPTBLOCK"
            validatorId = "VAL-PS-SCRIPTBLOCK-001"
            timeoutSeconds = 20
            temporaryDirectory = $TestDrive
            policy = @{}
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $inputPath -Encoding UTF8

        $invocation = Invoke-ValidationContract -ScriptPath $scriptBlockPath -InputPath $inputPath
        $invocation.ExitCode | Should -Be 0
        $raw = $invocation.Stdout.Trim()
        { $raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        $result = $raw | ConvertFrom-Json
        $result.schemaVersion | Should -Be "1.0"
        $result.validatorId | Should -Be "VAL-PS-SCRIPTBLOCK-001"
        @("PASSED", "FAILED", "INCONCLUSIVE") | Should -Contain $result.status
        $result.evidence[0].markerHash | Should -Match "^[0-9a-f]{64}$"
        $raw | Should -Not -Match "CSA_VALIDATION_PESTER"
        $result.evidence[0].PSObject.Properties.Name | Should -Not -Contain "message"
        $result.evidence[0].PSObject.Properties.Name | Should -Not -Contain "scriptBlockText"
    }

    It "returns a bounded Defender runtime result" {
        $inputPath = Join-Path $TestDrive "defender-input.json"
        @{
            schemaVersion = "1.0"
            runId = "PESTER-DEFENDER"
            validatorId = "VAL-DEFENDER-RUNTIME-001"
            timeoutSeconds = 20
            temporaryDirectory = $TestDrive
            policy = @{}
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $inputPath -Encoding UTF8

        $invocation = Invoke-ValidationContract -ScriptPath $defenderPath -InputPath $inputPath
        $invocation.ExitCode | Should -Be 0
        $raw = $invocation.Stdout.Trim()
        { $raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        $result = $raw | ConvertFrom-Json
        $result.schemaVersion | Should -Be "1.0"
        $result.validatorId | Should -Be "VAL-DEFENDER-RUNTIME-001"
        @("PASSED", "FAILED", "NOT_SUPPORTED") | Should -Contain $result.status
        $result.PSObject.Properties.Name | Should -Not -Contain "rawEventData"
    }
}
