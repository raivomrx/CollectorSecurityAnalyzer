[CmdletBinding()]
param(
    [ValidateRange(20, 50)]
    [int]$Iterations = 20,

    [string]$Python = "python",

    [string]$SummaryPath = "test-artifacts/active-validation/stress-summary.json"
)

$ErrorActionPreference = "Stop"
$summaryFile = [IO.Path]::GetFullPath($SummaryPath)
$summaryDirectory = Split-Path -Parent $summaryFile
New-Item -ItemType Directory -Path $summaryDirectory -Force | Out-Null
Remove-Item -LiteralPath $summaryFile -Force -ErrorAction SilentlyContinue

$baseline = @(
    Get-ChildItem `
        -LiteralPath ([IO.Path]::GetTempPath()) `
        -Directory `
        -Filter "CSA-VALIDATION-*" `
        -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
)
$runIds = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal
)
$startedAt = [DateTimeOffset]::UtcNow

for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
    $runId = [Guid]::NewGuid().ToString("N")
    if (-not $runIds.Add($runId)) {
        throw "Stress loop generated a duplicate run ID."
    }
    $env:CSA_STRESS_RUN_ID = $runId
    $arguments = @(
        "-W", "error::ResourceWarning",
        "-m", "unittest",
        "tests.test_active_validation",
        "tests.test_responder_exposure",
        "tests.test_responder_deep",
        "tests.test_live_responder_transport",
        "tests.test_html_report"
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Python
    $startInfo.Arguments = ($arguments | ForEach-Object {
        '"{0}"' -f $_.Replace('"', '\"')
    }) -join " "
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Unable to start the active validation stress process."
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
        $failurePath = Join-Path $summaryDirectory "stress-failure-$runId.txt"
        @($stdout, $stderr) |
            Set-Content -LiteralPath $failurePath -Encoding UTF8
        $process.Dispose()
        throw "Active validation stress iteration $iteration failed."
    }
    $process.Dispose()
    $current = @(
        Get-ChildItem `
            -LiteralPath ([IO.Path]::GetTempPath()) `
            -Directory `
            -Filter "CSA-VALIDATION-*" `
            -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName
    )
    $leaked = @($current | Where-Object { $_ -notin $baseline })
    if ($leaked.Count -gt 0) {
        throw "Worker temporary directory isolation failed."
    }
}
Remove-Item Env:\CSA_STRESS_RUN_ID -ErrorAction SilentlyContinue

$summary = [ordered]@{
    schemaVersion = "1.0"
    iterations = $Iterations
    uniqueRunIds = $runIds.Count
    failedIterations = 0
    temporaryDirectoryLeaks = 0
    startedAt = $startedAt.ToString("O")
    completedAt = [DateTimeOffset]::UtcNow.ToString("O")
}
$summary |
    ConvertTo-Json |
    Set-Content -LiteralPath $summaryFile -Encoding UTF8
Write-Output (
    "Active validation stress passed: {0}/{0}; unique run IDs: {1}" -f
    $Iterations,
    $runIds.Count
)
