[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath
)

$ErrorActionPreference = "Stop"
$inputData = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
$startedAt = [DateTimeOffset]::UtcNow
$status = "NOT_SUPPORTED"
$evidence = @()
$limitations = @()

try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $serviceRunning = [bool]$defender.AMServiceEnabled
    $engineOperational = [bool]$defender.AntivirusEnabled
    $realTimeEnabled = [bool]$defender.RealTimeProtectionEnabled
    $status = if ($serviceRunning -and $engineOperational -and $realTimeEnabled) {
        "PASSED"
    } else {
        "FAILED"
    }
    $evidence = @([ordered]@{
        evidenceType = "DEFENDER_RUNTIME_HEALTH"
        serviceRunning = $serviceRunning
        engineOperational = $engineOperational
        realTimeProtectionEnabled = $realTimeEnabled
        healthQuerySucceeded = $true
    })
}
catch {
    $limitations += "Defender status provider was unavailable."
}

$result = [ordered]@{
    schemaVersion = "1.0"
    runId = [string]$inputData.runId
    validatorId = [string]$inputData.validatorId
    status = $status
    startedAt = $startedAt.ToString("o")
    completedAt = [DateTimeOffset]::UtcNow.ToString("o")
    evidence = $evidence
    limitations = $limitations
    cleanup = [ordered]@{ required = $false; completed = $true }
}
[Console]::Out.Write(($result | ConvertTo-Json -Depth 6 -Compress))
