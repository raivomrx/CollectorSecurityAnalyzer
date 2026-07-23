[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath
)

$ErrorActionPreference = "Stop"
$inputData = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
$startedAt = [DateTimeOffset]::UtcNow
$marker = "CSA_VALIDATION_$($inputData.runId)"
$markerBytes = [Text.Encoding]::UTF8.GetBytes($marker)
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $markerHash = ([BitConverter]::ToString(
        $sha256.ComputeHash($markerBytes)
    ) -replace "-", "").ToLowerInvariant()
}
finally {
    $sha256.Dispose()
}
$status = "INCONCLUSIVE"
$eventFound = $false
$eventTimestamp = $null
$limitations = @()

try {
    & ([ScriptBlock]::Create("'$marker' | Out-Null"))
    Start-Sleep -Milliseconds 300
    $events = Get-WinEvent -MaxEvents 100 -FilterHashtable @{
        LogName = "Microsoft-Windows-PowerShell/Operational"
        Id = 4104
        StartTime = $startedAt.UtcDateTime.AddSeconds(-1)
    } -ErrorAction Stop
    foreach ($event in $events) {
        if ($event.Message -like "*$marker*") {
            $eventFound = $true
            $eventTimestamp = $event.TimeCreated.ToUniversalTime().ToString("o")
            break
        }
    }
    $status = if ($eventFound) { "PASSED" } else { "FAILED" }
}
catch {
    $limitations += "Operational event log could not be reliably evaluated."
}

$result = [ordered]@{
    schemaVersion = "1.0"
    runId = [string]$inputData.runId
    validatorId = [string]$inputData.validatorId
    status = $status
    startedAt = $startedAt.ToString("o")
    completedAt = [DateTimeOffset]::UtcNow.ToString("o")
    evidence = @([ordered]@{
        evidenceType = "POWERSHELL_EVENT"
        eventLog = "Microsoft-Windows-PowerShell/Operational"
        eventId = 4104
        markerHash = $markerHash
        eventFound = $eventFound
        eventTimestamp = $eventTimestamp
    })
    limitations = $limitations
    cleanup = [ordered]@{ required = $false; completed = $true }
}
[Console]::Out.Write(($result | ConvertTo-Json -Depth 6 -Compress))
