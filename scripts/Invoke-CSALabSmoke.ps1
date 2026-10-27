param(
    [string]$Executable = (Join-Path $PSScriptRoot '../dist/CSA-Lab/CSA-Lab.exe'),
    [string]$OutputRoot = (Join-Path $PSScriptRoot '../test-artifacts/packaged-lab-smoke'),
    [string]$ExpectedVersion = '5.6.2'
)
$ErrorActionPreference = 'Stop'
$base = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $base -Force | Out-Null
$data = Join-Path $base ('isolated-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $data | Out-Null
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$arguments = '--no-browser --admin-port ' + $port + ' --data-root "' + (Join-Path $data 'assessments') + '"'
$child = Start-Process -FilePath ([IO.Path]::GetFullPath($Executable)) -ArgumentList $arguments -WindowStyle Hidden -PassThru
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($child.HasExited) { throw 'Packaged Lab exited before becoming ready.' }
        try {
            $response = Invoke-WebRequest -Uri ('http://127.0.0.1:' + $port + '/') -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch { Start-Sleep -Milliseconds 250 }
    }
    if (-not $ready) { throw 'Packaged Lab did not become ready.' }
    if (-not $response.Content.Contains('Collector ' + $ExpectedVersion)) { throw 'Packaged version mismatch.' }
    $state = Invoke-RestMethod -Uri ('http://127.0.0.1:' + $port + '/api/v1/assessments') -TimeoutSec 3
    if (@($state.assessments).Count -ne 0) { throw 'Smoke data root was not empty.' }
    @{version=$ExpectedVersion; localhostHtml=$true; assessmentApi=$true; isolatedData=$true; browserOpened=$false} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $base 'result.json') -Encoding utf8
    Write-Host "Packaged CSA Lab $ExpectedVersion HTML/API startup: PASS"
} finally {
    # Only terminate the process created by this smoke check.
    if (-not $child.HasExited) { Stop-Process -Id $child.Id -Force }
}
