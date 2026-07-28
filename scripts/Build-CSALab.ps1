param(
    [switch]$SkipInstaller,
    [switch]$SkipCollectorBuild,
    [string]$PythonExecutable = $env:CSA_PYTHON
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $PythonExecutable = (Get-Command python -ErrorAction Stop).Source
}
Push-Location $root
try {
    if (-not $SkipCollectorBuild) {
        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File (Join-Path $root "scripts\Build-CSACollector.ps1")
        if ($LASTEXITCODE -ne 0) { throw "Collector build failed." }
    }
    $collector = Join-Path $root "build\collector\CSA-Collector.exe"
    & powershell.exe `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File (Join-Path $root "scripts\Sign-CSAArtifacts.ps1") `
        -Paths $collector
    if ($LASTEXITCODE -ne 0) { throw "Collector signing stage failed." }

    & $PythonExecutable -m PyInstaller `
        --noconfirm `
        --clean `
        (Join-Path $root "packaging\csa-lab.spec")
    if ($LASTEXITCODE -ne 0) { throw "CSA Lab PyInstaller build failed." }

    $lab = Join-Path $root "dist\CSA-Lab\CSA-Lab.exe"
    if (-not (Test-Path -LiteralPath $lab -PathType Leaf)) {
        throw "CSA Lab executable was not produced."
    }
    Write-Host "CSA Lab executable: $lab"
    Write-Host "SHA-256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $lab).Hash.ToLowerInvariant())"
    & powershell.exe `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File (Join-Path $root "scripts\Sign-CSAArtifacts.ps1") `
        -Paths $lab
    if ($LASTEXITCODE -ne 0) { throw "CSA Lab signing stage failed." }

    if (-not $SkipInstaller) {
        $makensis = @(
            "$env:ProgramFiles(x86)\NSIS\makensis.exe",
            "$env:ProgramFiles\NSIS\makensis.exe"
        ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
        if (-not $makensis) {
            throw "NSIS is required to build CSA-Lab-Setup.exe."
        }
        [System.IO.Directory]::CreateDirectory(
            (Join-Path $root "dist\installer")
        ) | Out-Null
        & $makensis (Join-Path $root "packaging\CSA-Lab.nsi")
        if ($LASTEXITCODE -ne 0) { throw "CSA Lab installer build failed." }
        $installer = Join-Path $root "dist\installer\CSA-Lab-Setup.exe"
        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File (Join-Path $root "scripts\Sign-CSAArtifacts.ps1") `
            -Paths $installer
        if ($LASTEXITCODE -ne 0) { throw "Installer signing stage failed." }
        Write-Host "CSA Lab installer: $installer"
        Write-Host "SHA-256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant())"
    }
} finally {
    Pop-Location
}
