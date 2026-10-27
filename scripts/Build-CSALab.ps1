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

    # Sign copies before trusted manifests are generated, never mutate source.
    $buildRoot = [IO.Path]::GetFullPath((Join-Path $root 'build'))
    $scriptStage = [IO.Path]::GetFullPath((Join-Path $buildRoot 'collector-scripts'))
    if (-not $scriptStage.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Collector script staging path is unsafe.'
    }
    if (Test-Path -LiteralPath $scriptStage) { Remove-Item -LiteralPath $scriptStage -Recurse -Force }
    Copy-Item -LiteralPath (Join-Path $root 'collector/windows') -Destination $scriptStage -Recurse
    $labScriptStage = [IO.Path]::GetFullPath((Join-Path $buildRoot 'lab-powershell'))
    if (-not $labScriptStage.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Lab script staging path is unsafe.'
    }
    if (Test-Path -LiteralPath $labScriptStage) { Remove-Item -LiteralPath $labScriptStage -Recurse -Force }
    Copy-Item -LiteralPath (Join-Path $root 'csa_lab/powershell') -Destination $labScriptStage -Recurse
    $scriptPaths = @(Get-ChildItem -LiteralPath $scriptStage,$labScriptStage -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1') } | ForEach-Object FullName)
    foreach ($scriptPath in $scriptPaths) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'scripts/Sign-CSAArtifacts.ps1') -Paths $scriptPath
        if ($LASTEXITCODE -ne 0) { throw 'Collector script signing failed.' }
    }
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $scriptStage 'Invoke-CSACollector.ps1')
    if ([string]$signature.Status -eq 'Valid') {
        @{ thumbprint = $signature.SignerCertificate.Thumbprint } | ConvertTo-Json -Compress |
            Set-Content -LiteralPath (Join-Path $scriptStage 'script-signing.json') -Encoding utf8
    }
    $previousSource = $env:CSA_COLLECTOR_SOURCE_DIR
    $previousLabScripts = $env:CSA_LAB_POWERSHELL_SOURCE_DIR
    $env:CSA_COLLECTOR_SOURCE_DIR = $scriptStage
    $env:CSA_LAB_POWERSHELL_SOURCE_DIR = $labScriptStage
    try { & $PythonExecutable -m PyInstaller `
        --noconfirm `
        --clean `
        (Join-Path $root "packaging\csa-lab.spec")
    } finally {
        $env:CSA_COLLECTOR_SOURCE_DIR = $previousSource
        $env:CSA_LAB_POWERSHELL_SOURCE_DIR = $previousLabScripts
    }
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
            "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
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
