param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\build\collector")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$source = Join-Path $root "collector\bootstrapper\Program.cs"
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($output) | Out-Null
$target = Join-Path $output "CSA-Collector.exe"
$compiler = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw "The .NET Framework C# compiler is unavailable."
}

& $compiler `
    /nologo `
    /optimize+ `
    /target:exe `
    /platform:anycpu `
    "/out:$target" `
    /reference:System.IO.Compression.dll `
    /reference:System.IO.Compression.FileSystem.dll `
    /reference:System.Web.Extensions.dll `
    $source

if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target)) {
    throw "CSA Collector bootstrapper build failed."
}

$digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant()
Write-Host "CSA Collector bootstrapper: $target"
Write-Host "SHA-256: $digest"
