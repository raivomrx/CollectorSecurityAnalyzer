param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../build/trusted-collector'))
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($output) | Out-Null
$compiler = "$env:SystemRoot/Microsoft.NET/Framework64/v4.0.30319/csc.exe"
$arguments = @('/nologo', '/optimize+', '/target:exe', '/platform:anycpu', '/main:CSA.Collector.TrustedEntry',
    "/out:$output/CSA-TrustedCollector.exe", '/reference:System.IO.Compression.dll',
    '/reference:System.IO.Compression.FileSystem.dll', '/reference:System.Web.Extensions.dll',
    '/reference:System.Security.dll', (Join-Path $root 'collector/bootstrapper/Program.cs'),
    (Join-Path $root 'collector/trusted/TrustProtocol.cs'), (Join-Path $root 'collector/trusted/TrustedEntry.cs'),
    (Join-Path $root 'collector/trusted/TrustedNetwork.cs'), (Join-Path $root 'collector/trusted/TrustInspection.cs'))
& $compiler $arguments
if ($LASTEXITCODE) { throw 'Trusted Collector build failed.' }
Copy-Item -LiteralPath (Join-Path $root 'collector/trusted/Start-CSATrustedCollector.ps1') -Destination $output
Write-Host 'Immutable trusted Collector built. UNSIGNED LAB ONLY until publisher signing and independent enrollment.'
