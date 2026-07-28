param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if (-not $env:CSA_SIGNING_CERTIFICATE_BASE64 -or -not $env:CSA_SIGNING_CERTIFICATE_PASSWORD) {
    Write-Host "Signing secrets are unavailable; unsigned CI artifacts retained."
    exit 0
}

$signtool = Get-ChildItem `
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
    -Filter signtool.exe `
    -Recurse `
    -ErrorAction Stop |
    Where-Object { $_.FullName -like "*\x64\signtool.exe" } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signtool) { throw "signtool.exe was not found." }

$certificate = Join-Path $env:RUNNER_TEMP "csa-signing.pfx"
try {
    [IO.File]::WriteAllBytes(
        $certificate,
        [Convert]::FromBase64String($env:CSA_SIGNING_CERTIFICATE_BASE64)
    )
    foreach ($path in $Paths) {
        & $signtool.FullName sign `
            /fd SHA256 `
            /td SHA256 `
            /tr "http://timestamp.digicert.com" `
            /f $certificate `
            /p $env:CSA_SIGNING_CERTIFICATE_PASSWORD `
            $path
        if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $path" }
    }
} finally {
    Remove-Item -LiteralPath $certificate -Force -ErrorAction SilentlyContinue
}
