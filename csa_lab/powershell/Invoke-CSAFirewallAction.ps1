param(
    [Parameter(Mandatory = $true)]
    [string]$RequestPath,

    [Parameter(Mandatory = $true)]
    [string]$ResultPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

Import-Module (
    Join-Path $PSScriptRoot "FirewallArguments.psm1"
) -Force

try {
    $text = [Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($RequestPath)).TrimStart([char]0xfeff)
    $request = ConvertFrom-Json -InputObject $text -ErrorAction Stop
} catch { throw 'CSA-FIREWALL-INVALID-JSON: Request must be a valid UTF-8 JSON object.' }
$allowed = @("advfirewall", "firewall")
$arguments = @($request.arguments | ForEach-Object { [string]$_ })

if (
    [string]$request.executable -ne "$env:SystemRoot\System32\netsh.exe" -or
    $arguments.Count -lt 5 -or
    $arguments[0] -ne $allowed[0] -or
    $arguments[1] -ne $allowed[1] -or
    $arguments[2] -notin @("add", "delete") -or
    $arguments[3] -ne "rule" -or
    $arguments[4] -notlike "name=CSA Lab Temporary *"
) {
    throw "CSA firewall helper rejected an unscoped request."
}

$argumentLine = Join-CSAProcessArguments -Values $arguments
$process = Start-Process `
    -FilePath ([string]$request.executable) `
    -ArgumentList $argumentLine `
    -Verb RunAs `
    -Wait `
    -PassThru `
    -WindowStyle Hidden

@{ exitCode = [int]$process.ExitCode } |
    ConvertTo-Json -Compress |
    Set-Content -LiteralPath $ResultPath -Encoding UTF8
