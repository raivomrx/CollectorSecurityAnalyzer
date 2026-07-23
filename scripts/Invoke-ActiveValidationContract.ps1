[CmdletBinding()]
param(
    [string]$ResultsPath = "test-artifacts/active-validation-pester.xml",
    [string]$TestPath = "tests/powershell/ActiveValidation.Tests.ps1",
    [switch]$SkipResultFile
)

$ErrorActionPreference = "Stop"
Import-Module Pester -RequiredVersion 5.7.1 -Force
$configuration = New-PesterConfiguration
$configuration.Run.Path = $TestPath
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = "Detailed"
if (-not $SkipResultFile) {
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputFormat = "NUnitXml"
    $configuration.TestResult.OutputPath = $ResultsPath
}
$result = Invoke-Pester -Configuration $configuration
if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0) {
    exit 1
}
if (-not $SkipResultFile -and -not (Test-Path -LiteralPath $ResultsPath)) {
    throw "Active validation Pester result XML was not created."
}
