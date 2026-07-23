[CmdletBinding()]
param(
    [string]$ResultsPath = "test-artifacts/active-validation-pester.xml",
    [string]$TestPath = "tests/powershell/ActiveValidation.Tests.ps1",
    [switch]$SkipResultFile
)

$ErrorActionPreference = "Stop"
Import-Module Pester -RequiredVersion 5.7.1 -Force
$startedAt = [DateTime]::UtcNow
$configuration = New-PesterConfiguration
$configuration.Run.Path = $TestPath
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = "Detailed"
if (-not $SkipResultFile) {
    $resolvedResultsPath = [IO.Path]::GetFullPath($ResultsPath)
    $resultsDirectory = Split-Path -Parent $resolvedResultsPath
    New-Item -ItemType Directory -Path $resultsDirectory -Force | Out-Null
    Remove-Item -LiteralPath $resolvedResultsPath -Force -ErrorAction SilentlyContinue
}
$result = Invoke-Pester -Configuration $configuration
if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0) {
    exit 1
}
if (-not $SkipResultFile) {
    $settings = [Xml.XmlWriterSettings]::new()
    $settings.Encoding = [Text.UTF8Encoding]::new($false)
    $settings.Indent = $true
    $writer = [Xml.XmlWriter]::Create($resolvedResultsPath, $settings)
    try {
        $writer.WriteStartDocument()
        $writer.WriteStartElement("testsuites")
        $writer.WriteAttributeString("name", "Pester")
        $writer.WriteAttributeString("tests", [string]$result.TotalCount)
        $writer.WriteAttributeString("failures", [string]$result.FailedCount)
        $writer.WriteAttributeString(
            "errors",
            [string]$result.FailedContainersCount
        )
        $writer.WriteAttributeString("skipped", [string]$result.SkippedCount)
        $writer.WriteStartElement("testsuite")
        $writer.WriteAttributeString("name", "PowerShell contract")
        $writer.WriteAttributeString("tests", [string]$result.TotalCount)
        $writer.WriteAttributeString("failures", [string]$result.FailedCount)
        $writer.WriteAttributeString(
            "errors",
            [string]$result.FailedContainersCount
        )
        $writer.WriteAttributeString("skipped", [string]$result.SkippedCount)
        foreach ($test in $result.Tests) {
            $writer.WriteStartElement("testcase")
            $writer.WriteAttributeString("classname", "Pester")
            $writer.WriteAttributeString("name", [string]$test.ExpandedName)
            $writer.WriteAttributeString(
                "time",
                $test.Duration.TotalSeconds.ToString(
                    "0.000000",
                    [Globalization.CultureInfo]::InvariantCulture
                )
            )
            if ($test.Result -eq "Skipped") {
                $writer.WriteStartElement("skipped")
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    }
    finally {
        $writer.Dispose()
    }
    $resultFile = Get-Item -LiteralPath $resolvedResultsPath -ErrorAction Stop
    if ($resultFile.LastWriteTimeUtc -lt $startedAt) {
        throw "Active validation Pester result XML is stale."
    }
    try {
        $null = [xml](Get-Content -LiteralPath $resolvedResultsPath -Raw)
    }
    catch {
        throw "Active validation Pester result XML is invalid."
    }
}
