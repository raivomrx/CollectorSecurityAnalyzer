param(
    [string]$Path = "tests/powershell",
    [string]$ResultPath = "test-artifacts/pester-results.xml"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
Import-Module Pester -RequiredVersion 5.7.1 -Force
$resultDirectory = Split-Path -Parent $ResultPath
if (-not [string]::IsNullOrWhiteSpace($resultDirectory)) {
    New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
}
$configuration = New-PesterConfiguration
$configuration.Run.Path = $Path
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = "Detailed"
$configuration.TestResult.Enabled = $false
$result = Invoke-Pester -Configuration $configuration
if ($null -eq $result) {
    throw "Pester did not return a test result."
}

$settings = New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.Encoding = New-Object System.Text.UTF8Encoding($false)
$writer = [System.Xml.XmlWriter]::Create(
    [System.IO.Path]::GetFullPath($ResultPath),
    $settings
)
try {
    $writer.WriteStartDocument()
    $writer.WriteStartElement("testsuites")
    $writer.WriteAttributeString("tests", [string]$result.TotalCount)
    $writer.WriteAttributeString("failures", [string]$result.FailedCount)
    $writer.WriteAttributeString("skipped", [string]$result.SkippedCount)
    $writer.WriteStartElement("testsuite")
    $writer.WriteAttributeString("name", "CSA PowerShell")
    $writer.WriteAttributeString("tests", [string]$result.TotalCount)
    $writer.WriteAttributeString("failures", [string]$result.FailedCount)
    $writer.WriteAttributeString("skipped", [string]$result.SkippedCount)
    foreach ($test in @($result.Tests)) {
        $writer.WriteStartElement("testcase")
        $writer.WriteAttributeString("classname", [string]($test.Path -join "."))
        $writer.WriteAttributeString("name", [string]$test.ExpandedName)
        $writer.WriteAttributeString(
            "time",
            [string][math]::Round($test.Duration.TotalSeconds, 6)
        )
        if ([string]$test.Result -eq "Failed") {
            $writer.WriteStartElement("failure")
            $message = if ($null -ne $test.ErrorRecord) {
                [string]$test.ErrorRecord.Exception.Message
            } else {
                "Pester assertion failed."
            }
            $writer.WriteAttributeString("message", $message)
            $writer.WriteEndElement()
        } elseif ([string]$test.Result -eq "Skipped") {
            $writer.WriteStartElement("skipped")
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
    }
    $writer.WriteEndElement()
    $writer.WriteEndElement()
    $writer.WriteEndDocument()
} finally {
    $writer.Dispose()
}
if ($result.FailedCount -gt 0) {
    exit 1
}
if (-not (Test-Path -LiteralPath $ResultPath)) {
    throw "Pester result XML was not created."
}
Write-Output "Passed=$($result.PassedCount) Failed=$($result.FailedCount) Skipped=$($result.SkippedCount)"
