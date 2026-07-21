param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidateSet("Standard", "Strict")]
    [string]$PrivacyMode = "Standard"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$collectorVersion = "CSA-WINDOWS-COLLECTOR-3.1.1"
$started = (Get-Date).ToUniversalTime()
$moduleRoot = Join-Path $PSScriptRoot "modules"
$manifestPath = Join-Path $PSScriptRoot "evidence-manifest.json"
$modules = @(
    "General",
    "Firewall",
    "Defender",
    "BitLocker",
    "Accounts",
    "Protocols",
    "AuditPolicy",
    "DeviceGuard",
    "Updates",
    "RemoteAccess",
    "Network",
    "PowerShell",
    "UAC"
)

Import-Module (Join-Path $moduleRoot "General.psm1") -Force
$manifest = @{}
if (Test-Path -LiteralPath $manifestPath) {
    foreach ($entry in @((Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json).modules)) {
        $manifest[$entry.module] = $entry
    }
}

$securitySettings = New-Object System.Collections.Generic.List[object]
$updateSettings = New-Object System.Collections.Generic.List[object]
$softwareItems = New-Object System.Collections.Generic.List[object]
$services = New-Object System.Collections.Generic.List[object]
$scheduledTasks = New-Object System.Collections.Generic.List[object]
$errors = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[string]
$moduleResults = New-Object System.Collections.Generic.List[object]
$expectedEvidence = 0
$collectedEvidence = 0
$statusCounts = @{
    SUCCESS = 0; PARTIAL = 0; FAILED = 0; NOT_SUPPORTED = 0
    ACCESS_DENIED = 0; NOT_AVAILABLE = 0
}

foreach ($moduleName in $modules) {
    $modulePath = Join-Path $moduleRoot "$moduleName.psm1"
    $result = $null
    try {
        Import-Module $modulePath -Force
        $functionName = "Get-CSA$moduleName`Evidence"
        if (-not (Get-Command $functionName -ErrorAction SilentlyContinue)) {
            throw "Module command $functionName was not found."
        }
        $result = & $functionName -PrivacyMode $PrivacyMode
        if ($null -eq $result -or -not $result.Contains("Status")) {
            throw "Module did not return the CSA result contract."
        }
    } catch [System.UnauthorizedAccessException] {
        $moduleError = New-CSACollectionError $moduleName "ACCESS_DENIED" "CSA-COLLECT-ACCESS-DENIED" $_.Exception.Message
        $result = New-CSAModuleResult -Module $moduleName -Errors @($moduleError) -StartedAt $started -Status "ACCESS_DENIED"
    } catch [System.NotSupportedException] {
        $moduleError = New-CSACollectionError $moduleName "NOT_SUPPORTED" "CSA-COLLECT-NOT-SUPPORTED" $_.Exception.Message
        $result = New-CSAModuleResult -Module $moduleName -Errors @($moduleError) -StartedAt $started -Status "NOT_SUPPORTED"
    } catch {
        $moduleError = New-CSACollectionError $moduleName "FAILED" "CSA-COLLECT-MODULE-FAILED" $_.Exception.Message
        $result = New-CSAModuleResult -Module $moduleName -Errors @($moduleError) -StartedAt $started -Status "FAILED"
    }

    $moduleResults.Add($result)
    $expectedEvidence += [int]$result.ExpectedEvidenceCount
    $collectedEvidence += [int]$result.CollectedEvidenceCount
    $moduleStatus = [string]$result.Status
    if (-not $statusCounts.ContainsKey($moduleStatus)) { $moduleStatus = "FAILED" }
    $statusCounts[$moduleStatus]++
    foreach ($item in @($result.Settings)) {
        if ($moduleName -eq "Updates") { $updateSettings.Add($item) } else { $securitySettings.Add($item) }
    }
    foreach ($item in @($result.SoftwareItems)) { $softwareItems.Add($item) }
    foreach ($item in @($result.Services)) { $services.Add($item) }
    foreach ($item in @($result.ScheduledTasks)) { $scheduledTasks.Add($item) }
    foreach ($item in @($result.Errors)) { $errors.Add($item) }
    foreach ($item in @($result.Warnings)) { $warnings.Add([string]$item) }
}

$completed = (Get-Date).ToUniversalTime()
$executed = $modules.Count - $statusCounts.FAILED
$executionCoverage = if ($modules.Count -gt 0) { [math]::Round(($executed / $modules.Count) * 100, 1) } else { 0.0 }
$collectedEvidence = $securitySettings.Count + $updateSettings.Count
$evidenceCoverage = if ($expectedEvidence -gt 0) { [math]::Round(([math]::Min($collectedEvidence, $expectedEvidence) / $expectedEvidence) * 100, 1) } else { 0.0 }

$applicableMandatory = 0
$collectedMandatory = 0
$allSettings = $securitySettings.ToArray() + $updateSettings.ToArray()
foreach ($moduleResult in $moduleResults) {
    if (-not $manifest.ContainsKey($moduleResult.Module)) { continue }
    if ($moduleResult.Status -eq "NOT_SUPPORTED") { continue }
    foreach ($settingId in @($manifest[$moduleResult.Module].mandatorySettingIds)) {
        $applicableMandatory++
        $matched = @($allSettings | Where-Object { $_.settingId -eq $settingId -and $_.collectionStatus -eq "SUCCESS" })
        if ($matched.Count -gt 0) { $collectedMandatory++ }
    }
}
$mandatoryCoverage = if ($applicableMandatory -gt 0) { [math]::Round(($collectedMandatory / $applicableMandatory) * 100, 1) } else { 0.0 }
$generalModulePath = Join-Path $moduleRoot "General.psm1"
Import-Module $generalModulePath -Force
$elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$os = $null
$computer = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { $warnings.Add("Operating system CIM evidence was unavailable; registry fallback was used.") }
try { $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { $warnings.Add("Computer system CIM evidence was unavailable; environment fallback was used.") }
$windowsVersionPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$osName = if ($null -ne $os) { $os.Caption } else { Get-CSARegistryValue $windowsVersionPath "ProductName" "Windows" }
$osVersion = if ($null -ne $os) { $os.Version } else { Get-CSARegistryValue $windowsVersionPath "CurrentVersion" $null }
$osBuild = if ($null -ne $os) { $os.BuildNumber } else { Get-CSARegistryValue $windowsVersionPath "CurrentBuildNumber" $null }
$osArchitecture = if ($null -ne $os) { $os.OSArchitecture } else { $env:PROCESSOR_ARCHITECTURE }
$osEdition = if ($null -ne $os) { $os.OperatingSystemSKU } else { Get-CSARegistryValue $windowsVersionPath "EditionID" $null }
$deviceDomain = if ($null -ne $computer) { $computer.Domain } else { $env:USERDOMAIN }
$deviceWorkgroup = if ($null -ne $computer -and -not $computer.PartOfDomain) { $computer.Workgroup } else { $null }
if ($PrivacyMode -eq "Strict") {
    $deviceDomain = Protect-CSAIdentifier $deviceDomain $PrivacyMode
    $deviceWorkgroup = Protect-CSAIdentifier $deviceWorkgroup $PrivacyMode
}
$hostname = if ($PrivacyMode -eq "Strict") { Protect-CSAIdentifier $env:COMPUTERNAME $PrivacyMode } else { $env:COMPUTERNAME }
$currentUser = if ($PrivacyMode -eq "Strict") { Protect-CSAIdentifier "$env:USERDOMAIN\$env:USERNAME" $PrivacyMode } else { "$env:USERDOMAIN\$env:USERNAME" }
$pendingRebootSetting = @($updateSettings | Where-Object { $_.settingId -eq "WINDOWS_UPDATE_PENDING_REBOOT" } | Select-Object -First 1)

$document = [ordered]@{
    schemaVersion = "2.0"
    collectorVersion = $collectorVersion
    collectionId = [guid]::NewGuid().ToString()
    collectionStartedAt = $started.ToString("o")
    collectionCompletedAt = $completed.ToString("o")
    device = [ordered]@{
        hostname = $hostname
        domain = $deviceDomain
        workgroup = $deviceWorkgroup
        currentUser = $currentUser
        elevated = $elevated
    }
    operatingSystem = [ordered]@{
        name = $osName
        version = $osVersion
        build = $osBuild
        architecture = $osArchitecture
        edition = $osEdition
    }
    security = [ordered]@{ settings = $securitySettings.ToArray() }
    software = [ordered]@{ items = $softwareItems.ToArray() }
    updates = [ordered]@{ settings = $updateSettings.ToArray() }
    services = [ordered]@{
        services = $services.ToArray()
        scheduledTasks = $scheduledTasks.ToArray()
    }
    collectionSummary = [ordered]@{
        totalCollectors = $modules.Count
        successfulCollectors = $statusCounts.SUCCESS
        partialCollectors = $statusCounts.PARTIAL
        failedCollectors = $statusCounts.FAILED + $statusCounts.NOT_AVAILABLE
        unsupportedCollectors = $statusCounts.NOT_SUPPORTED
        accessDeniedCollectors = $statusCounts.ACCESS_DENIED
        evidenceItems = $collectedEvidence
        moduleExecutionCoveragePercent = $executionCoverage
        evidenceCollectionCoveragePercent = $evidenceCoverage
        collectionCoveragePercent = $evidenceCoverage
        mandatoryCollectionCoveragePercent = $mandatoryCoverage
        mandatoryEvidenceApplicable = $applicableMandatory
        mandatoryEvidenceCollected = $collectedMandatory
        elevated = $elevated
        rebootPending = if ($pendingRebootSetting.Count -gt 0) { $pendingRebootSetting[0].effectiveValue } else { $null }
        warnings = $warnings.ToArray()
    }
    errors = $errors.ToArray()
    metadata = [ordered]@{
        privacyMode = $PrivacyMode
        readOnly = $true
        moduleResults = $moduleResults.ToArray()
    }
}

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutput)
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
$tmpPath = "$resolvedOutput.tmp"
$json = $document | ConvertTo-Json -Depth 12
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($tmpPath, $json, $utf8WithoutBom)
Move-Item -LiteralPath $tmpPath -Destination $resolvedOutput -Force
