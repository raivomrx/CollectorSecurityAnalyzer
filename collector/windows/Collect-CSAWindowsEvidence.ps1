param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidateSet("Standard", "Strict")]
    [string]$PrivacyMode = "Standard"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$collectorVersion = "CSA-WINDOWS-COLLECTOR-3.1.2"
$started = (Get-Date).ToUniversalTime()
$moduleRoot = Join-Path $PSScriptRoot "modules"
$manifestPath = Join-Path $PSScriptRoot "evidence-manifest.json"
Import-Module (Join-Path $moduleRoot "General.psm1") -Force
$manifest = @{}
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Evidence manifest was not found: $manifestPath"
}
$manifestDocument = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
Test-CSAEvidenceManifest -Manifest $manifestDocument -ModuleRoot $moduleRoot | Out-Null
$modules = @($manifestDocument.modules | ForEach-Object { [string]$_.module })
foreach ($entry in @($manifestDocument.modules)) {
    $manifest[$entry.module] = $entry
}

$securitySettings = New-Object System.Collections.Generic.List[object]
$updateSettings = New-Object System.Collections.Generic.List[object]
$softwareItems = New-Object System.Collections.Generic.List[object]
$services = New-Object System.Collections.Generic.List[object]
$scheduledTasks = New-Object System.Collections.Generic.List[object]
$errors = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[string]
$moduleResults = New-Object System.Collections.Generic.List[object]
$expectedEvidenceUnits = 0
$collectedEvidenceUnits = 0
$expectedMandatoryUnits = 0
$collectedMandatoryUnits = 0
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

    if ($manifest.ContainsKey($moduleName)) {
        $result = Resolve-CSAModuleEvidence -Result $result -ManifestModule $manifest[$moduleName]
    }
    $moduleResults.Add($result)
    if ([string]$result.Status -ne "NOT_SUPPORTED") {
        $expectedEvidenceUnits += [int]$result.ExpectedEvidenceCount
        $collectedEvidenceUnits += [int]$result.CollectedEvidenceCount
        $expectedMandatoryUnits += [int]$result.ExpectedMandatoryEvidenceCount
        $collectedMandatoryUnits += [int]$result.CollectedMandatoryEvidenceCount
    }
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
$invocationCoverage = if ($modules.Count -gt 0) { [math]::Round(($moduleResults.Count / $modules.Count) * 100, 1) } else { 0.0 }
$successfulModulePercent = if ($modules.Count -gt 0) { [math]::Round(($statusCounts.SUCCESS / $modules.Count) * 100, 1) } else { 0.0 }
$evidenceCoverage = if ($expectedEvidenceUnits -gt 0) { [math]::Round(($collectedEvidenceUnits / $expectedEvidenceUnits) * 100, 1) } else { 0.0 }
$mandatoryCoverage = if ($expectedMandatoryUnits -gt 0) { [math]::Round(($collectedMandatoryUnits / $expectedMandatoryUnits) * 100, 1) } else { 0.0 }
$collectedEvidenceItems = $securitySettings.Count + $updateSettings.Count
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
        evidenceItems = $collectedEvidenceItems
        moduleInvocationCoveragePercent = $invocationCoverage
        successfulModulePercent = $successfulModulePercent
        evidenceUnitCoveragePercent = $evidenceCoverage
        mandatoryEvidenceCoveragePercent = $mandatoryCoverage
        moduleExecutionCoveragePercent = $invocationCoverage
        evidenceCollectionCoveragePercent = $evidenceCoverage
        collectionCoveragePercent = $evidenceCoverage
        mandatoryCollectionCoveragePercent = $mandatoryCoverage
        evidenceUnitsApplicable = $expectedEvidenceUnits
        evidenceUnitsCollected = $collectedEvidenceUnits
        mandatoryEvidenceApplicable = $expectedMandatoryUnits
        mandatoryEvidenceCollected = $collectedMandatoryUnits
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
