param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidateSet("Standard", "Strict")]
    [string]$PrivacyMode = "Strict",

    [ValidateSet("STANDARD_USER_COLLECTION", "ELEVATED_COLLECTION")]
    [string]$CollectionMode = "STANDARD_USER_COLLECTION",

    [string]$CapabilityRegistryPath,

    [string]$CollectionProfilePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$CapabilityRegistryPath = if ([string]::IsNullOrWhiteSpace($CapabilityRegistryPath)) {
    Join-Path $PSScriptRoot "collection-capabilities.json"
} else {
    $CapabilityRegistryPath
}
$CollectionProfilePath = if ([string]::IsNullOrWhiteSpace($CollectionProfilePath)) {
    Join-Path $PSScriptRoot "profiles\windows-standard-v1.json"
} else {
    $CollectionProfilePath
}
$collectorVersion = "CSA-WINDOWS-COLLECTOR-5.0.0"
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
if (-not (Test-Path -LiteralPath $CapabilityRegistryPath)) {
    throw "Collection capability registry was not found: $CapabilityRegistryPath"
}
if (-not (Test-Path -LiteralPath $CollectionProfilePath)) {
    throw "Collection profile was not found: $CollectionProfilePath"
}
$capabilityRegistry = Get-Content -Raw -LiteralPath $CapabilityRegistryPath | ConvertFrom-Json
$collectionProfile = Get-Content -Raw -LiteralPath $CollectionProfilePath | ConvertFrom-Json
$profileCapabilityIds = @($collectionProfile.capabilities | ForEach-Object { [string]$_ })
$selectedCapabilities = @(
    $capabilityRegistry.capabilities |
        Where-Object { $profileCapabilityIds -contains [string]$_.capabilityId }
)
if ($selectedCapabilities.Count -ne $profileCapabilityIds.Count) {
    throw "Collection profile references an unknown or duplicate capability."
}
$selectedModules = @($selectedCapabilities | ForEach-Object { [string]$_.module } | Select-Object -Unique)
$modules = @(
    $manifestDocument.modules |
        Where-Object { $selectedModules -contains [string]$_.module } |
        ForEach-Object { [string]$_.module }
)
foreach ($entry in @($manifestDocument.modules)) {
    $manifest[$entry.module] = $entry
}

function Get-CSACollectionPrivilegeContext {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $groupOutput = (& "$env:SystemRoot\System32\whoami.exe" /groups /fo csv /nh 2>$null) -join "`n"
    $isAdministratorMember = $groupOutput -match "S-1-5-32-544"
    $integrityLevel = "UNKNOWN"
    if ($groupOutput -match "S-1-16-16384") { $integrityLevel = "SYSTEM" }
    elseif ($groupOutput -match "S-1-16-12288") { $integrityLevel = "HIGH" }
    elseif ($groupOutput -match "S-1-16-(8192|8448)") { $integrityLevel = "MEDIUM" }
    elseif ($groupOutput -match "S-1-16-4096") { $integrityLevel = "LOW" }
    $executionMode = "UNKNOWN"
    if ($identity.User.Value -eq "S-1-5-18") { $executionMode = "SYSTEM" }
    elseif ($isElevated) { $executionMode = "ELEVATED_ADMINISTRATOR" }
    elseif ($isAdministratorMember) { $executionMode = "ADMIN_MEMBER_NOT_ELEVATED" }
    else { $executionMode = "STANDARD_USER" }
    return [ordered]@{
        executionMode = $executionMode
        isElevated = [bool]$isElevated
        isLocalAdministratorMember = [bool]$isAdministratorMember
        integrityLevel = $integrityLevel
        uacVirtualization = $null
        effectiveUserHash = Protect-CSAIdentifier $identity.Name "Strict"
        collectionScope = "CURRENT_USER_AND_PUBLIC_MACHINE_STATE"
    }
}

function ConvertTo-CSACapabilityStatus {
    param($Capability, $ModuleResult, $PrivilegeContext)

    if (
        [string]$Capability.minimumPrivilege -eq "ELEVATED_ADMINISTRATOR" -and
        -not [bool]$PrivilegeContext.isElevated
    ) {
        return "NOT_COLLECTED_PRIVILEGE_REQUIRED"
    }
    switch ([string]$ModuleResult.Status) {
        "SUCCESS" { return "COLLECTED" }
        "PARTIAL" { return "COLLECTED_PARTIAL" }
        "NOT_SUPPORTED" { return "NOT_SUPPORTED" }
        "ACCESS_DENIED" { return "NOT_COLLECTED_ACCESS_DENIED" }
        "NOT_AVAILABLE" { return "NOT_COLLECTED_ERROR" }
        default { return "NOT_COLLECTED_ERROR" }
    }
}

$privilegeContext = Get-CSACollectionPrivilegeContext

$securitySettings = New-Object System.Collections.Generic.List[object]
$updateSettings = New-Object System.Collections.Generic.List[object]
$softwareItems = New-Object System.Collections.Generic.List[object]
$services = New-Object System.Collections.Generic.List[object]
$scheduledTasks = New-Object System.Collections.Generic.List[object]
$certificateItems = New-Object System.Collections.Generic.List[object]
$errors = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[string]
$moduleResults = New-Object System.Collections.Generic.List[object]
$capabilityResults = New-Object System.Collections.Generic.List[object]
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
    $moduleCapabilities = @(
        $selectedCapabilities |
            Where-Object { [string]$_.module -eq $moduleName }
    )
    $elevatedCapabilityCount = @(
        $moduleCapabilities |
            Where-Object {
                [string]$_.minimumPrivilege -eq "ELEVATED_ADMINISTRATOR"
            }
    ).Count
    $skipForPrivilege = (
        -not [bool]$privilegeContext.isElevated -and
        $moduleCapabilities.Count -gt 0 -and
        $elevatedCapabilityCount -eq $moduleCapabilities.Count
    )
    if ($skipForPrivilege) {
        $result = New-CSAModuleResult `
            -Module $moduleName `
            -Warnings @(
                "Module was not invoked because every selected capability requires elevation."
            ) `
            -StartedAt $started `
            -Status "NOT_AVAILABLE"
    } else {
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
    foreach ($item in @($result.Certificates)) { $certificateItems.Add($item) }
    foreach ($item in @($result.Errors)) { $errors.Add($item) }
    foreach ($item in @($result.Warnings)) { $warnings.Add([string]$item) }
    foreach ($capability in $moduleCapabilities) {
        $capabilityResults.Add([ordered]@{
            capabilityId = [string]$capability.capabilityId
            status = ConvertTo-CSACapabilityStatus $capability $result $privilegeContext
            startedAt = [string]$result.StartedAt
            completedAt = [string]$result.CompletedAt
            evidenceCount = [int]$result.CollectedEvidenceCount
            expectedEvidenceCount = [int]$result.ExpectedEvidenceCount
            limitationCode = if (
                [string]$capability.minimumPrivilege -eq "ELEVATED_ADMINISTRATOR" -and
                -not [bool]$privilegeContext.isElevated
            ) { "PRIVILEGE_REQUIRED" } else { $null }
            safeMessage = if (
                [string]$capability.minimumPrivilege -eq "ELEVATED_ADMINISTRATOR" -and
                -not [bool]$privilegeContext.isElevated
            ) { "Capability requires an explicitly elevated collection run." } else { $null }
        })
    }
}

$completed = (Get-Date).ToUniversalTime()
$invocationCoverage = if ($modules.Count -gt 0) { [math]::Round(($moduleResults.Count / $modules.Count) * 100, 1) } else { 0.0 }
$successfulModulePercent = if ($modules.Count -gt 0) { [math]::Round(($statusCounts.SUCCESS / $modules.Count) * 100, 1) } else { 0.0 }
$evidenceCoverage = if ($expectedEvidenceUnits -gt 0) { [math]::Round(($collectedEvidenceUnits / $expectedEvidenceUnits) * 100, 1) } else { 0.0 }
$mandatoryCoverage = if ($expectedMandatoryUnits -gt 0) { [math]::Round(($collectedMandatoryUnits / $expectedMandatoryUnits) * 100, 1) } else { 0.0 }
$collectedEvidenceItems = $securitySettings.Count + $updateSettings.Count
$elevated = [bool]$privilegeContext.isElevated
$os = $null
$computer = $null
$bios = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { $warnings.Add("Operating system CIM evidence was unavailable; registry fallback was used.") }
try { $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { $warnings.Add("Computer system CIM evidence was unavailable; environment fallback was used.") }
try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop } catch { $warnings.Add("BIOS metadata was unavailable.") }
$windowsVersionPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$osName = if ($null -ne $os) { $os.Caption } else { Get-CSARegistryValue $windowsVersionPath "ProductName" "Windows" }
$osVersion = if ($null -ne $os) { $os.Version } else { Get-CSARegistryValue $windowsVersionPath "CurrentVersion" $null }
$osBuild = if ($null -ne $os) { $os.BuildNumber } else { Get-CSARegistryValue $windowsVersionPath "CurrentBuildNumber" $null }
$osArchitecture = if ($null -ne $os) { $os.OSArchitecture } else { $env:PROCESSOR_ARCHITECTURE }
$osEdition = if ($null -ne $os) { $os.OperatingSystemSKU } else { Get-CSARegistryValue $windowsVersionPath "EditionID" $null }
$deviceDomain = if ($null -ne $computer) { $computer.Domain } else { $env:USERDOMAIN }
$deviceWorkgroup = if ($null -ne $computer -and -not $computer.PartOfDomain) { $computer.Workgroup } else { $null }
$domainJoined = if ($null -ne $computer) { [bool]$computer.PartOfDomain } else { $null }
$entraJoined = $null
try {
    $dsregOutput = (& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>$null) -join "`n"
    if ($dsregOutput -match '(?im)^\s*AzureAdJoined\s*:\s*(YES|NO)\s*$') {
        $entraJoined = $Matches[1] -eq "YES"
    }
} catch {
    $warnings.Add("Entra join state was unavailable.")
}
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
    collectionMode = $CollectionMode
    collectionProfile = [string]$collectionProfile.profileId
    collectionProfileVersion = [string]$collectionProfile.version
    collectionId = [guid]::NewGuid().ToString()
    collectionStartedAt = $started.ToString("o")
    collectionCompletedAt = $completed.ToString("o")
    device = [ordered]@{
        hostname = $hostname
        domain = $deviceDomain
        workgroup = $deviceWorkgroup
        currentUser = $currentUser
        elevated = $elevated
        domainJoined = $domainJoined
        entraJoined = $entraJoined
    }
    operatingSystem = [ordered]@{
        name = $osName
        version = $osVersion
        build = $osBuild
        architecture = $osArchitecture
        edition = $osEdition
        installDate = if ($null -ne $os -and $null -ne $os.InstallDate) { $os.InstallDate.ToUniversalTime().ToString("o") } else { $null }
        lastBoot = if ($null -ne $os -and $null -ne $os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime().ToString("o") } else { $null }
        uptimeSeconds = if ($null -ne $os -and $null -ne $os.LastBootUpTime) { [math]::Max(0, [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds) } else { $null }
        timeZone = [System.TimeZoneInfo]::Local.Id
        collectedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    }
    hardware = [ordered]@{
        manufacturer = if ($null -ne $computer) { [string]$computer.Manufacturer } else { $null }
        model = if ($null -ne $computer) { [string]$computer.Model } else { $null }
        totalPhysicalMemoryBytes = if ($null -ne $computer) { [int64]$computer.TotalPhysicalMemory } else { $null }
        biosManufacturer = if ($null -ne $bios) { [string]$bios.Manufacturer } else { $null }
        biosVersion = if ($null -ne $bios) { [string]$bios.SMBIOSBIOSVersion } else { $null }
        biosReleaseDate = if ($null -ne $bios -and $null -ne $bios.ReleaseDate) { $bios.ReleaseDate.ToUniversalTime().ToString("o") } else { $null }
        virtualizationDetected = if ($null -ne $computer) {
            ([string]$computer.Manufacturer -match '(?i)vmware|xen|qemu|microsoft corporation') -or
            ([string]$computer.Model -match '(?i)virtual|kvm|vmware')
        } else { $null }
    }
    privilegeContext = $privilegeContext
    capabilityResults = $capabilityResults.ToArray()
    security = [ordered]@{ settings = $securitySettings.ToArray() }
    software = [ordered]@{ items = $softwareItems.ToArray() }
    updates = [ordered]@{ settings = $updateSettings.ToArray() }
    services = [ordered]@{
        services = $services.ToArray()
        scheduledTasks = $scheduledTasks.ToArray()
    }
    certificates = [ordered]@{
        items = $certificateItems.ToArray()
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
        activeValidation = $false
        privilegeEscalationAttempted = $false
        endpointChangesPerformed = @()
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
