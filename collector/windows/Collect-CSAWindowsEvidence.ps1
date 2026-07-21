Set-StrictMode -Version 2.0

param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidateSet("Standard", "Strict")]
    [string]$PrivacyMode = "Standard"
)

$ErrorActionPreference = "Stop"
$collectorVersion = "CSA-WINDOWS-COLLECTOR-3.1"
$started = (Get-Date).ToUniversalTime()
$moduleRoot = Join-Path $PSScriptRoot "modules"
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
    "Network"
)

function New-CollectionError {
    param([string]$Module, [string]$Status, [string]$Code, [string]$Message)
    [ordered]@{
        module = $Module
        status = $Status
        errorCode = $Code
        message = $Message
    }
}

$settings = New-Object System.Collections.Generic.List[object]
$errors = New-Object System.Collections.Generic.List[object]
$success = 0
$failed = 0
$partial = 0
$unsupported = 0
$accessDenied = 0

foreach ($moduleName in $modules) {
    $modulePath = Join-Path $moduleRoot "$moduleName.psm1"
    try {
        Import-Module $modulePath -Force
        $functionName = "Get-CSA$moduleName`Evidence"
        if (Get-Command $functionName -ErrorAction SilentlyContinue) {
            $result = & $functionName -PrivacyMode $PrivacyMode
            foreach ($item in @($result.Settings)) {
                $settings.Add($item)
            }
            $success++
        } else {
            $partial++
            $errors.Add((New-CollectionError $moduleName "PARTIAL" "CSA-COLLECT-MODULE-MISSING" "Module command was not found."))
        }
    } catch [System.UnauthorizedAccessException] {
        $accessDenied++
        $errors.Add((New-CollectionError $moduleName "ACCESS_DENIED" "CSA-COLLECT-ACCESS-DENIED" $_.Exception.Message))
    } catch [System.NotSupportedException] {
        $unsupported++
        $errors.Add((New-CollectionError $moduleName "NOT_SUPPORTED" "CSA-COLLECT-NOT-SUPPORTED" $_.Exception.Message))
    } catch {
        $failed++
        $errors.Add((New-CollectionError $moduleName "FAILED" "CSA-COLLECT-MODULE-FAILED" $_.Exception.Message))
    }
}

$completed = (Get-Date).ToUniversalTime()
$coverage = if ($modules.Count -gt 0) { [math]::Round(($success / $modules.Count) * 100, 1) } else { 0 }
$document = [ordered]@{
    schemaVersion = "2.0"
    collectorVersion = $collectorVersion
    collectionId = [guid]::NewGuid().ToString()
    collectionStartedAt = $started.ToString("o")
    collectionCompletedAt = $completed.ToString("o")
    device = [ordered]@{
        hostname = $env:COMPUTERNAME
        domain = $env:USERDOMAIN
        currentUser = "$env:USERDOMAIN\$env:USERNAME"
        elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    operatingSystem = [ordered]@{
        name = (Get-CimInstance Win32_OperatingSystem).Caption
        version = (Get-CimInstance Win32_OperatingSystem).Version
        build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    }
    security = [ordered]@{
        settings = $settings
    }
    software = [ordered]@{
        items = @()
    }
    updates = [ordered]@{
        settings = @()
    }
    services = [ordered]@{
        services = @()
        scheduledTasks = @()
    }
    collectionSummary = [ordered]@{
        totalCollectors = $modules.Count
        successfulCollectors = $success
        partialCollectors = $partial
        failedCollectors = $failed
        unsupportedCollectors = $unsupported
        accessDeniedCollectors = $accessDenied
        evidenceItems = $settings.Count
        collectionCoveragePercent = $coverage
        mandatoryCollectionCoveragePercent = $coverage
        elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        rebootPending = $null
        warnings = @()
    }
    errors = $errors
    metadata = [ordered]@{
        privacyMode = $PrivacyMode
        readOnly = $true
    }
}

$tmpPath = "$OutputPath.tmp"
$document | ConvertTo-Json -Depth 8 | Set-Content -Path $tmpPath -Encoding UTF8
Move-Item -Path $tmpPath -Destination $OutputPath -Force
