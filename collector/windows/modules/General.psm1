Set-StrictMode -Version 2.0

function New-CSASetting {
    param(
        [Parameter(Mandatory = $true)][string]$SettingId,
        [Parameter(Mandatory = $true)][string]$Category,
        $Value,
        [string]$Source = "UNKNOWN",
        [string]$Status = "SUCCESS",
        [int]$Confidence = 90,
        [string]$Provider = "",
        [string]$SourcePath = $null,
        [string]$ErrorCode = $null,
        [string]$ErrorMessage = $null,
        $ConfiguredValue = $null,
        [hashtable]$Metadata = @{}
    )

    if (-not $PSBoundParameters.ContainsKey("ConfiguredValue")) {
        $ConfiguredValue = $Value
    }
    [ordered]@{
        settingId = $SettingId
        category = $Category
        configuredValue = $ConfiguredValue
        effectiveValue = $Value
        source = $Source
        collectionStatus = $Status
        confidence = $Confidence
        collectedAt = (Get-Date).ToUniversalTime().ToString("o")
        provider = $Provider
        sourcePath = $SourcePath
        errorCode = $ErrorCode
        errorMessage = $ErrorMessage
        metadata = $Metadata
    }
}

function New-CSACollectionError {
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message
    )

    [ordered]@{
        module = $Module
        status = $Status
        errorCode = $Code
        message = $Message
    }
}

function New-CSAModuleResult {
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [object[]]$Settings = @(),
        [object[]]$Errors = @(),
        [string[]]$Warnings = @(),
        [int]$ExpectedEvidenceCount = 0,
        [datetime]$StartedAt = (Get-Date).ToUniversalTime(),
        [string]$Status = "",
        [object[]]$SoftwareItems = @(),
        [object[]]$Services = @(),
        [object[]]$ScheduledTasks = @()
    )

    $completedAt = (Get-Date).ToUniversalTime()
    $collectedCount = @($Settings).Count + @($SoftwareItems).Count + @($Services).Count + @($ScheduledTasks).Count
    if ([string]::IsNullOrWhiteSpace($Status)) {
        if (@($Errors).Count -gt 0 -and $collectedCount -eq 0) {
            $Status = "FAILED"
        } elseif ($ExpectedEvidenceCount -gt 0 -and $collectedCount -eq 0) {
            $Status = "NOT_AVAILABLE"
        } elseif (@($Errors).Count -gt 0 -or ($ExpectedEvidenceCount -gt 0 -and $collectedCount -lt $ExpectedEvidenceCount)) {
            $Status = "PARTIAL"
        } else {
            $Status = "SUCCESS"
        }
    }

    [ordered]@{
        Module = $Module
        Status = $Status
        Settings = @($Settings)
        Errors = @($Errors)
        Warnings = @($Warnings)
        ExpectedEvidenceCount = $ExpectedEvidenceCount
        CollectedEvidenceCount = $collectedCount
        StartedAt = $StartedAt.ToString("o")
        CompletedAt = $completedAt.ToString("o")
        DurationMilliseconds = [math]::Round(($completedAt - $StartedAt).TotalMilliseconds, 1)
        SoftwareItems = @($SoftwareItems)
        Services = @($Services)
        ScheduledTasks = @($ScheduledTasks)
    }
}

function Get-CSARegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        $DefaultValue = $null
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $DefaultValue
    }
}

function Resolve-CSAExceptionStatus {
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    $category = [string]$ErrorRecord.CategoryInfo.Category
    if ($message -match '(?i)access denied|requires elevation|unauthorized|privilege|0x80070005|0x80041003|0x00000522' -or $category -eq "PermissionDenied") {
        return "ACCESS_DENIED"
    }
    if ($message -match '(?i)not supported|not implemented|is unavailable') {
        return "NOT_SUPPORTED"
    }
    return "FAILED"
}

function Protect-CSAIdentifier {
    param($Value, [string]$PrivacyMode = "Standard")

    if ($null -eq $Value -or $PrivacyMode -ne "Strict") {
        return $Value
    }
    $text = [string]$Value
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        $hash = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").Substring(0, 12).ToLowerInvariant()
        return "id-$hash"
    } finally {
        $sha.Dispose()
    }
}

function Protect-CSAPath {
    param($Value, [string]$PrivacyMode = "Standard")

    if ($null -eq $Value) {
        return $null
    }
    $text = [string]$Value
    $text = [regex]::Replace($text, 'C:\\Users\\[^\\]+', 'C:\Users\<USER>', 'IgnoreCase')
    if ($PrivacyMode -eq "Strict") {
        $text = [regex]::Replace($text, '\b(\d{1,3}\.){3}\d{1,3}\b', '<IP>')
    }
    return $text
}

function Get-CSAGeneralEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $softwareItems = @()
    $services = @()
    $scheduledTasks = @()
    $errors = @()
    $warnings = @()

    try {
        $uninstallRoots = @(
            @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Architecture = 'x64' },
            @{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Architecture = 'x86' }
        )
        foreach ($root in $uninstallRoots) {
            foreach ($item in @(Get-ItemProperty -Path $root.Path -ErrorAction SilentlyContinue)) {
                if ([string]::IsNullOrWhiteSpace([string]$item.DisplayName)) { continue }
                $softwareItems += [ordered]@{
                    Vendor = if ($item.PSObject.Properties.Name -contains "Publisher") { [string]$item.Publisher } else { "" }
                    Product = [string]$item.DisplayName
                    Version = if ($item.PSObject.Properties.Name -contains "DisplayVersion") { [string]$item.DisplayVersion } else { "" }
                    Architecture = $root.Architecture
                    InstallDate = if ($item.PSObject.Properties.Name -contains "InstallDate") { [string]$item.InstallDate } else { $null }
                }
            }
        }
    } catch {
        $errors += New-CSACollectionError "General" (Resolve-CSAExceptionStatus $_) "CSA-COLLECT-SOFTWARE" $_.Exception.Message
    }

    try {
        foreach ($service in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
            $services += [ordered]@{
                Name = $service.Name
                DisplayName = $service.DisplayName
                StartType = $service.StartMode
                CurrentState = $service.State
                BinaryPath = Protect-CSAPath $service.PathName $PrivacyMode
                ServiceAccount = Protect-CSAIdentifier $service.StartName $PrivacyMode
                VendorClassification = if ([string]$service.PathName -match '(?i)\\Windows\\|Microsoft') { 'MICROSOFT' } else { 'THIRD_PARTY_OR_UNKNOWN' }
            }
        }
    } catch {
        $errors += New-CSACollectionError "General" (Resolve-CSAExceptionStatus $_) "CSA-COLLECT-SERVICES" $_.Exception.Message
    }

    try {
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
                $action = @($task.Actions | Select-Object -First 1)
                $principal = $task.Principal
                $scheduledTasks += [ordered]@{
                    TaskPath = $task.TaskPath
                    TaskName = $task.TaskName
                    State = [string]$task.State
                    Principal = Protect-CSAIdentifier $principal.UserId $PrivacyMode
                    RunLevel = [string]$principal.RunLevel
                    Executable = if ($action.Count -gt 0) { Protect-CSAPath $action[0].Execute $PrivacyMode } else { $null }
                    TriggerSummary = (@($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', ')
                    VendorClassification = if ($task.TaskPath -like '\Microsoft\*') { 'MICROSOFT' } else { 'THIRD_PARTY_OR_UNKNOWN' }
                }
            }
        } else {
            $warnings += "Scheduled task cmdlets are not available."
        }
    } catch {
        $errors += New-CSACollectionError "General" (Resolve-CSAExceptionStatus $_) "CSA-COLLECT-SCHEDULED-TASKS" $_.Exception.Message
    }

    $status = if (@($errors).Count -gt 0) { "PARTIAL" } else { "SUCCESS" }
    New-CSAModuleResult -Module "General" -Errors $errors -Warnings $warnings -ExpectedEvidenceCount 0 -StartedAt $startedAt -Status $status -SoftwareItems $softwareItems -Services $services -ScheduledTasks $scheduledTasks
}

Export-ModuleMember -Function New-CSASetting, New-CSACollectionError, New-CSAModuleResult, Get-CSARegistryValue, Resolve-CSAExceptionStatus, Protect-CSAIdentifier, Protect-CSAPath, Get-CSAGeneralEvidence
