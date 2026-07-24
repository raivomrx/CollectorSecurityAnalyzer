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
        [datetime]$StartedAt = (Get-Date).ToUniversalTime(),
        [string]$Status = "",
        [object[]]$SoftwareItems = @(),
        [object[]]$Services = @(),
        [object[]]$ScheduledTasks = @(),
        [object[]]$Certificates = @()
    )

    $completedAt = (Get-Date).ToUniversalTime()
    $collectedCount = @($Settings).Count + @($SoftwareItems).Count +
        @($Services).Count + @($ScheduledTasks).Count + @($Certificates).Count
    if ([string]::IsNullOrWhiteSpace($Status)) {
        if (@($Errors).Count -gt 0 -and $collectedCount -eq 0) {
            $Status = "FAILED"
        } elseif ($collectedCount -eq 0) {
            $Status = "NOT_AVAILABLE"
        } elseif (@($Errors).Count -gt 0) {
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
        ExpectedEvidenceCount = 0
        CollectedEvidenceCount = $collectedCount
        RawEvidenceItemCount = $collectedCount
        ExpectedMandatoryEvidenceCount = 0
        CollectedMandatoryEvidenceCount = 0
        EvidenceUnitResults = @()
        StartedAt = $StartedAt.ToString("o")
        CompletedAt = $completedAt.ToString("o")
        DurationMilliseconds = [math]::Round(($completedAt - $StartedAt).TotalMilliseconds, 1)
        SoftwareItems = @($SoftwareItems)
        Services = @($Services)
        ScheduledTasks = @($ScheduledTasks)
        Certificates = @($Certificates)
    }
}

function Test-CSASettingMatchesManifestEntry {
    param(
        [Parameter(Mandatory = $true)][string]$SettingId,
        [Parameter(Mandatory = $true)]$Entry
    )

    switch ([string]$Entry.matchType) {
        "LITERAL" { return $SettingId -eq [string]$Entry.id }
        "WILDCARD" {
            $pattern = New-Object System.Management.Automation.WildcardPattern(
                [string]$Entry.id,
                [System.Management.Automation.WildcardOptions]::IgnoreCase
            )
            return $pattern.IsMatch($SettingId)
        }
        "REGEX" { return [regex]::IsMatch($SettingId, [string]$Entry.id) }
        default { return $false }
    }
}

function Get-CSASettingInstanceKey {
    param(
        [Parameter(Mandatory = $true)]$Setting,
        [Parameter(Mandatory = $true)]$Entry
    )

    if ([string]$Entry.cardinality -eq "SINGLE") { return "SINGLE" }
    $metadataField = ""
    if ($Entry.PSObject.Properties.Name -contains "instanceMetadataField") {
        $metadataField = [string]$Entry.instanceMetadataField
    }
    if (-not [string]::IsNullOrWhiteSpace($metadataField) -and $null -ne $Setting.metadata) {
        $value = $null
        if ($Setting.metadata -is [System.Collections.IDictionary]) {
            $value = $Setting.metadata[$metadataField]
        } elseif ($Setting.metadata.PSObject.Properties.Name -contains $metadataField) {
            $value = $Setting.metadata.$metadataField
        }
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            return ([string]$value).TrimEnd(':', '\').ToUpperInvariant()
        }
    }
    if ([string]$Entry.matchType -eq "WILDCARD") {
        $expression = "^" + [regex]::Escape([string]$Entry.id).Replace("\*", "(?<instance>.+?)") + "$"
        $match = [regex]::Match([string]$Setting.settingId, $expression, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($match.Success) { return $match.Groups["instance"].Value.ToUpperInvariant() }
    }
    return $null
}

function Resolve-CSAModuleEvidence {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Result,
        [Parameter(Mandatory = $true)]$ManifestModule
    )

    $mandatoryEntries = @($ManifestModule.mandatoryEvidence)
    $optionalEntries = @($ManifestModule.optionalEvidence)
    $entries = @($mandatoryEntries + $optionalEntries)
    $Result.RawEvidenceItemCount = [int]$Result.CollectedEvidenceCount
    if ($entries.Count -eq 0) {
        $Result.ExpectedEvidenceCount = 0
        $Result.CollectedEvidenceCount = 0
        $Result.ExpectedMandatoryEvidenceCount = 0
        $Result.CollectedMandatoryEvidenceCount = 0
        $Result.EvidenceUnitResults = @()
        return $Result
    }

    $mandatoryUnits = @{}
    foreach ($entry in $mandatoryEntries) { $mandatoryUnits[[string]$entry.evidenceUnitId] = $true }
    $instances = @{}
    foreach ($cardinality in @("PER_FIREWALL_PROFILE", "PER_FIXED_VOLUME", "PER_NETWORK_ADAPTER", "PER_LOCAL_ACCOUNT")) {
        $instances[$cardinality] = New-Object System.Collections.Generic.List[string]
        if ($ManifestModule.PSObject.Properties.Name -contains "cardinalityContexts") {
            $property = $ManifestModule.cardinalityContexts.PSObject.Properties[$cardinality]
            if ($null -ne $property) {
                foreach ($value in @($property.Value)) { $instances[$cardinality].Add(([string]$value).ToUpperInvariant()) }
            }
        }
    }
    foreach ($setting in @($Result.Settings)) {
        foreach ($entry in $entries) {
            if (-not (Test-CSASettingMatchesManifestEntry ([string]$setting.settingId) $entry)) { continue }
            $cardinality = [string]$entry.cardinality
            if ($cardinality -ne "SINGLE") {
                $hasDeclaredContext = $ManifestModule.PSObject.Properties.Name -contains "cardinalityContexts" -and
                    $null -ne $ManifestModule.cardinalityContexts.PSObject.Properties[$cardinality]
                if ($hasDeclaredContext) { continue }
                $instance = Get-CSASettingInstanceKey $setting $entry
                if ($null -ne $instance -and -not $instances[$cardinality].Contains($instance)) {
                    $instances[$cardinality].Add($instance)
                }
            }
        }
    }

    $expected = @{}
    foreach ($entry in @($entries | Where-Object { [bool]$_.canonical })) {
        $unitId = [string]$entry.evidenceUnitId
        $isMandatory = $mandatoryUnits.ContainsKey($unitId)
        if ([string]$entry.cardinality -eq "SINGLE") {
            $expected[$unitId] = [ordered]@{ UnitId = $unitId; Instance = "SINGLE"; Mandatory = $isMandatory; Collected = $false }
        } else {
            foreach ($instance in @($instances[[string]$entry.cardinality])) {
                $key = "$unitId|$instance"
                $expected[$key] = [ordered]@{ UnitId = $unitId; Instance = $instance; Mandatory = $isMandatory; Collected = $false }
            }
        }
    }

    $unmapped = New-Object System.Collections.Generic.List[string]
    foreach ($setting in @($Result.Settings)) {
        $matched = $false
        foreach ($entry in $entries) {
            if (-not (Test-CSASettingMatchesManifestEntry ([string]$setting.settingId) $entry)) { continue }
            $matched = $true
            $key = [string]$entry.evidenceUnitId
            if ([string]$entry.cardinality -ne "SINGLE") {
                $instance = Get-CSASettingInstanceKey $setting $entry
                if ($null -eq $instance) { continue }
                $key = "$key|$instance"
            }
            if ($expected.ContainsKey($key) -and [string]$setting.collectionStatus -eq "SUCCESS") {
                $expected[$key].Collected = $true
            }
        }
        if (-not $matched) { $unmapped.Add([string]$setting.settingId) }
    }

    $units = @($expected.Values)
    $mandatory = @($units | Where-Object { $_.Mandatory })
    $collected = @($units | Where-Object { $_.Collected })
    $collectedMandatory = @($mandatory | Where-Object { $_.Collected })
    $warningList = New-Object System.Collections.Generic.List[string]
    foreach ($warning in @($Result.Warnings)) { $warningList.Add([string]$warning) }
    if ($unmapped.Count -gt 0) {
        throw "Evidence not declared in manifest for $($Result.Module): $($unmapped -join ', ')"
    }
    $missingOptional = @($units | Where-Object { -not $_.Mandatory -and -not $_.Collected }).Count
    if ($missingOptional -gt 0) {
        $warningList.Add("Optional evidence units not collected: $missingOptional")
    }

    $preservedStatus = [string]$Result.Status
    if ($preservedStatus -notin @("NOT_SUPPORTED", "ACCESS_DENIED", "FAILED")) {
        if ($units.Count -eq 0) {
            $Result.Status = "NOT_AVAILABLE"
        } elseif ($mandatory.Count -gt 0 -and $collectedMandatory.Count -lt $mandatory.Count) {
            $Result.Status = if ($collected.Count -eq 0) { "NOT_AVAILABLE" } else { "PARTIAL" }
        } elseif (@($Result.Errors).Count -gt 0) {
            $Result.Status = "PARTIAL"
        } else {
            $Result.Status = "SUCCESS"
        }
    }
    $Result.ExpectedEvidenceCount = $units.Count
    $Result.CollectedEvidenceCount = $collected.Count
    $Result.ExpectedMandatoryEvidenceCount = $mandatory.Count
    $Result.CollectedMandatoryEvidenceCount = $collectedMandatory.Count
    $Result.EvidenceUnitResults = $units
    $Result.Warnings = $warningList.ToArray()
    return $Result
}

function Test-CSAEvidenceManifest {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$ModuleRoot
    )

    $allowedCardinalities = @($Manifest.cardinalityTypes)
    $globalSettingIds = @{}
    foreach ($module in @($Manifest.modules)) {
        $modulePath = Join-Path $ModuleRoot "$($module.module).psm1"
        if (-not (Test-Path -LiteralPath $modulePath)) { throw "Manifest module file is missing: $($module.module)" }
        $moduleSource = Get-Content -Raw -LiteralPath $modulePath
        $functionName = "Get-CSA$($module.module)Evidence"
        if ($moduleSource -notmatch "(?i)function\s+$functionName\b") { throw "Manifest module function is missing: $functionName" }
        $entries = @(@($module.mandatoryEvidence) + @($module.optionalEvidence))
        if ($module.PSObject.Properties.Name -contains "cardinalityContexts") {
            foreach ($context in @($module.cardinalityContexts.PSObject.Properties.Name)) {
                if ($context -eq "SINGLE" -or $context -notin $allowedCardinalities) { throw "Unknown cardinality context in $($module.module): $context" }
            }
        }
        $mandatoryUnits = @($module.mandatoryEvidence | ForEach-Object { [string]$_.evidenceUnitId })
        $optionalUnits = @($module.optionalEvidence | ForEach-Object { [string]$_.evidenceUnitId })
        $overlap = @($mandatoryUnits | Where-Object { $optionalUnits -contains $_ } | Select-Object -Unique)
        if ($overlap.Count -gt 0) { throw "Mandatory and optional evidence units overlap in $($module.module): $($overlap -join ', ')" }
        $seenIds = @{}
        foreach ($entry in $entries) {
            foreach ($field in @("id", "matchType", "cardinality", "evidenceUnitId", "canonical")) {
                if (-not ($entry.PSObject.Properties.Name -contains $field)) { throw "Manifest entry in $($module.module) is missing $field." }
            }
            if ([string]$entry.matchType -notin @("LITERAL", "WILDCARD", "REGEX")) { throw "Unknown match type: $($entry.matchType)" }
            if ([string]$entry.cardinality -notin $allowedCardinalities) { throw "Unknown cardinality: $($entry.cardinality)" }
            if ($entry.canonical -isnot [bool]) { throw "Canonical flag must be boolean: $($entry.id)" }
            if ([string]$entry.matchType -eq "LITERAL" -and [string]$entry.id -match '[*<>]') { throw "Literal evidence ID contains a placeholder: $($entry.id)" }
            if ([string]$entry.matchType -eq "WILDCARD" -and [string]$entry.id -notmatch '\*') { throw "Wildcard evidence ID has no wildcard: $($entry.id)" }
            if ([string]$entry.cardinality -ne "SINGLE" -and [string]$entry.matchType -ne "WILDCARD" -and -not ($entry.PSObject.Properties.Name -contains "instanceMetadataField")) {
                throw "Dynamic non-wildcard evidence needs instanceMetadataField: $($entry.id)"
            }
            if ($seenIds.ContainsKey([string]$entry.id)) { throw "Evidence ID is declared twice in $($module.module): $($entry.id)" }
            $seenIds[[string]$entry.id] = $true
            if ($globalSettingIds.ContainsKey([string]$entry.id)) { throw "Evidence ID is declared by multiple modules: $($entry.id)" }
            $globalSettingIds[[string]$entry.id] = $true
        }
        foreach ($group in @($entries | Group-Object evidenceUnitId)) {
            if (@($group.Group | Where-Object { [bool]$_.canonical }).Count -ne 1) {
                throw "Evidence unit must have exactly one canonical entry: $($group.Name)"
            }
            if (@($group.Group | ForEach-Object { [string]$_.cardinality } | Select-Object -Unique).Count -ne 1) {
                throw "Aliases use different cardinalities: $($group.Name)"
            }
        }
    }
    return $true
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
    New-CSAModuleResult -Module "General" -Errors $errors -Warnings $warnings -StartedAt $startedAt -Status $status -SoftwareItems $softwareItems -Services $services -ScheduledTasks $scheduledTasks
}

Export-ModuleMember -Function New-CSASetting, New-CSACollectionError, New-CSAModuleResult, Test-CSASettingMatchesManifestEntry, Resolve-CSAModuleEvidence, Test-CSAEvidenceManifest, Get-CSARegistryValue, Resolve-CSAExceptionStatus, Protect-CSAIdentifier, Protect-CSAPath, Get-CSAGeneralEvidence
