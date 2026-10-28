# Profile enforcement happens on the complete in-memory document before writing.
Set-StrictMode -Version 2.0

function ConvertTo-CSAPrivacyObject {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $result=[ordered]@{}
        $names=if($Value -is [Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties.Name) }
        foreach($name in $names) {
            if($Value -is [Collections.IDictionary]) { $item=$Value[$name] } else { $item=$Value.$name }
            $result[[string]$name]=ConvertTo-CSAPrivacyObject $item
        }
        return $result
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        $items=@(foreach($item in $Value) { ConvertTo-CSAPrivacyObject $item })
        return ,$items
    }
    return $Value
}

function Get-CSAPrivacyDigest {
    param([string]$Value, $State, [string]$Kind='principal', [switch]$Full)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if($Kind -eq 'principal' -and $Value -match '^S-1-(5-(18|19|20|32-\d+)|16-\d+)$') { return $Value }
    $hmac=New-Object Security.Cryptography.HMACSHA256
    try {
        $hmac.Key=$State.Key
        $bytes=[Text.Encoding]::UTF8.GetBytes($State.AssessmentId+'|'+$Kind+'|'+$Value.ToLowerInvariant())
        $hex=([BitConverter]::ToString($hmac.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
        if($Full) { return 'sha256:'+$hex }
        return 'id-'+$hex.Substring(0,24)
    } finally { $hmac.Dispose() }
}

function New-CSAPrivacyState {
    param($Context)
    if($null -eq $Context) {
        $key=New-Object byte[] 32
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($key) } finally { $rng.Dispose() }
        return @{Key=$key;AssessmentId=[guid]::NewGuid().ToString('N');Scope='COLLECTION';Identifiers=@{}}
    }
    try {
        $key=[Convert]::FromBase64String([string]$Context.key)
        if($key.Length -ne 32 -or [string]::IsNullOrWhiteSpace([string]$Context.assessmentId)) { throw 'Invalid context' }
        return @{Key=$key;AssessmentId=[string]$Context.assessmentId;Scope='ASSESSMENT';Identifiers=@{}}
    } catch { throw 'CSA-PRIVACY-CONTEXT: Privacy context is invalid.' }
}

function Get-CSAPrivacyDeviceId {
    param([string]$Hostname, $Context)
    $state=New-CSAPrivacyState $Context
    try { return Get-CSAPrivacyDigest $Hostname $state 'endpoint' -Full }
    finally { [Array]::Clear($state.Key,0,$state.Key.Length) }
}

function Add-CSAPrivacyIdentifiers {
    param($Value,$State,[string]$Scope='')
    if($Value -is [Collections.IDictionary]) {
        if($Value.Contains('category')) { $Scope+='|'+[string]$Value['category'] }
        if($Value.Contains('Module')) { $Scope+='|'+[string]$Value['Module'] }
        foreach($name in @($Value.Keys)) {
            $item=$Value[$name]
            if($item -is [string] -and ($name -match '^(computerName|hostname|fqdn|domain|workgroup|domainOrWorkgroup|currentUser|currentUserSid|entraTenantId|deviceId|subjectSid|sid|userName|serviceAccount|principal)$' -or
                    ($Scope -match 'Accounts|device|Certificates' -and $name -match '^(Name|ProfileName|SubjectIdentifier|IssuerIdentifier|Subject|Issuer)$'))) {
                if($item.Length -ge 3 -and $item -notmatch '^S-1-(5-(18|19|20|32-\d+)|16-\d+)$') {
                    $State.Identifiers[$item]=Get-CSAPrivacyDigest $item $State
                    if($item.Contains('\')) {
                        foreach($part in $item.Split('\')) {
                            if($part.Length -ge 3) { $State.Identifiers[$part]=Get-CSAPrivacyDigest $part $State }
                        }
                    }
                }
            }
            Add-CSAPrivacyIdentifiers $item $State ($Scope+'|'+$name)
        }
    } elseif($Value -is [array]) { foreach($item in $Value) { Add-CSAPrivacyIdentifiers $item $State $Scope } }
}

function Protect-CSAPrivacyPath {
    param([string]$Value,$State,$Policy)
    if($Policy.includeFilePaths -eq 'NONE') { return $null }
    $result=$Value
    if($Policy.includeFilePaths -ne 'FULL' -or $Policy.hashUsername) {
        $result=[regex]::Replace($result,'(?i)[A-Z]:\\Users\\[^\\/\s]+','C:\Users\<USER>')
        $result=[regex]::Replace($result,'(?i)/Users/[^/\s]+','/Users/<USER>')
    }
    $result=[regex]::Replace($result,'S-1-5-21-\d+(?:-\d+)+',{
        param($match) Get-CSAPrivacyDigest $match.Value $State
    }.GetNewClosure())
    if(-not $Policy.includeHostname) {
        $result=[regex]::Replace($result,'\\\\([^\\]+)',{
            param($match) '\\'+(Get-CSAPrivacyDigest $match.Groups[1].Value $State 'endpoint')
        }.GetNewClosure())
    }
    foreach($original in @($State.Identifiers.Keys | Sort-Object Length -Descending)) {
        $pattern='(?i)(?<![A-Za-z0-9_])'+[regex]::Escape([string]$original)+'(?![A-Za-z0-9_])'
        $result=[regex]::Replace($result,$pattern,[string]$State.Identifiers[$original])
    }
    return $result
}

function Protect-CSAPrivacyValue {
    param($Value,$State,$Policy,[string]$Scope='',[string]$Field='')
    if($null -eq $Value) { return $null }
    if($Field -match '^(message|errorMessage|warning|warnings|safeMessage|diagnostic|diagnostics)$') {
        if($Value -is [array]) { return ,@(foreach($item in $Value) { 'Diagnostic detail withheld by privacy policy.' }) }
        return 'Diagnostic detail withheld by privacy policy.'
    }
    if($Value -is [Collections.IDictionary]) {
        if($Value.Contains('category')) { $Scope+='|'+[string]$Value['category'] }
        if($Value.Contains('Module')) { $Scope+='|'+[string]$Value['Module'] }
        if($Value.Contains('settingId')) { $Scope+='|'+[string]$Value['settingId'] }
        $result=[ordered]@{}
        foreach($name in @($Value.Keys)) {
            if(-not $Policy.includeRawRegistryValues -and $name -match '^rawRegistry') { continue }
            if(-not $Policy.includeBrowserExtensions -and $name -eq 'browserExtensions') { $result[$name]=@(); continue }
            if($name -eq 'SidSuffix') { $result[$name]=$null; continue }
            $result[$name]=Protect-CSAPrivacyValue $Value[$name] $State $Policy ($Scope+'|'+$name) ([string]$name)
        }
        return $result
    }
    if($Value -is [array]) { return ,@(foreach($item in $Value) { Protect-CSAPrivacyValue $item $State $Policy $Scope $Field }) }
    if($Value -isnot [string]) { return $Value }
    # Do not interpret product versions such as 120.0.0.0 as IP addresses.
    if($Field -match '^(displayVersion|normalizedVersion|version|build|cpe|cpeName|productKey|publisher|displayName|normalizedProduct|normalizedVendor)$') { return $Value }
    if($Field -match '^(sid|subjectSid|currentUserSid)$') { return Get-CSAPrivacyDigest $Value $State }
    if($Field -match '^(currentUser|userName|serviceAccount|principal|effectiveUserHash)$' -and $Policy.hashUsername) { return Get-CSAPrivacyDigest $Value $State }
    if($Scope -match 'Accounts|CURRENT_EXECUTION_USER|LOCAL_ADMINISTRATORS|LOCAL_USERS|USER_PROFILES|LOGGED_ON_USERS' -and $Field -match '^(Name|ProfileName|user|account)$') {
        if($Policy.hashUsername -or -not $Policy.includeLocalAdminNames) { return Get-CSAPrivacyDigest $Value $State }
    }
    if($Field -match '^(computerName|hostname|fqdn|domain|workgroup|domainOrWorkgroup)$' -and -not $Policy.includeHostname) { return Get-CSAPrivacyDigest $Value $State 'endpoint' }
    if($Field -match '^(entraTenantId|tenantId|entraDeviceId|deviceId)$' -and $Policy.hashTenantId) { return Get-CSAPrivacyDigest $Value $State 'tenant' }
    if($Scope -match 'Certificates|certificates' -and $Field -match '^(Subject|Issuer|SubjectIdentifier|IssuerIdentifier)$' -and -not $Policy.includeCertificateSubjects) { return Get-CSAPrivacyDigest $Value $State 'certificate' }
    if($Scope -match 'Network|NETWORK_|ADAPTER|network' -and $Field -match 'Mac|PhysicalAddress' -and -not $Policy.includeMacAddresses) { return $null }
    if($Scope -match 'Network|NETWORK_|ADAPTER|network' -and $Field -match 'IP(Address|v4Address|v6Address)|Gateway|DnsServer|Subnet' -and -not $Policy.includeIpAddresses) { return $null }
    if($Scope -match 'ACTIVE_NETWORK_PROFILE' -and $Field -match 'effectiveValue|configuredValue') { return Get-CSAPrivacyDigest $Value $State 'network' }
    if($Scope -match 'Network|NETWORK_|ADAPTER|network' -and $Field -match '^(Name|InterfaceAlias|ProfileName)$' -and -not $Policy.includeHostname) { return Get-CSAPrivacyDigest $Value $State 'network' }
    if($Field -match 'Path|Location|Executable|UninstallKey|CommandLine') { return Protect-CSAPrivacyPath $Value $State $Policy }
    return $Value
}

function Invoke-CSACollectionPrivacy {
    param($Document,$Policy,$Context)
    foreach($name in @('includeHostname','hashUsername','hashTenantId','includeIpAddresses','includeMacAddresses',
        'includeSoftwareInventory','includeBrowserExtensions','includeCertificateSubjects','includeLocalAdminNames','includeRawRegistryValues')) {
        if($Policy.$name -isnot [bool]) { throw 'CSA-PRIVACY-POLICY: Privacy policy is malformed.' }
    }
    if($Policy.includeFilePaths -notin @('REDACT_USER_PROFILE','NONE','FULL')) { throw 'CSA-PRIVACY-POLICY: File-path policy is invalid.' }
    $state=New-CSAPrivacyState $Context
    try {
        $source=ConvertTo-CSAPrivacyObject $Document
        $scopeId=Get-CSAPrivacyDigest $state.AssessmentId $state 'scope'
        # Always enforce the selected policy; a caller-supplied metadata stamp
        # must never skip redaction. Production calls this stage exactly once.
        Add-CSAPrivacyIdentifiers $source $state
        $result=Protect-CSAPrivacyValue $source $state $Policy
        if(-not $result.Contains('metadata')) { $result['metadata']=[ordered]@{} }
        $result.metadata['privacyMode']='PROFILE_ENFORCED'
        $result.metadata['privacyScope']=$state.Scope
        $result.metadata['privacyScopeId']=$scopeId
        $result.metadata['privacyPolicyApplied']=ConvertTo-CSAPrivacyObject $Policy
        if(-not $Policy.includeSoftwareInventory -and $result.Contains('software')) {
            $result.software['items']=@(); $result.software['recordsCollected']=0
            $result.software['collectionStatus']='NOT_EVALUATED'
            $result.metadata['softwarePrivacyLimitation']='SOFTWARE_INVENTORY_WITHHELD_BY_POLICY'
            if($result.Contains('capabilityResults')) {
                foreach($capability in $result.capabilityResults) {
                    if($capability.capabilityId -eq 'COL-SOFTWARE-001') {
                        $capability['status']='NOT_COLLECTED_POLICY_BLOCKED'; $capability['evidenceCount']=0
                        $capability['limitationCode']='PRIVACY_POLICY'
                    }
                }
            }
            if($result.metadata.Contains('moduleResults')) {
                foreach($module in $result.metadata.moduleResults) { if($module.Contains('SoftwareItems')) { $module['SoftwareItems']=@() } }
            }
        }
        return $result
    } finally { [Array]::Clear($state.Key,0,$state.Key.Length) }
}

Export-ModuleMember -Function Invoke-CSACollectionPrivacy, Get-CSAPrivacyDeviceId
