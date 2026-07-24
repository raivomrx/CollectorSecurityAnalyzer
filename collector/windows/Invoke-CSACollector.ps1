param(
    [string]$ExportPath,
    [switch]$NoSubmit
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$packageRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Get-CSASha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return "sha256:" + ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-CSASha256File {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return "sha256:" + ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function ConvertTo-CSAOrderedObject {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $ordered[$key] = ConvertTo-CSAOrderedObject $Value[$key]
        }
        return $ordered
    }
    if ($Value -is [pscustomobject]) {
        $ordered = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties | Sort-Object Name)) {
            $ordered[$property.Name] = ConvertTo-CSAOrderedObject $property.Value
        }
        return $ordered
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @($Value | ForEach-Object { ConvertTo-CSAOrderedObject $_ })
        return ,$items
    }
    return $Value
}

function ConvertTo-CSACanonicalJson {
    param($Value)
    $normalized = ConvertTo-CSAOrderedObject $Value
    return (ConvertTo-Json -InputObject $normalized -Depth 24 -Compress)
}

function Write-CSACanonicalJson {
    param([string]$Path, $Value)
    [System.IO.File]::WriteAllText($Path, (ConvertTo-CSACanonicalJson $Value), $utf8)
}

function Resolve-CSAPackagePath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)
    if ([System.IO.Path]::IsPathRooted($RelativePath) -or $RelativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "Trusted package contains an unsafe path."
    }
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $packageRoot $RelativePath))
    if (-not $candidate.StartsWith($packageRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Trusted package path escapes the package root."
    }
    return $candidate
}

function Test-CSATrustedPackage {
    $manifestPath = Join-Path $packageRoot "trusted-manifest.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Trusted package manifest is missing."
    }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $declared = @{}
    foreach ($file in @($manifest.files)) {
        $relative = [string]$file.path
        if ($declared.ContainsKey($relative)) { throw "Trusted package contains a duplicate path." }
        $declared[$relative] = $true
        $path = Resolve-CSAPackagePath $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Trusted package file is missing." }
        if ((Get-Item -LiteralPath $path).Length -ne [long]$file.size) { throw "Trusted package file size mismatch." }
        if ((Get-CSASha256File $path) -ne [string]$file.sha256) { throw "Trusted package digest mismatch." }
    }
    $actual = @(
        Get-ChildItem -LiteralPath $packageRoot -Recurse -File |
            Where-Object { $_.Name -ne "trusted-manifest.json" } |
            ForEach-Object { $_.FullName.Substring($packageRoot.Length + 1).Replace("\", "/") }
    )
    if (@($actual | Where-Object { -not $declared.ContainsKey($_) }).Count -gt 0 -or $actual.Count -ne $declared.Count) {
        throw "Trusted package contains an undeclared file."
    }
    return $manifest
}

function Get-CSAPrivilegeContext {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $groups = (& "$env:SystemRoot\System32\whoami.exe" /groups /fo csv /nh 2>$null) -join "`n"
    $adminMember = $groups -match "S-1-5-32-544"
    $integrity = "UNKNOWN"
    if ($groups -match "S-1-16-16384") { $integrity = "SYSTEM" }
    elseif ($groups -match "S-1-16-12288") { $integrity = "HIGH" }
    elseif ($groups -match "S-1-16-(8192|8448)") { $integrity = "MEDIUM" }
    elseif ($groups -match "S-1-16-4096") { $integrity = "LOW" }
    $mode = if ($identity.User.Value -eq "S-1-5-18") { "SYSTEM" }
        elseif ($elevated) { "ELEVATED_ADMINISTRATOR" }
        elseif ($adminMember) { "ADMIN_MEMBER_NOT_ELEVATED" }
        else { "STANDARD_USER" }
    return [ordered]@{
        executionMode = $mode
        isElevated = [bool]$elevated
        isLocalAdministratorMember = [bool]$adminMember
        integrityLevel = $integrity
    }
}

function New-CSATemporaryDirectory {
    param([Parameter(Mandatory = $true)][string]$SubmissionId)
    $root = Join-Path $env:TEMP "CSA"
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    $path = Join-Path $root $SubmissionId
    if (Test-Path -LiteralPath $path) { throw "Unique Collector temporary directory already exists." }
    [System.IO.Directory]::CreateDirectory($path) | Out-Null
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & "$env:SystemRoot\System32\icacls.exe" `
        $path `
        /inheritance:r `
        /grant:r `
        "*$($currentSid):(OI)(CI)F" `
        "*S-1-5-18:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        throw "Unable to apply restrictive permissions to Collector temporary data."
    }
    return $path
}

function Test-CSASensitiveData {
    param($Value)
    $json = ConvertTo-CSACanonicalJson $Value
    $patterns = @(
        '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        '(?i)"(password|passwd|cookie|accessToken|refreshToken|privateKey|recoveryKey|ntlmResponse|kerberosTicket)"\s*:'
    )
    foreach ($pattern in $patterns) {
        if ($json -match $pattern) { throw "Sensitive-data policy rejected the collected evidence." }
    }
}

function New-CSAArchive {
    param([string]$SourceDirectory, [string]$OutputPath)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew)
    try {
        $archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $SourceDirectory -Recurse -File | Sort-Object FullName)) {
                $name = $file.FullName.Substring($SourceDirectory.Length + 1).Replace("\", "/")
                $entry = $archive.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $input = [System.IO.File]::OpenRead($file.FullName)
                $output = $entry.Open()
                try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function New-CSAEvidencePackage {
    param(
        $Configuration,
        $TrustedManifest,
        [string]$EvidencePath,
        [string]$StagingDirectory,
        [string]$SubmissionId,
        [string]$Nonce
    )
    $evidence = Get-Content -Raw -LiteralPath $EvidencePath | ConvertFrom-Json
    Test-CSASensitiveData $evidence
    Test-CSASensitiveData @($evidence.capabilityResults)
    $collectionLog = [ordered]@{
        schemaVersion = "5.0"
        events = @(
            [ordered]@{ event = "COLLECTION_STARTED"; timestamp = [string]$evidence.collectionStartedAt },
            [ordered]@{ event = "COLLECTION_COMPLETED"; timestamp = [string]$evidence.collectionCompletedAt }
        )
        errorCount = @($evidence.errors).Count
        endpointChangesPerformed = @()
        activeValidationPerformed = $false
    }
    $payload = Join-Path $StagingDirectory "payload"
    [System.IO.Directory]::CreateDirectory((Join-Path $payload "signatures")) | Out-Null
    Write-CSACanonicalJson (Join-Path $payload "evidence.json") $evidence
    Write-CSACanonicalJson (Join-Path $payload "capability-results.json") @($evidence.capabilityResults)
    Write-CSACanonicalJson (Join-Path $payload "collection-log.json") $collectionLog
    $files = @()
    foreach ($name in @("evidence.json", "capability-results.json", "collection-log.json")) {
        $path = Join-Path $payload $name
        $files += [ordered]@{ path = $name; sha256 = Get-CSASha256File $path; size = (Get-Item $path).Length }
    }
    $binding = [ordered]@{
        assessmentId = [string]$Configuration.assessmentId
        files = $files
        nonce = $Nonce
        sessionId = [string]$Configuration.sessionId
        submissionId = $SubmissionId
    }
    $packageDigest = Get-CSASha256Bytes ([Text.Encoding]::UTF8.GetBytes((ConvertTo-CSACanonicalJson $binding)))
    $integrity = [ordered]@{ binding = $binding; packageDigest = $packageDigest; schemaVersion = "5.0" }
    $integrityPath = Join-Path $payload "integrity.json"
    Write-CSACanonicalJson $integrityPath $integrity
    $signed = [ordered]@{
        nonce = $Nonce
        packageDigest = $packageDigest
        sessionId = [string]$Configuration.sessionId
        submissionId = $SubmissionId
    }
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes([string]$Configuration.enrollmentToken)
        $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-CSACanonicalJson $signed)))
    } finally {
        $hmac.Dispose()
    }
    $signature = [ordered]@{
        algorithm = "HMAC-SHA256"
        keyId = ([string]$Configuration.enrollmentToken).Split(".")[0]
        signature = [Convert]::ToBase64String($signatureBytes)
        signed = $signed
    }
    $signaturePath = Join-Path $payload "signatures\submission.sig"
    Write-CSACanonicalJson $signaturePath $signature
    $deviceSeed = "$($Configuration.sessionId)|$env:COMPUTERNAME"
    $deviceId = Get-CSASha256Bytes ([Text.Encoding]::UTF8.GetBytes($deviceSeed))
    $manifest = [ordered]@{
        assessmentId = [string]$Configuration.assessmentId
        collectionProfile = [string]$Configuration.collectionProfile
        collectionProfileDigest = [string]$Configuration.collectionProfileDigest
        collectorBuildDigest = [string]$TrustedManifest.collectorBuildDigest
        collectorVersion = [string]$evidence.collectorVersion
        completedAt = [string]$evidence.collectionCompletedAt
        deviceId = $deviceId
        files = $files
        integrityDigest = Get-CSASha256File $integrityPath
        packageDigest = $packageDigest
        privilegeContext = [string]$evidence.privilegeContext.executionMode
        schemaVersion = "5.0"
        sessionId = [string]$Configuration.sessionId
        signatureDigest = Get-CSASha256File $signaturePath
        startedAt = [string]$evidence.collectionStartedAt
        submissionId = $SubmissionId
    }
    Write-CSACanonicalJson (Join-Path $payload "manifest.json") $manifest
    $archivePath = Join-Path $StagingDirectory "$SubmissionId.csa.zip"
    New-CSAArchive $payload $archivePath
    return [ordered]@{ path = $archivePath; digest = $packageDigest; manifest = $manifest; nonce = $Nonce }
}

function Invoke-CSAPinnedRequest {
    param(
        [string]$Uri,
        [string]$Method,
        [string]$ContentType,
        [byte[]]$Body,
        [hashtable]$Headers,
        [string]$Fingerprint
    )
    $target = [Uri]$Uri
    if ($target.Scheme -ne "https") { throw "SERVER_IDENTITY_VALIDATION_FAILED" }
    $expected = $Fingerprint.ToLowerInvariant()
    $previousProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    try {
        $validationCallback = {
            param($Sender, $Certificate, $Chain, $Errors)
            if ($null -eq $Certificate) { return $false }
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $actual = "sha256:" + (
                    [BitConverter]::ToString(
                        $sha.ComputeHash($Certificate.GetRawCertData())
                    )
                ).Replace("-", "").ToLowerInvariant()
                $now = [DateTime]::Now
                return (
                    $actual -eq $expected -and
                    $now -ge $Certificate.NotBefore -and
                    $now -le $Certificate.NotAfter
                )
            } catch {
                return $false
            } finally {
                $sha.Dispose()
            }
        }.GetNewClosure()
        $request = [System.Net.HttpWebRequest]::Create($target)
        $request.ServerCertificateValidationCallback = $validationCallback
        $request.Method = $Method
        $request.ContentType = $ContentType
        $request.Timeout = 60000
        $request.ReadWriteTimeout = 60000
        foreach ($name in $Headers.Keys) { $request.Headers[$name] = [string]$Headers[$name] }
        $request.ContentLength = $Body.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($Body, 0, $Body.Length) } finally { $stream.Dispose() }
        $response = $request.GetResponse()
        try {
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
            try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally {
            $response.Dispose()
        }
    } catch {
        $webResponse = $null
        $exceptionCursor = $_.Exception
        while ($null -ne $exceptionCursor -and $null -eq $webResponse) {
            if ($exceptionCursor.PSObject.Properties.Name -contains "Response") {
                $webResponse = $exceptionCursor.Response
            }
            $exceptionCursor = $exceptionCursor.InnerException
        }
        if ($null -ne $webResponse) {
            try {
                $errorReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream(), [Text.Encoding]::UTF8)
                try {
                    $errorText = $errorReader.ReadToEnd()
                    $errorObject = $errorText | ConvertFrom-Json
                    throw "CONSOLE_REJECTED $([string]$errorObject.error): $([string]$errorObject.message)"
                } finally {
                    $errorReader.Dispose()
                }
            } finally {
                $webResponse.Dispose()
            }
        }
        if ($_.Exception.Message -match '(?i)trust|certificate|secure channel') {
            throw "SERVER_IDENTITY_VALIDATION_FAILED"
        }
        throw
    } finally {
        [System.Net.ServicePointManager]::SecurityProtocol = $previousProtocol
    }
}

function Protect-CSAOfflinePackage {
    param($Configuration, $Package, [string]$OutputPath)
    $publicKeyPath = Resolve-CSAPackagePath ([string]$Configuration.offlinePublicKey)
    $keyMaterial = New-Object byte[] 64
    $iv = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($keyMaterial)
        $rng.GetBytes($iv)
    } finally {
        $rng.Dispose()
    }
    $aesKey = New-Object byte[] 32
    $hmacKey = New-Object byte[] 32
    [Array]::Copy($keyMaterial, 0, $aesKey, 0, 32)
    [Array]::Copy($keyMaterial, 32, $hmacKey, 0, 32)
    $inner = [ordered]@{
        archive = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes([string]$Package.path))
        enrollmentToken = [string]$Configuration.enrollmentToken
        nonce = [string]$Package.nonce
    }
    $plainBytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CSACanonicalJson $inner))
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV = $iv
        $encryptor = $aes.CreateEncryptor()
        try { $ciphertext = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length) }
        finally { $encryptor.Dispose() }
    } finally {
        $aes.Dispose()
    }
    $associated = [ordered]@{
        assessmentId = [string]$Configuration.assessmentId
        packageDigest = [string]$Package.digest
        sessionId = [string]$Configuration.sessionId
        submissionId = [string]$Package.manifest.submissionId
    }
    $associatedBytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CSACanonicalJson $associated))
    $macInput = New-Object byte[] ($associatedBytes.Length + $iv.Length + $ciphertext.Length)
    [Array]::Copy($associatedBytes, 0, $macInput, 0, $associatedBytes.Length)
    [Array]::Copy($iv, 0, $macInput, $associatedBytes.Length, $iv.Length)
    [Array]::Copy($ciphertext, 0, $macInput, $associatedBytes.Length + $iv.Length, $ciphertext.Length)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $hmacKey
        $mac = $hmac.ComputeHash($macInput)
    } finally {
        $hmac.Dispose()
    }
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(3072)
    try {
        $rsa.PersistKeyInCsp = $false
        $rsa.FromXmlString((Get-Content -Raw -LiteralPath $publicKeyPath))
        $wrappedKey = $rsa.Encrypt($keyMaterial, $true)
    } finally {
        $rsa.Dispose()
    }
    $envelope = [ordered]@{
        algorithm = "RSA-OAEP-SHA1+A256CBC-HS256"
        associatedData = $associated
        ciphertext = [Convert]::ToBase64String($ciphertext)
        iv = [Convert]::ToBase64String($iv)
        mac = [Convert]::ToBase64String($mac)
        schemaVersion = "5.0"
        wrappedKey = [Convert]::ToBase64String($wrappedKey)
    }
    $resolved = [System.IO.Path]::GetFullPath($OutputPath)
    if ([System.IO.Path]::GetExtension($resolved) -eq "") {
        [System.IO.Directory]::CreateDirectory($resolved) | Out-Null
        $resolved = Join-Path $resolved "$($Package.manifest.submissionId).csa"
    } else {
        [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($resolved)) | Out-Null
    }
    if (Test-Path -LiteralPath $resolved) { throw "Offline export target already exists." }
    Write-CSACanonicalJson $resolved $envelope
    Write-Host "Encrypted offline submission created: $resolved"
}

$temporaryDirectory = $null
$cleanupConfirmed = $false
$terminalError = $null
try {
    $trustedManifest = Test-CSATrustedPackage
    $configPath = Resolve-CSAPackagePath "session-config.json"
    $configuration = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
    if ([string]$configuration.collectorMode -ne "STANDARD_USER_COLLECTION") {
        throw "Collector package mode is not STANDARD_USER_COLLECTION."
    }
    if ([bool]$configuration.activeValidation) { throw "Active validation is forbidden in standard collection." }
    if ([Uri]$configuration.serverUrl -and ([Uri]$configuration.serverUrl).Scheme -ne "https") {
        throw "SERVER_IDENTITY_VALIDATION_FAILED"
    }
    if ((Get-Date).ToUniversalTime() -ge ([DateTimeOffset]::Parse([string]$configuration.expiresAt)).UtcDateTime) {
        throw "Collector package has expired."
    }
    $privilege = Get-CSAPrivilegeContext
    if ([bool]$privilege.isElevated -or [string]$privilege.executionMode -in @("ELEVATED_ADMINISTRATOR", "SYSTEM")) {
        throw "STANDARD_USER_COLLECTION refuses an elevated or SYSTEM process."
    }
    if ([string]$privilege.integrityLevel -ne "MEDIUM") {
        throw "STANDARD_USER_COLLECTION requires a medium-integrity process."
    }
    Write-Host "Assessment: $($configuration.assessmentName)"
    Write-Host "Organization reference: $($configuration.customerReference)"
    Write-Host "Collector mode: STANDARD USER"
    Write-Host "Administrator rights required: NO"
    Write-Host "Active security testing: NO"
    Write-Host "Data destination: $($configuration.serverUrl)"
    $submissionId = "SUB-" + [guid]::NewGuid().ToString("N")
    $temporaryDirectory = New-CSATemporaryDirectory $submissionId
    $evidencePath = Join-Path $temporaryDirectory "collector-evidence.json"
    & (Resolve-CSAPackagePath "collector\Collect-CSAWindowsEvidence.ps1") `
        -OutputPath $evidencePath `
        -PrivacyMode Strict `
        -CollectionMode STANDARD_USER_COLLECTION `
        -CapabilityRegistryPath (Resolve-CSAPackagePath "collector\collection-capabilities.json") `
        -CollectionProfilePath (Resolve-CSAPackagePath "collector\profiles\windows-standard-v1.json")
    $evidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json
    if ([bool]$evidence.privilegeContext.isElevated) {
        throw "Collected evidence unexpectedly reports an elevated context."
    }
    Write-Host "Collection completed"
    $nonce = $null
    if (-not $NoSubmit) {
        $nonceBody = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CSACanonicalJson ([ordered]@{ submissionId = $submissionId })))
        $nonceResponse = Invoke-CSAPinnedRequest `
            -Uri "$($configuration.serverUrl)/api/v1/nonce" `
            -Method "POST" `
            -ContentType "application/json" `
            -Body $nonceBody `
            -Headers @{ Authorization = "CSA-Enrollment $($configuration.enrollmentToken)" } `
            -Fingerprint ([string]$configuration.serverCertificateFingerprint)
        $nonce = [string](($nonceResponse | ConvertFrom-Json).nonce)
    } else {
        $nonce = "offline:" + [guid]::NewGuid().ToString("N")
    }
    if ([string]::IsNullOrWhiteSpace($nonce)) { throw "Submission nonce was not issued." }
    $package = New-CSAEvidencePackage $configuration $trustedManifest $evidencePath $temporaryDirectory $submissionId $nonce
    if ($NoSubmit) {
        if ([string]::IsNullOrWhiteSpace($ExportPath)) { throw "Offline export path is required with -NoSubmit." }
        Protect-CSAOfflinePackage $configuration $package $ExportPath
    } else {
        $archiveBytes = [System.IO.File]::ReadAllBytes([string]$package.path)
        $receiptText = Invoke-CSAPinnedRequest `
            -Uri "$($configuration.serverUrl)/api/v1/submissions/$submissionId" `
            -Method "POST" `
            -ContentType "application/vnd.csa.submission+zip" `
            -Body $archiveBytes `
            -Headers @{
                Authorization = "CSA-Enrollment $($configuration.enrollmentToken)"
                "X-CSA-Nonce" = $nonce
            } `
            -Fingerprint ([string]$configuration.serverCertificateFingerprint)
        $receipt = $receiptText | ConvertFrom-Json
        if (
            [string]$receipt.submissionId -ne $submissionId -or
            [string]$receipt.packageDigest -ne [string]$package.digest -or
            [string]$receipt.validationStatus -ne "ACCEPTED"
        ) {
            throw "Server receipt binding is invalid."
        }
        Write-Host "Submission accepted"
        Write-Host "Receipt ID: $($receipt.serverReceiptId)"
    }
} catch {
    $terminalError = [string]$_.Exception.Message
} finally {
    if ($null -ne $temporaryDirectory -and (Test-Path -LiteralPath $temporaryDirectory)) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
        $cleanupConfirmed = -not (Test-Path -LiteralPath $temporaryDirectory)
    } else {
        $cleanupConfirmed = $true
    }
    Write-Host "Local temporary data removed: $(if ($cleanupConfirmed) { 'YES' } else { 'NO' })"
}
if ($null -ne $terminalError) {
    [Console]::Error.WriteLine("CSA Collector failed: $terminalError")
    exit 1
}
