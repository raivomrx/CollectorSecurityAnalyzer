param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths,
    [switch]$RequireSignature = ($env:CSA_BUILD_KIND -eq 'RELEASE')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if (-not $env:CSA_SIGNING_CERTIFICATE_BASE64 -or -not $env:CSA_SIGNING_CERTIFICATE_PASSWORD) {
    if ($RequireSignature) { throw 'CSA-RELEASE-SIGNING-REQUIRED' }
    Write-Host "UNSIGNED LAB ONLY. Publisher signing is unavailable. Release HOLD."
    exit 0
}
if ($RequireSignature -and $env:CSA_PUBLISHER_CERT_SHA256 -notmatch '^sha256:[0-9a-f]{64}$') {
    throw 'CSA-RELEASE-PUBLISHER-IDENTITY-REQUIRED'
}

$signtool = Get-ChildItem `
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
    -Filter signtool.exe `
    -Recurse `
    -ErrorAction Stop |
    Where-Object { $_.FullName -like "*\x64\signtool.exe" } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signtool) { throw "signtool.exe was not found." }

$certificate = Join-Path $env:RUNNER_TEMP ("csa-signing-" + [guid]::NewGuid().ToString('N') + ".pfx")
$imported = $null
$alreadyPresent = $false
try {
    # Establish the file ACL before writing any private certificate material.
    [IO.File]::WriteAllBytes($certificate, [byte[]]@())
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($identity)
    foreach ($sid in @($identity, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    Set-Acl -LiteralPath $certificate -AclObject $acl
    [IO.File]::WriteAllBytes(
        $certificate,
        [Convert]::FromBase64String($env:CSA_SIGNING_CERTIFICATE_BASE64)
    )
    $password = ConvertTo-SecureString $env:CSA_SIGNING_CERTIFICATE_PASSWORD -AsPlainText -Force
    $probe = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate,
        $env:CSA_SIGNING_CERTIFICATE_PASSWORD, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    try { $alreadyPresent = Test-Path -LiteralPath ("Cert:\CurrentUser\My\" + $probe.Thumbprint) }
    finally { $probe.Dispose() }
    $imported = Import-PfxCertificate -FilePath $certificate -CertStoreLocation 'Cert:\CurrentUser\My' -Password $password |
        Where-Object HasPrivateKey | Select-Object -First 1
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($imported)
    if ($null -eq $rsa -or $rsa.KeySize -lt 3072) { throw 'CSA-RELEASE-KEY-SIZE' }
    $rsa.Dispose()
    foreach ($path in $Paths) {
        if ([IO.Path]::GetExtension($path) -in @('.ps1', '.psm1')) {
            $signature = Set-AuthenticodeSignature -LiteralPath $path -Certificate $imported -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.digicert.com'
                if ([string]$signature.Status -ne 'Valid') { throw 'PowerShell signing failed.' }
        } else {
        & $signtool.FullName sign `
            /fd SHA256 `
            /td SHA256 `
            /tr "http://timestamp.digicert.com" `
            /sha1 $imported.Thumbprint `
            $path
        if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $path" }
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ([string]$signature.Status -ne 'Valid' -or $null -eq $signature.TimeStamperCertificate) {
            throw 'CSA-RELEASE-FINAL-SIGNATURE'
        }
        if ($RequireSignature) {
            $hash = [Security.Cryptography.SHA256]::Create()
            try { $actual = 'sha256:' + ([BitConverter]::ToString($hash.ComputeHash($signature.SignerCertificate.RawData))).Replace('-', '').ToLowerInvariant() }
            finally { $hash.Dispose() }
            if ($actual -cne $env:CSA_PUBLISHER_CERT_SHA256) { throw 'CSA-RELEASE-WRONG-PUBLISHER' }
        }
        & $signtool.FullName verify /pa /all /v $path
        if ($LASTEXITCODE) { throw 'CSA-RELEASE-SIGNATURE-VERIFY' }
    }
} finally {
    Remove-Item -LiteralPath $certificate -Force -ErrorAction SilentlyContinue
    if ($null -ne $imported -and -not $alreadyPresent) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $imported.Thumbprint) -DeleteKey -Force
    }
}
