param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$Thumbprint,
    [string]$PublisherVerificationPath
)
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Security
    if ($Thumbprint -notmatch '\A[A-Fa-f0-9]{40}\z') { throw 'CSA-TRUST-SIGNER' }
    $certificate = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Thumbprint -eq $Thumbprint -and $_.HasPrivateKey } | Select-Object -First 1
    if ($null -eq $certificate) { throw 'CSA-TRUST-SIGNER' }
    $now = [DateTime]::UtcNow
    if ($certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now) {
        throw 'CSA-TRUST-EXPIRED'
    }
    if ($PublisherVerificationPath) {
        $verification = Get-Content -LiteralPath $PublisherVerificationPath -Raw | ConvertFrom-Json
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $actual = 'sha256:' + ([BitConverter]::ToString($hash.ComputeHash($certificate.RawData))).Replace('-', '').ToLowerInvariant() }
        finally { $hash.Dispose() }
        if ($verification.certificateSha256 -cne $actual -or @($verification.artifacts).Count -ne 2) { throw 'CSA-TRUST-PUBLISHER' }
        foreach ($artifact in $verification.artifacts) {
            $signature = Get-AuthenticodeSignature -LiteralPath $artifact
            if ([string]$signature.Status -ne 'Valid' -or $null -eq $signature.TimeStamperCertificate -or
                $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw 'CSA-TRUST-AUTHENTICODE' }
        }
    }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    if ($null -eq $rsa -or $rsa.KeySize -lt 3072) { throw 'CSA-TRUST-ALGORITHM' }
    $rsa.Dispose()
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($InputPath)), $true)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
    $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer, $true)
    [IO.File]::WriteAllBytes($OutputPath, $cms.Encode())
} catch {
    [Console]::Error.WriteLine('CSA-TRUST-SIGNING: The independently provisioned signing identity is unavailable or invalid.')
    exit 1
}
