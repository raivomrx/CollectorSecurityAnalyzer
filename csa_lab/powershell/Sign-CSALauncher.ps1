param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Thumbprint)
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path $PSHOME "Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1") -ErrorAction Stop
    if ($Thumbprint -notmatch '\A[0-9a-fA-F]{40}\z') { throw 'SIGNER_UNAVAILABLE' }
    $certificate = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Thumbprint -eq $Thumbprint -and $_.HasPrivateKey } | Select-Object -First 1
    if ($null -eq $certificate) { throw 'SIGNER_UNAVAILABLE' }
    $result = Set-AuthenticodeSignature -LiteralPath $Path -Certificate $certificate -HashAlgorithm SHA256
    if ([string]$result.Status -ne 'Valid') { throw 'SIGNING_FAILED' }
} catch { [Console]::Error.WriteLine('CSA launcher signing failed.'); exit 1 }
