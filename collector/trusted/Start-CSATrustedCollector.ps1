param([Parameter(Mandatory = $true)][string]$Bundle, [string]$OfflineExport)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
try {
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'CSA-TRUST-POLICY' }
    $policyPath = Join-Path $env:ProgramData 'CSA/Trust/policy.json'
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { throw 'TRUST_NOT_ESTABLISHED' }
    $trustedOwners = @('S-1-5-18', 'S-1-5-32-544')
    $current = [IO.Path]::GetFullPath($policyPath)
    $writeRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    while ($current -and $current -ne $env:ProgramData) {
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CSA-TRUST-POLICY-PATH' }
        $acl = Get-Acl -LiteralPath $current
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedOwners) { throw 'CSA-TRUST-POLICY-ACL' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeRights) -and
                $rule.IdentityReference.Value -notin $trustedOwners) { throw 'CSA-TRUST-POLICY-ACL' }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    $policy = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($policyPath))) -ErrorAction Stop
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($policy.objectType -ne 'CSA_TRUST_POLICY' -or $policy.schemaVersion -ne 1 -or
        $policy.issuedAt -gt ($now + 120) -or $policy.expiresAt -le $now -or $policy.revocationFreshUntil -le $now) { throw 'CSA-TRUST-STALE' }
    $self = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
    $executable = Join-Path $PSScriptRoot 'CSA-TrustedCollector.exe'
    if ([IO.Path]::GetFullPath($executable) -ne (Join-Path $env:ProgramFiles 'CSA/Collector/CSA-TrustedCollector.exe')) {
        throw 'CSA-TRUST-INSTALLATION'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $executable
    if ([string]$self.Status -ne 'Valid' -or [string]$signature.Status -ne 'Valid' -or
        $self.SignerCertificate.Thumbprint -ne $signature.SignerCertificate.Thumbprint) { throw 'CSA-TRUST-AUTHENTICODE' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $pin = 'sha256:' + ([BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $keys = @($policy.publishers | Where-Object { $_.certificateSha256 -eq $pin -and
        $_.revoked -ceq $false -and $_.issuedAt -le ($now + 120) -and $_.expiresAt -gt $now })
    if ($keys.Count -ne 1) { throw 'CSA-TRUST-PUBLISHER' }
    # Both transports invoke the same immutable enrolled verifier. It checks
    # the publisher, Lab, session and all engine bytes before collection.
    $arguments = @('--bundle', [IO.Path]::GetFullPath($Bundle))
    if ($OfflineExport) { $arguments += @('--offline', [IO.Path]::GetFullPath($OfflineExport)) }
    & $executable @arguments
    exit $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine('TRUST_NOT_ESTABLISHED: Contact the assessor for independently verified enrollment and distribution.')
    exit 1
}
