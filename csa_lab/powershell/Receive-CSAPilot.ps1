param(
    [Parameter(Mandatory=$true)][string]$Origin,
    [Parameter(Mandatory=$true)][string]$LaunchId,
    [Parameter(Mandatory=$true)][string]$TlsPin,
    [Parameter(Mandatory=$true)][string]$ArchiveSha256,
    [Parameter(Mandatory=$true)][string]$ApprovalSha256,
    [Parameter(Mandatory=$true)][string]$ExeSha256,
    [ValidateSet('Quick','Standard')][string]$Mode='Quick'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$root=$null
$lease=$null
$ticket=$null
$previous=[Net.ServicePointManager]::SecurityProtocol
function Get-PilotDigest([byte[]]$Bytes) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try { return 'sha256:'+([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Request-Pilot([string]$Action,[string]$Credential,[int]$Maximum) {
    $request=[Net.HttpWebRequest]::Create($Origin+'/api/v1/pilot-launch/'+$LaunchId+'/'+$Action)
    $request.Method='POST';$request.ContentLength=0;$request.AllowAutoRedirect=$false
    $request.Timeout=15000;$request.ReadWriteTimeout=15000;$request.KeepAlive=$false
    $expected=$TlsPin
    $request.ServerCertificateValidationCallback={
        param($Sender,$Certificate,$Chain,$Errors)
        if ($null -eq $Certificate) { return $false }
        $h=[Security.Cryptography.SHA256]::Create()
        try {
            $actual='sha256:'+([BitConverter]::ToString($h.ComputeHash($Certificate.GetRawCertData()))).Replace('-','').ToLowerInvariant()
            return ($actual -ceq $expected -and [DateTime]::Now -ge $Certificate.NotBefore -and [DateTime]::Now -le $Certificate.NotAfter)
        } finally { $h.Dispose() }
    }.GetNewClosure()
    $request.Headers['Authorization']=$Credential
    $response=$null;$input=$null;$memory=New-Object IO.MemoryStream
    try {
        $response=$request.GetResponse()
        if ($response.ContentLength -lt 0 -or $response.ContentLength -gt $Maximum) { throw 'CSA-JOIN-SIZE' }
        $input=$response.GetResponseStream();$buffer=New-Object byte[] 65536
        $clock=[Diagnostics.Stopwatch]::StartNew()
        while (($count=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
            if ($memory.Length+$count -gt $Maximum -or $clock.Elapsed.TotalSeconds -gt 30) { throw 'CSA-JOIN-SIZE' }
            $memory.Write($buffer,0,$count)
        }
        if ($memory.Length -ne $response.ContentLength) { throw 'CSA-JOIN-TRANSFER-INTERRUPTED' }
        return ,$memory.ToArray()
    } catch [IO.IOException] {
        throw 'CSA-JOIN-TRANSFER-INTERRUPTED'
    } catch [Net.WebException] {
        $status=$_.Exception.Status
        if ($status -in @([Net.WebExceptionStatus]::Timeout,[Net.WebExceptionStatus]::ConnectionClosed,
                         [Net.WebExceptionStatus]::ReceiveFailure,[Net.WebExceptionStatus]::ConnectFailure)) {
            throw 'CSA-JOIN-TRANSFER-INTERRUPTED'
        }
        throw 'CSA-JOIN-AUTHORIZATION-OR-TLS'
    } finally {
        if ($input) { $input.Dispose() };if ($response) { $response.Dispose() }
        $memory.Dispose();$request.Abort()
    }
}
try {
    if ($Origin -notmatch '^https://[a-zA-Z0-9.\[\]:-]+$' -or $LaunchId -notmatch '^[a-zA-Z0-9_-]{16,128}$') { throw 'CSA-JOIN-SCOPE' }
    foreach ($hash in @($TlsPin,$ArchiveSha256,$ApprovalSha256,$ExeSha256)) {
        if ($hash -notmatch '^sha256:[a-f0-9]{64}$') { throw 'CSA-JOIN-IDENTITY' }
    }
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    Write-Host 'CSA: enter the code supplied by your assessor.'
    $secure=Read-Host 'Code' -AsSecureString
    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $code=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);$secure.Dispose() }
    try {
        if ($code -notmatch '^[A-Za-z0-9_-]{16,128}$') { throw 'CSA-JOIN-CODE' }
        $authorization=[Text.Encoding]::UTF8.GetString((Request-Pilot 'ticket' ('CSA-Pilot '+$code) 4096)) | ConvertFrom-Json
    } finally { $code=$null }
    $ticket=[string]$authorization.ticket
    if ($ticket -notmatch '^[A-Za-z0-9_-]{16,128}$') { throw 'CSA-JOIN-CODE' }
    Write-Host 'CSA: downloading the authorized Collector.'
    $bytes=$null
    for ($attempt=0;$attempt -lt 3;$attempt++) {
        try { $bytes=Request-Pilot 'package' ('CSA-Pilot-Ticket '+$ticket) (64*1024*1024);break }
        catch {
            if ($_.Exception.Message -ne 'CSA-JOIN-TRANSFER-INTERRUPTED' -or $attempt -eq 2) { throw }
            Start-Sleep -Milliseconds (250*($attempt+1))
        }
    }
    if ((Get-PilotDigest $bytes) -cne $ArchiveSha256) { throw 'CSA-JOIN-PACKAGE-HASH' }
    $base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $root=Join-Path $base ('CSA-Join-'+[Guid]::NewGuid().ToString('N'))
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($sid)
    foreach ($principal in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')),(New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    [IO.Directory]::CreateDirectory($root,$acl) | Out-Null
    Add-Type -AssemblyName System.IO.Compression
    $memory=New-Object IO.MemoryStream(,$bytes)
    $zip=New-Object IO.Compression.ZipArchive($memory,[IO.Compression.ZipArchiveMode]::Read)
    try {
        $allowed=@('pilot-approval.json','publisher-manifest.json','publisher-manifest.p7s','session-envelope.json',
            'session-envelope.p7s','collector.zip','CSA-TrustedCollector.exe','Start-CSATrustedCollector.ps1','Start-CSACollector.cmd')
        $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $total=0L
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -notin $allowed -or -not $seen.Add($entry.FullName) -or $entry.Length -gt 64*1024*1024) { throw 'CSA-JOIN-UNSAFE-ARCHIVE' }
            $input=$entry.Open()
            try {
                $output=[IO.File]::Open((Join-Path $root $entry.FullName),'CreateNew','Write','None')
                try {
                    $buffer=New-Object byte[] 65536
                    while(($read=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
                        $total+=$read
                        if($total -gt 128*1024*1024 -or $output.Length+$read -gt $entry.Length) { throw 'CSA-JOIN-SIZE' }
                        $output.Write($buffer,0,$read)
                    }
                    if($output.Length -ne $entry.Length) { throw 'CSA-JOIN-INCOMPLETE-ARCHIVE' }
                } finally { $output.Dispose() }
            } finally { $input.Dispose() }
        }
        if ($seen.Count -ne $allowed.Count) { throw 'CSA-JOIN-INCOMPLETE-ARCHIVE' }
    } finally { $zip.Dispose();$memory.Dispose();$bytes=$null }
    $exe=Join-Path $root 'CSA-TrustedCollector.exe'
    $lease=[IO.File]::Open($exe,'Open','Read','Read')
    $h=[Security.Cryptography.SHA256]::Create()
    try { $actual='sha256:'+([BitConverter]::ToString($h.ComputeHash($lease))).Replace('-','').ToLowerInvariant() }
    finally { $h.Dispose() }
    if ($actual -cne $ExeSha256) { throw 'CSA-JOIN-EXE-HASH' }
    $arguments=@('--assessor-pilot','--bundle',$root,'--approval-sha256',$ApprovalSha256)
    if ($Mode -eq 'Quick') { $arguments+='--quick-run' } else { $arguments+='--powershell' }
    & $exe @arguments
    $result=$LASTEXITCODE
    exit $result
} catch {
    $message=$_.Exception.Message
    if ($message -notmatch '^CSA-JOIN-[A-Z0-9-]+$') { $message='CSA-JOIN-EXECUTION-OR-POLICY' }
    [Console]::Error.WriteLine('CSA-JOIN-STOPPED: '+$message+'; contact the assessor.')
    exit 1
} finally {
    $ticket=$null
    if ($lease) { $lease.Dispose() }
    [Net.ServicePointManager]::SecurityProtocol=$previous
    if ($root -and [IO.Directory]::Exists($root)) {
        $full=[IO.Path]::GetFullPath($root)
        if ($full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($full) -match '^CSA-Join-[a-f0-9]{32}$' -and
            -not ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            try { Remove-Item -LiteralPath $full -Recurse -Force }
            catch { [Console]::Error.WriteLine('CSA-JOIN-CLEANUP: contact the assessor.');exit 1 }
        } else { [Console]::Error.WriteLine('CSA-JOIN-CLEANUP: contact the assessor.');exit 1 }
    }
}
