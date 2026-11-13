param(
    [Parameter(Mandatory=$true)][string]$Origin,
    [Parameter(Mandatory=$true)][string]$LaunchId,
    [Parameter(Mandatory=$true)][string]$TlsPin,
    [Parameter(Mandatory=$true)][string]$ExeSha256
)
$ErrorActionPreference='Stop'
$root=$null
$stage='APPLICATION_CONTROL'
$code='CSA-JOIN-APPLICATION-CONTROL'
try {
    if ($Origin -notmatch '^https://[a-zA-Z0-9.\[\]:-]+$' -or $LaunchId -notmatch '^[a-zA-Z0-9_-]{16,128}$' -or
        $TlsPin -notmatch '^sha256:[a-f0-9]{64}$' -or $ExeSha256 -notmatch '^sha256:[a-f0-9]{64}$') { throw 'CSA-JOIN-SCOPE' }
    # Typed .NET TLS callbacks run without a PowerShell runspace on the TLS
    # worker thread. A PowerShell script-block callback is not portable there.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
public static class CSASimpleTransport {
    public static string Correlation = "", Reason = "", Stage = "CONNECTION_TLS";
    public static void Report(string url,string pin,byte[] body) {
        try {
            HttpWebRequest request=(HttpWebRequest)WebRequest.Create(url);
            request.Method="POST";request.ContentType="application/json";request.ContentLength=body.Length;
            request.Timeout=3000;request.ReadWriteTimeout=3000;request.AllowAutoRedirect=false;request.KeepAlive=false;
            request.ServerCertificateValidationCallback=(s,c,ch,e)=>{
                if(c==null)return false;
                using(SHA256 h=SHA256.Create())return "sha256:"+BitConverter.ToString(h.ComputeHash(c.GetRawCertData())).Replace("-", "").ToLowerInvariant()==pin;
            };
            using(Stream stream=request.GetRequestStream())stream.Write(body,0,body.Length);
            using(WebResponse response=request.GetResponse()){}
            request.Abort();
        }catch{} // Preserve the original local diagnostic if Lab is unreachable.
    }
    public static int Download(string url, string pin, string target, string expected) {
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        request.AllowAutoRedirect = false; request.Timeout = 15000; request.ReadWriteTimeout = 10000;
        request.KeepAlive = false;
        request.ServerCertificateValidationCallback = (sender, certificate, chain, errors) => {
            if (certificate == null) { Reason="TLS_CERTIFICATE_MISSING"; return false; }
            using (SHA256 hash=SHA256.Create()) {
                string actual="sha256:"+BitConverter.ToString(hash.ComputeHash(certificate.GetRawCertData())).Replace("-", "").ToLowerInvariant();
                if (actual!=pin) { Reason="TLS_PIN_MISMATCH"; return false; }
            }
            using (X509Certificate2 cert=new X509Certificate2(certificate)) {
                if (DateTime.UtcNow < cert.NotBefore.ToUniversalTime() || DateTime.UtcNow > cert.NotAfter.ToUniversalTime()) {
                    Reason="TLS_CERTIFICATE_EXPIRED"; return false;
                }
            }
            return true;
        };
        try {
            using (HttpWebResponse response=(HttpWebResponse)request.GetResponse()) {
                Correlation=response.Headers["X-CSA-Correlation-ID"] ?? "";
                if (response.StatusCode!=HttpStatusCode.OK) { Reason="HTTP_REDIRECT_OR_REJECTION"; return 1; }
                Stage="PACKAGE_INTEGRITY";
                if(response.ContentLength<=0 || response.ContentLength>67108864) { Reason="PACKAGE_SIZE";return 1; }
                using(Stream input=response.GetResponseStream())
                using(FileStream output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None))
                using(SHA256 hash=SHA256.Create()) {
                    byte[] buffer=new byte[65536];long total=0;int count;Stopwatch watch=Stopwatch.StartNew();
                    while((count=input.Read(buffer,0,buffer.Length))>0) {
                        total+=count;
                        if(total>response.ContentLength || watch.Elapsed.TotalSeconds>60) { Reason="TRANSFER_LIMIT"; return 1; }
                        output.Write(buffer,0,count);hash.TransformBlock(buffer,0,count,buffer,0);
                    }
                    hash.TransformFinalBlock(new byte[0],0,0);
                    if(total!=response.ContentLength) { Reason="TRANSFER_INTERRUPTED"; return 1; }
                    if("sha256:"+BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant()!=expected) { Reason="PACKAGE_HASH_MISMATCH";return 1; }
                }
            }
            return 0;
        } catch(WebException error) {
            HttpWebResponse response=error.Response as HttpWebResponse;
            if(response!=null) {
                using(response) {
                    Correlation=response.Headers["X-CSA-Correlation-ID"]??"";Stage="AUTHORIZATION";
                    Reason="HTTP_"+((int)response.StatusCode).ToString();
                    if(response.ContentLength>0 && response.ContentLength<=4096) {
                        using(StreamReader reader=new StreamReader(response.GetResponseStream())) {
                            char[] buffer=new char[4096];int count=reader.ReadBlock(buffer,0,(int)response.ContentLength);
                            var match=System.Text.RegularExpressions.Regex.Match(new string(buffer,0,count),@"""reason""\s*:\s*""([A-Z0-9_-]+)""");
                            if(match.Success)Reason=match.Groups[1].Value;
                        }
                    }
                    if(Reason.Contains("INTEGRITY"))Stage="PACKAGE_INTEGRITY";
                }
            } else if(String.IsNullOrEmpty(Reason)) { Reason="CONNECTION_"+error.Status.ToString().ToUpperInvariant(); }
            return 1;
        } finally { request.Abort(); }
    }
    public static int Run(string path, string expected) {
        Stage="PACKAGE_INTEGRITY";
        using(FileStream lease=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            using(SHA256 hash=SHA256.Create()) {
                if("sha256:"+BitConverter.ToString(hash.ComputeHash(lease)).Replace("-", "").ToLowerInvariant()!=expected) {
                    Reason="PACKAGE_HASH_MISMATCH";return 1;
                }
            }
            Stage="APPLICATION_CONTROL";
            ProcessStartInfo info=new ProcessStartInfo(path,"--quick-run");
            info.UseShellExecute=false;info.RedirectStandardOutput=true;info.RedirectStandardError=true;info.RedirectStandardInput=true;info.CreateNoWindow=true;
            using(Process process=new Process()) {
                process.StartInfo=info;
                process.OutputDataReceived+=(s,e)=>{if(e.Data!=null){
                    if(e.Data.IndexOf("Collection completed",StringComparison.OrdinalIgnoreCase)>=0) Stage="EVIDENCE_SUBMISSION";
                    Console.WriteLine(e.Data);
                }};
                process.ErrorDataReceived+=(s,e)=>{if(e.Data!=null){
                    if(e.Data.Contains("CSA-PILOT-STANDARD-USER") || e.Data.Contains("CSA-TRUST-GPO")) Stage="APPLICATION_CONTROL";
                    else if(e.Data.Contains("CSA-PILOT-SOURCE") || e.Data.Contains("CSA-TRUST-EXPIRED") || e.Data.Contains("CSA-TRUST-REPLAY")) Stage="AUTHORIZATION";
                    else if(e.Data.Contains("CSA-TRUST-") || e.Data.Contains("CSA-PILOT-APPROVAL")) Stage="PACKAGE_INTEGRITY";
                    var diagnostic=System.Text.RegularExpressions.Regex.Match(e.Data,@"CSA-[A-Z0-9_-]+");
                    if(diagnostic.Success)Reason=diagnostic.Value.Substring(4);
                    Console.Error.WriteLine(e.Data);
                }};
                try { process.Start(); }
                catch(System.ComponentModel.Win32Exception error) { Reason="WINDOWS_ERROR_"+error.NativeErrorCode.ToString();return 1; }
                process.StandardInput.Close();Stage="COLLECTOR_EXECUTION";process.BeginOutputReadLine();process.BeginErrorReadLine();
                process.WaitForExit();
                if(process.ExitCode!=0 && String.IsNullOrEmpty(Reason)) Reason="COLLECTOR_EXIT_"+process.ExitCode.ToString();
                return process.ExitCode;
            }
        }
    }
}
'@
    $stage='CONNECTION_TLS'
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    $root=Join-Path ([IO.Path]::GetTempPath()) ('CSA-Quick-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
    $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    [IO.Directory]::SetAccessControl($root,$acl)
    $file=Join-Path $root 'CSA-Collector.exe'
    Write-Host 'CSA: verifying the connection and Collector package...'
    if ([CSASimpleTransport]::Download($Origin+'/api/v1/pilot-launch/'+$LaunchId+'/collector.exe',$TlsPin,$file,$ExeSha256) -ne 0) {
        $stage=[CSASimpleTransport]::Stage;$code='CSA-JOIN-'+[CSASimpleTransport]::Reason;throw $code
    }
    # Real Windows sharing/lock errors alone receive bounded retry.
    for($attempt=0;;$attempt++) {
        try { $result=[CSASimpleTransport]::Run($file,$ExeSha256);break }
        catch {
            $cause=$_.Exception
            while($cause.InnerException){$cause=$cause.InnerException}
            if(($cause.HResult -band 65535) -notin 32,33 -or $attempt -ge 6){throw}
            Write-Host 'CSA-COL-FILELOCK: Endpoint security is scanning a Collector file. Waiting...'
            Start-Sleep -Milliseconds 1000
        }
    }
    if($result -ne 0){$stage=[CSASimpleTransport]::Stage;$code='CSA-JOIN-'+[CSASimpleTransport]::Reason;throw $code}
    Write-Host 'CSA: collection and submission completed.'
    exit 0
} catch {
    if('CSASimpleTransport' -as [type]) {
        $stage=[CSASimpleTransport]::Stage
        if([CSASimpleTransport]::Reason){$code='CSA-JOIN-'+[CSASimpleTransport]::Reason}
        $correlation=[CSASimpleTransport]::Correlation
    } else {$correlation=''}
    [Console]::Error.WriteLine(($code+'; stage='+$stage+'; correlation='+$correlation+'. Contact the assessor. Windows security controls remain enforced.'))
    if('CSASimpleTransport' -as [type]) {
        $diagnostic=@{stage=$stage;code=$code;correlationId=$correlation} | ConvertTo-Json -Compress
        [CSASimpleTransport]::Report($Origin+'/api/v1/pilot-launch/'+$LaunchId+'/diagnostic',$TlsPin,[Text.Encoding]::UTF8.GetBytes($diagnostic))
    }
    exit 1
} finally {
    if($root -and [IO.Directory]::Exists($root)) {
        for($attempt=0;$attempt -lt 6;$attempt++) {
            try{[IO.Directory]::Delete($root,$true);break}catch{if($attempt -eq 5){[Console]::Error.WriteLine('CSA-BOOT-CLEANUP: Temporary Collector files remain; contact the assessor.')};Start-Sleep -Milliseconds 500}
        }
    }
}
