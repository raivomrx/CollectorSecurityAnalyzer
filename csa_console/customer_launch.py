"""Small customer page and fixed, independently hash-pinned transport bootstrap."""
import base64
import html
import json
import re

from csa_console.collector_package import COLLECTOR_VERSION


def commands(view):
    if view.get("singleFile"):
        return single_file_commands(view)
    for field in ("archiveSha256","approvalSha256","exeSha256","tlsFingerprint","bootstrapSha256"):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}",view[field]):
            raise ValueError("CSA-JOIN-IDENTITY")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}",view["handoffId"]) or not re.fullmatch(r"https://[a-zA-Z0-9.\[\]:-]+",view["origin"]):
        raise ValueError("CSA-JOIN-SCOPE")
    result={}
    for mode in ("Quick","Standard"):
        # Fixed local verifier download; no credential in the command. Its exact
        # hash and TLS pin were approved in the independent assessor handoff.
        args=" ".join("-"+name+" '"+view[key]+"'" for name,key in (
            ("Origin","origin"),("LaunchId","handoffId"),("TlsPin","tlsFingerprint"),
            ("ArchiveSha256","archiveSha256"),("ApprovalSha256","approvalSha256"),("ExeSha256","exeSha256")))
        script=("$ErrorActionPreference='Stop';[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
            "$p=Join-Path ([IO.Path]::GetTempPath()) ('CSA-start-'+[Guid]::NewGuid().ToString('N')+'.ps1');$f=$null;try{"
            "$r=[Net.HttpWebRequest]::Create('"+view["origin"]+"/api/v1/pilot-launch/"+view["handoffId"]+"/bootstrap.ps1');"
            "$r.AllowAutoRedirect=$false;$r.Timeout=15000;$r.ReadWriteTimeout=15000;"
            "$r.ServerCertificateValidationCallback={param($s,$c,$ch,$e)if(!$c){return $false};$h=[Security.Cryptography.SHA256]::Create();"
            "try{return ('sha256:'+([BitConverter]::ToString($h.ComputeHash($c.GetRawCertData()))).Replace('-','').ToLowerInvariant()) -ceq '"+
            view["tlsFingerprint"]+"'}finally{$h.Dispose()}};"
            "$a=$r.GetResponse();try{if($a.ContentLength -lt 0 -or $a.ContentLength -gt 65536){throw 'CSA-JOIN-SIZE'};"
            "$m=New-Object IO.MemoryStream;try{$a.GetResponseStream().CopyTo($m);$b=$m.ToArray()}finally{$m.Dispose()}}finally{$a.Dispose()};"
            "$h=[Security.Cryptography.SHA256]::Create();try{$d='sha256:'+([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant()}"
            "finally{$h.Dispose()};if($d -cne '"+view["bootstrapSha256"]+"'){throw 'CSA-JOIN-BOOTSTRAP-HASH'};"
            "$w=[IO.File]::Open($p,'CreateNew','Write','None');try{$w.Write($b,0,$b.Length)}finally{$w.Dispose()};"
            "$f=[IO.File]::Open($p,'Open','Read','Read');"
            # Recheck leased bytes so replacing the temporary script cannot win a race.
            "$h=[Security.Cryptography.SHA256]::Create();try{$d='sha256:'+([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}"
            "finally{$h.Dispose()};if($d -cne '"+view["bootstrapSha256"]+"'){throw 'CSA-JOIN-BOOTSTRAP-HASH'};"
            "powershell.exe -NoProfile "+("-ExecutionPolicy Bypass " if mode=="Quick" else "")+"-File $p "+args+" -Mode "+mode+
            ";exit $LASTEXITCODE}catch{[Console]::Error.WriteLine('CSA-JOIN-START-FAILED: contact the assessor.');exit 1}finally{if($f){$f.Dispose()};if([IO.File]::Exists($p)){[IO.File]::Delete($p)}}")
        result[mode.lower()]="powershell.exe -NoProfile"+(" -ExecutionPolicy Bypass" if mode=="Quick" else "")+" -EncodedCommand "+base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return result


def single_file_commands(view):
    for key in ("exeSha256","tlsFingerprint"):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}",view[key]):
            raise ValueError("CSA-JOIN-IDENTITY")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}",view["handoffId"]) or not re.fullmatch(r"https://[a-zA-Z0-9.\[\]:-]+",view["origin"]):
        raise ValueError("CSA-JOIN-SCOPE")
    # Public locator/pins only. Start Collector in the independently obtained
    # local Lab grants source/session-scoped authority. Hashes from an arbitrary
    # untrusted page are not a substitute for that assessor handoff.
    script=("$ErrorActionPreference='Stop';[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        "$p=Join-Path ([IO.Path]::GetTempPath()) ('CSA-'+[Guid]::NewGuid().ToString('N')+'.exe');$f=$null;try{"
        "$r=[Net.HttpWebRequest]::Create('"+view["origin"]+"/api/v1/pilot-launch/"+view["handoffId"]+"/collector.exe');"
        "$r.AllowAutoRedirect=$false;$r.Timeout=30000;$r.ReadWriteTimeout=30000;"
        "$r.ServerCertificateValidationCallback={param($s,$c,$ch,$e)if(!$c){return $false};$h=[Security.Cryptography.SHA256]::Create();"
        "try{return ('sha256:'+([BitConverter]::ToString($h.ComputeHash($c.GetRawCertData()))).Replace('-','').ToLowerInvariant()) -ceq '"+
        view["tlsFingerprint"]+"'}finally{$h.Dispose()}};"
        "$a=$r.GetResponse();try{if($a.ContentLength -le 0 -or $a.ContentLength -gt 67108864){throw 'CSA-JOIN-SIZE'};"
        "$w=[IO.File]::Open($p,'CreateNew','Write','None');try{$s=$a.GetResponseStream();$b=New-Object byte[] 65536;$n=0;"
        "while(($k=$s.Read($b,0,$b.Length)) -gt 0){$n+=$k;if($n -gt $a.ContentLength){throw 'CSA-JOIN-SIZE'};$w.Write($b,0,$k)};"
        "if($n -ne $a.ContentLength){throw 'CSA-JOIN-TRUNCATED'}}finally{$w.Dispose()}}finally{$a.Dispose()};"
        "for($i=0;;$i++){try{$f=[IO.File]::Open($p,'Open','Read','Read');break}catch [IO.IOException]{"
        "$e=$_.Exception.HResult -band 65535;if($e -notin 32,33 -or $i -ge 5){throw};"
        "[Console]::WriteLine('CSA-COL-FILELOCK: Endpoint security is scanning a Collector file. Waiting...');Start-Sleep -Milliseconds 1000}};"
        "$h=[Security.Cryptography.SHA256]::Create();try{$d='sha256:'+([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}"
        "finally{$h.Dispose()};if($d -cne '"+view["exeSha256"]+"'){throw 'CSA-JOIN-EXE-HASH'};"
        "& $p --quick-run;$rc=$LASTEXITCODE;exit $rc}catch{[Console]::Error.WriteLine('CSA-JOIN-START-FAILED: Verification, connection or Windows policy stopped execution. Contact the assessor.');exit 1}"
        "finally{if($f){$f.Dispose()};if([IO.File]::Exists($p)){[IO.File]::Delete($p)}}")
    return {"quick":"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "+
            base64.b64encode(script.encode("utf-16-le")).decode("ascii")}


def render(name, view=None, *, network_options=None, development=False, activation_available=False):
    escape=html.escape
    body='<p>Käivitamiseks pöördu hindaja poole.</p>'
    if view and view.get("singleFile"):
        start=commands(view)
        body=('<section><h2><span aria-hidden="true">⌘</span> PowerShell Quick Run <small>Recommended</small></h2>'
              '<p>Copy the command, paste it into PowerShell or CMD and press Enter.</p>'
              '<button type="button" data-copy-command="quick">▣ Copy Quick Run</button>'
              '<details><summary>Show command</summary><pre><code id="quick">'+escape(start["quick"])+'</code></pre></details></section>'
              '<section><h2><span aria-hidden="true">⇩</span> Windows EXE Collector</h2>'
              '<p>Download and run the Collector.</p><a class="button" href="'+escape(view["origin"]+"/api/v1/pilot-launch/"+
              view["handoffId"]+"/collector.exe",quote=True)+'">⇩ Download Collector (.exe)</a></section>')
    elif view:
        start=commands(view)
        body=('<section><h2>PowerShell Quick Run</h2><p>Kopeeri käsk Windows PowerShelli ja sisesta hindajalt saadud kood.</p>'
              '<button type="button" data-copy-command="quick">Kopeeri Quick Run</button>'
              '<details><summary>Kuva valitav käsk</summary><pre><code id="quick">'+escape(start["quick"])+'</code></pre></details></section>'
              '<section><h2>Windows EXE Collector</h2><a class="button" href="pilot-download">Laadi alla EXE pakett (.zip)</a>'
              '<p>Paki failid lahti ja ava Start-CSACollector.cmd. Pärast lõpetamist kustuta allalaaditud ZIP.</p></section>'
              '<details><summary>Tavaline PowerShell</summary><pre><code id="standard">'+escape(start["standard"])+'</code></pre>'
              '<button type="button" data-copy-command="standard">Kopeeri käsk</button></details>')
        if not view.get("allowQuick",True):
            body=('<p>Jätka allalaaditud Collectoriga. Uue käivituse jaoks pöördu hindaja poole.</p>'
                  '<a class="button" href="pilot-download">Laadi EXE pakett uuesti</a>')
    elif activation_available:
        body=('<p>Sisesta hindajalt saadud käivituskood.</p><form method="post" action="pilot-activate">'
              '<input type="password" name="code" autocomplete="off" required maxlength="128" aria-label="Käivituskood">'
              '<button type="submit">Jätka</button></form>')
    elif network_options:
        from csa_console.quick_start import quick_start_command
        body=""
        for number,option in enumerate(network_options):
            for quick in (False,True):
                identifier="trusted-command-"+str(number)+("-quick" if quick else "-standard")
                body+='<details><summary>Kuva käsk</summary><pre><code id="'+identifier+'">'+escape(quick_start_command(option["labId"],option["envelopeId"],quick_run=quick))+'</code></pre></details><button type="button" data-copy-command="'+identifier+'">'+("Kopeeri Quick Run" if quick else "Kopeeri PowerShell")+'</button>'
        body='<p>Kasuta hindaja ettevalmistatud käivitajat.</p>'+body
    elif development:
        body=('<a href="download">Hindaja arendus-EXE</a> <a href="download-powershell">PowerShelli ZIP</a> '
              '<a href="download-launcher">PowerShelli käivitaja</a><p>Kasuta ainult hindaja antud juhiseid.</p>')
    script=""
    if view or network_options:
        from csa_console.quick_start import PORTAL_SCRIPT
        script="<script>"+PORTAL_SCRIPT+"</script>"
    return ('<!doctype html><html lang="et"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>CSA Security Assessment</title><style>body{font:16px Segoe UI,sans-serif;background:#182128;color:#edf2f5;margin:0}'
        'main{box-sizing:border-box;max-width:780px;margin:4px auto;padding:20px;background:#182229;border-radius:18px}h1{font-size:21px;margin:0 0 16px}h2{font-size:16px;margin:0 0 16px}h2 span{color:#8dd9ce;margin-right:8px}h2 small{float:right;color:#00bb61;background:#10382d;padding:3px 8px;border-radius:14px;font-size:12px}'
        'section{padding:22px 0 20px;border-top:1px solid #40535b}details{padding:8px 0 0;font-size:12px}summary{cursor:pointer;color:#adbec7}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}'
        'button,.button{background:#49b9a1;color:#10251f;border:0;border-radius:5px;padding:12px;cursor:pointer;text-decoration:none}'
        'button,.button{display:block;box-sizing:border-box;width:100%;text-align:center;font:600 16px Segoe UI,sans-serif;padding:15px}.privacy,footer{color:#bfccd2;font-size:12px}.privacy{border-top:1px solid #40535b;padding-top:22px}footer{color:#819ca9}main>p{font-size:14px;margin-bottom:20px}@media(max-width:600px){main{margin:0;border-radius:0;padding:20px}h2 small{font-size:10px}}</style><main><h1>CSA Security Assessment</h1><p>Assessment: '+escape(name)+'</p>'+
        body+'<p class="privacy">No installation required. Passwords, private keys and personal documents are not collected.</p>'
        '<footer>Collector '+escape(COLLECTOR_VERSION)+'</footer></main>'+script+'</html>').encode("utf-8")
