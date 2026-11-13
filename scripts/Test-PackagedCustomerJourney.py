"""Exercise the built/installed Lab through its actual localhost HTTP API.

No source-module injection, pre-issued grants or development distribution.
--execute explicitly runs real acquisition on the current Windows host and keeps
evidence only in the specified private output root. Never upload that root.
This is engineering verification, not PM fresh HOME/LAB acceptance.
"""
import argparse
import base64
import ctypes
import hashlib
import html as html_parser
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time

import requests


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0))
        return listener.getsockname()[1]


def verify_evidence(root,identifier,certificate):
    """Check signed results and actual code bytes, excluding one-use config."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    assessment=root/"assessments"/identifier
    accepted=assessment/"submissions"/"accepted"
    documents=[json.loads(path.read_bytes()) for path in accepted.glob("*.evidence.json")]
    records=[json.loads(path.read_bytes()) for path in accepted.glob("*.trust.json")]
    assert len(documents)==len(records)==3,"Missing accepted evidence/provenance"
    assert all(document["metadata"]["privacyMode"]=="PROFILE_ENFORCED" for document in documents)
    key=x509.load_pem_x509_certificate(Path(certificate).read_bytes()).public_key()
    receipts=tuple(accepted.glob("*.receipt.json"));assert len(receipts)==3
    for path in (*receipts,*accepted.glob("*.trust.json")):
        record=json.loads(path.read_bytes());signature=record.pop("serverSignature")
        assert signature.startswith("rsa-pss-sha256:")
        key.verify(base64.b64decode(signature.split(":",1)[1]),
            json.dumps(record,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.DIGEST_LENGTH),hashes.SHA256())
    identities=set()
    for row in records:
        publisher=(assessment/"pilot-handoffs"/row["envelopeId"]/"publisher-manifest.json").read_bytes()
        assert "sha256:"+hashlib.sha256(publisher).hexdigest()==row["provenance"]["publisherManifestDigest"]
        release=json.loads(publisher)
        # collectorBuildDigest includes the private one-use session-config, so
        # it must differ between grants. Compare authenticated code artifacts.
        identities.add((release["bootstrapSha256"],release["entryPointSha256"],
            json.dumps(release["files"],sort_keys=True),row["provenance"]["profileDigest"],
            row["provenance"]["privacyPolicyDigest"]))
    assert len(identities)==1,"Transport profile/engine drift"
    return True


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--executable",required=True)
    parser.add_argument("--output",required=True)
    parser.add_argument("--execute",action="store_true")
    parser.add_argument("--browser",help="Optional headless Edge/Chrome executable for screenshot/Copy test")
    args=parser.parse_args()
    root=Path(args.output).resolve()
    if len(str(root))>100:
        raise ValueError("Use a short private Windows test root (for example C:/CSA-Test/run1); .NET Framework tooling has path-length limits.")
    root.mkdir(parents=True,exist_ok=False)
    env=dict(os.environ);env.pop("PSModulePath",None)
    port=free_port();origin="http://127.0.0.1:"+str(port)
    child=subprocess.Popen([str(Path(args.executable).resolve()),"--no-browser","--admin-port",str(port),
        "--data-root",str(root/"assessments")],env=env,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    csrf=None
    try:
        for _ in range(120):
            if child.poll() is not None:raise AssertionError("Packaged Lab exited")
            try:
                page=requests.get(origin,timeout=2)
                csrf=re.search(r'name="csa-csrf" content="([^\"]+)"',page.text).group(1)
                break
            except (requests.RequestException,AttributeError):time.sleep(.25)
        assert csrf,"Packaged Lab did not start"
        def post(path,data=None):
            response=requests.post(origin+path,json=data or {},headers={"X-CSA-Lab-CSRF":csrf},timeout=90)
            assert response.status_code in (200,201,202),"Packaged Lab action refused: "+path.rsplit("/",1)[-1]
            return response.json()
        state=post("/api/v1/assessments",dict(name="Synthetic packaged acceptance",expectedEndpoints=3,
            listenerAddress="127.0.0.1",listenerPort=free_port(),sourceSubnet="127.0.0.0/8",networkProfile="Private"))["assessment"]
        identifier=state["assessmentId"];api="/api/v1/assessments/"+identifier
        # This is the sole preparation action available to the assessor.
        post(api+"/start")
        details=requests.get(origin+api,timeout=30).json()
        assert details["collectorReadiness"]["state"]=="READY"
        url=details["portalUrl"]
        session=json.loads((root/"assessments"/identifier/"sessions"/(state["sessionId"]+".json")).read_bytes())
        certificate=session["tlsCertificatePath"]
        outcomes=[]
        for mode in (("exe","powershell","cmd") if args.execute else ("exe",)):
            page=requests.get(url,verify=certificate,timeout=90)
            assert page.status_code==200,"Actual Join refused"
            assert "Copy Quick Run" in page.text and "Download Collector (.exe)" in page.text
            assert "pöördu hindaja" not in page.text and ".zip" not in page.text
            if not (root/"join.html").is_file():(root/"join.html").write_bytes(page.content)
            if args.browser and mode=="exe":
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                cert=x509.load_pem_x509_certificate(Path(certificate).read_bytes())
                pin=base64.b64encode(hashlib.sha256(cert.public_key().public_bytes(
                    serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
                browser=subprocess.run(["node",str(Path(__file__).resolve().parents[1]/"tests/fixtures/join_browser_smoke.mjs")],
                    input=json.dumps(dict(url=url,browserPath=args.browser,profile=str(root/"browser"),pin=pin,
                        mode="start-only",screenshot=str(root/"customer-start-only.png"))),capture_output=True,text=True,timeout=60)
                assert browser.returncode==0,"Packaged browser Copy check failed"
            command=html_parser.unescape(re.search(r'<code id="quick">([^<]+)</code>',page.text).group(1))
            assert len(command)<8191 and "-ExecutionPolicy Bypass" in command
            script=command
            assert "-EncodedCommand" not in command
            config=json.loads(next((root/"assessments"/identifier/"downloads").glob("*/package/session-config.json")).read_bytes())
            assert config["enrollmentToken"] not in script
            assert all(text not in script for text in ("Read-Host","IEX","DownloadString","Set-ExecutionPolicy"))
            if mode=="exe":
                exe_url=re.search(r'href="(https://[^\"]+/collector.exe)"',page.text).group(1)
                download=requests.get(exe_url,verify=certificate,timeout=60)
                assert download.status_code==200 and download.content.startswith(b"MZ")
                assert 'filename="CSA-Collector.exe"' in download.headers["Content-Disposition"]
                executable=root/"CSA-Collector.exe";executable.write_bytes(download.content)
                assert "sha256:"+hashlib.sha256(download.content).hexdigest() in script
                launch=[str(executable)]
            else:
                launch=("cmd.exe /d /s /c "+command if mode=="cmd" else
                        ["powershell.exe","-NoProfile","-Command",command])
            if args.execute:
                run=subprocess.run(launch,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=240,env=env)
                if ctypes.windll.shell32.IsUserAnAdmin():
                    assert run.returncode!=0 and "STANDARD-USER-REQUIRED" in run.stderr,"Real elevation gate missing"
                    outcomes.append(mode+":REAL_ELEVATION_REFUSED")
                else:
                    # Keep real output private; the public result is a boolean.
                    (root/(mode+"-private.log")).write_text(run.stdout+run.stderr,encoding="utf-8")
                    assert run.returncode==0 and "Submission accepted" in run.stdout,"Collector failed; see private local log"
                    outcomes.append(mode+":RECEIPT_RECEIVED")
            else:outcomes.append("READY_AND_SINGLE_EXE_DOWNLOADED")
        post(api+"/stop")
        report=False
        parity=False
        if args.execute and not ctypes.windll.shell32.IsUserAnAdmin():
            parity=verify_evidence(root,identifier,certificate)
            # Do not pretend a live CVE lookup occurred during transport testing.
            result=post(api+"/report",{"allowWithoutCve":True})
            html=requests.get(origin+result["reportUrl"],timeout=30)
            report=html.status_code==200 and "<!doctype html>" in html.text.lower()
            assert report,"No HTML report served by packaged Lab"
        summary={"packagedStartOnly":True,"standaloneExe":True,"quickRunCopy":True,"outcomes":outcomes,
                 "htmlReport":report,"profilePrivacyParityAndSignedReceipts":parity,
                 "freshEndpoint":False,"pmLiveAcceptance":"PENDING","publicRelease":"HOLD"}
        (root/"summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
        print(json.dumps(summary))
    finally:
        if child.poll() is None and csrf:
            try:requests.post(origin+"/api/v1/shutdown",json={},headers={"X-CSA-Lab-CSRF":csrf},timeout=5)
            except requests.RequestException:pass
        try:child.wait(timeout=15)
        except subprocess.TimeoutExpired:child.terminate();child.wait(timeout=10)


if __name__=="__main__":main()
