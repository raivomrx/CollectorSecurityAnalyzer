"""One-file bootstrap transport: real TLS, safe extraction and shared submission."""
from __future__ import annotations

import base64
from datetime import timedelta
from dataclasses import replace
import hashlib
import http.server
import socket
import ssl
import threading
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import urljoin
import zipfile

import requests

from csa_console.canonical import sha256_file
from csa_console.enums import SessionStatus
from csa_console.identifiers import utc_text, utc_now
from csa_console.portal import PortalBinding
from csa_lab.collector_executable import read_bound_collector_payload
from csa_lab.collector_launcher import build_powershell_launcher, TEMPLATE
from csa_lab.firewall import NullFirewallManager
from csa_lab.models import AssessmentWizardRequest
from csa_lab.service import LabApplicationService
from tests.test_lab_sprint51 import _free_port
from tests.test_console_sprint5 import Sprint5TestCase

ROOT = Path(__file__).resolve().parents[1]


def decode_binding(launcher):
    match = re.search(r"\$embeddedBinding = '([A-Za-z0-9+/=]+)'", launcher.decode('utf-8-sig'))
    if not match:
        raise AssertionError('Generated launcher binding is missing')
    return json.loads(base64.b64decode(match[1]))


class LauncherCase(unittest.TestCase):
    def setUp(self):
        signing_environment = mock.patch.dict(os.environ, {'CSA_LAUNCHER_SIGNING_THUMBPRINT':''})
        signing_environment.start()
        self.addCleanup(signing_environment.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        bootstrap = self.root / 'bootstrap.exe'
        bootstrap.write_bytes(b'MZ'+bytes(range(128)))
        self.service = LabApplicationService(self.root/'assessments', firewall=NullFirewallManager(), collector_bootstrap=bootstrap)
        self.addCleanup(self.service.shutdown)

    def create(self, synthetic=False):
        request = AssessmentWizardRequest(name='Synthetic launcher acceptance', organization='DEMO', expected_endpoints=1,
            source_subnet='127.0.0.0/8', network_profile='Private', listener_address='127.0.0.1', listener_port=_free_port())
        if synthetic:
            source = self.root/'synthetic-engine'
            shutil.copytree(ROOT/'collector/windows', source)
            fixture = Sprint5TestCase().evidence()
            fixture['collectorVersion'] = '5.6.2'
            fixture['collectorBuildDigest'] = ''
            fixture['collectorBuildCommit'] = ''
            encoded = base64.b64encode(json.dumps(fixture).encode()).decode()
            (source/'Collect-CSAWindowsEvidence.ps1').write_text('''param($OutputPath,$PrivacyMode,$CollectionMode,$CapabilityRegistryPath,$CollectionProfilePath,$CollectorBuildDigest,$CollectorBuildCommit)
$data = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+"'"+encoded+"'"+''')) | ConvertFrom-Json
$data.collectorBuildDigest = $CollectorBuildDigest
$data.collectorBuildCommit = $CollectorBuildCommit
[IO.File]::WriteAllText($OutputPath, ($data | ConvertTo-Json -Depth 32 -Compress), [Text.UTF8Encoding]::new($false))
''', encoding='utf-8-sig')
            (source/'modules/General.psm1').write_text('''function Get-CSAExecutionTokenContext {
    param($PrivacyMode)
    return @{ isElevated=$false; integrityLevel='MEDIUM'; executionMode='STANDARD_USER'; isLocalAdministratorMember=$false }
}
Export-ModuleMember -Function Get-CSAExecutionTokenContext
''',encoding='utf-8-sig')
            with mock.patch('csa_console.collector_package.COLLECTOR_SOURCE', source):
                state = self.service.create_assessment(request)
        else:
            state = self.service.create_assessment(request)
        self.state = self.service.start_collection(state.assessment_id)
        self.session = self.service.sessions.load_session(state.assessment_id,state.session_id)
        self.url = self.service.portal_url(state.assessment_id)
        return self.state

    def download(self):
        response = requests.get(urljoin(self.url,'download-launcher'),verify=self.session.tls_certificate_path,timeout=10)
        self.assertEqual(response.status_code,200)
        self.launcher = self.root/'Start-CSACollector.ps1'
        self.launcher.write_bytes(response.content)
        return decode_binding(response.content)


class LauncherPortalTests(LauncherCase):
    def test_join_offers_three_transports_and_launcher_uses_header_only_download(self):
        self.create()
        page = requests.get(self.url,verify=self.session.tls_certificate_path,timeout=5)
        for label in ['CSA Collector (.exe)', 'PowerShell Quick Start (.ps1)', 'PowerShell Offline Package (.zip)']:
            self.assertIn(label,page.text)
        self.assertNotIn('ExecutionPolicy Bypass',page.text)
        binding = self.download()
        self.assertEqual(binding['assessmentId'], self.state.assessment_id)
        self.assertEqual(binding['sessionId'],self.state.session_id)
        self.assertEqual(binding['serverCertificateFingerprint'],self.session.tls_fingerprint)
        self.assertEqual(binding['packageDigest'],'sha256:'+hashlib.sha256(read_bound_collector_payload(self.state.collector_path)).hexdigest())
        self.assertFalse(binding['downloadCredential'] in page.text)
        config = json.loads((Path(self.state.collector_path).parent/'package/session-config.json').read_text())
        self.assertFalse(config['enrollmentToken'] in self.launcher.read_text(encoding='utf-8-sig'))
        endpoint = binding['serverUrl']+'/api/v1/collector-package'
        self.assertNotIn('?',endpoint)
        self.assertFalse(binding['downloadCredential'] in endpoint)
        response = requests.post(endpoint,headers={'Authorization':'CSA-Launcher '+binding['downloadCredential']},
                                 verify=self.session.tls_certificate_path,timeout=10)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.content,read_bound_collector_payload(self.state.collector_path))
        self.assertEqual(self.service.load_state(self.state.assessment_id).download_count,2)
        audit = self.service.storage.path(self.state.assessment_id,'audit','audit.jsonl').read_text()
        self.assertFalse(binding['downloadCredential'] in audit)
        self.assertFalse(config['enrollmentToken'] in audit)

    def test_missing_wrong_paused_expired_or_budget_exhausted_download_fails(self):
        self.create()
        binding = self.download()
        endpoint = binding['serverUrl']+'/api/v1/collector-package'
        def post(credential):
            return requests.post(endpoint,headers={'Authorization':'CSA-Launcher '+credential},verify=self.session.tls_certificate_path,timeout=5)
        self.assertEqual(post('').status_code,403)
        self.assertEqual(post('invalid').status_code,403)
        self.service.sessions.set_session_status(self.state.assessment_id,self.state.session_id,SessionStatus.PAUSED)
        self.assertEqual(post(binding['downloadCredential']).status_code,403)
        self.service.sessions.set_session_status(self.state.assessment_id,self.state.session_id,SessionStatus.OPEN)
        with mock.patch('csa_console.portal.PortalBinding._authorize_session',return_value=False):
            self.assertEqual(post(binding['downloadCredential']).status_code,403)
        closed = replace(self.session, status=SessionStatus.CLOSED)
        with mock.patch('csa_console.portal.AssessmentSessionService.load_session',return_value=closed):
            self.assertEqual(post(binding['downloadCredential']).status_code,403)

    def test_same_source_expiry_and_download_budget_apply_to_launcher_credentials(self):
        self.create()
        binding = self.download()
        portal = PortalBinding(assessment_id=self.state.assessment_id, session_id=self.state.session_id,
            join_code_hash='unused', collector_path=Path(self.state.collector_path), expires_at=self.state.expires_at,
            maximum_downloads=1, storage=self.service.storage,
            launcher_token_hash=hashlib.sha256(binding['downloadCredential'].encode()).hexdigest())
        credential = binding['downloadCredential']
        self.assertTrue(portal.authorize_launcher(credential,'127.0.0.1'))
        self.assertFalse(portal.authorize_launcher(credential,'203.0.113.10'))
        portal.expires_at=utc_text(utc_now()-timedelta(seconds=1))
        self.assertFalse(portal.authorize_launcher(credential,'127.0.0.1'))
        portal.expires_at=self.state.expires_at
        portal.record_download('127.0.0.1')
        self.assertFalse(portal.authorize_launcher(credential,'127.0.0.1'))
        self.assertFalse(credential in repr(portal))

    def test_configured_signer_failure_does_not_fall_back_to_unsigned(self):
        self.create()
        archive=Path(self.state.collector_path).with_name('CSA-PowerShell-Collector.zip')
        with mock.patch.dict(os.environ,{'CSA_LAUNCHER_SIGNING_THUMBPRINT':'a'*40}), mock.patch(
                'csa_lab.collector_launcher._sign_launcher',side_effect=ValueError('Synthetic signing unavailable')):
            with self.assertRaisesRegex(ValueError,'signing unavailable'):
                build_powershell_launcher(archive,self.session,f'https://127.0.0.1:{self.state.listener_port}','e'*43,self.root/'signing')

    def test_launcher_credential_rotates_on_listener_restart(self):
        self.create()
        old = self.download()
        self.service.pause_collection(self.state.assessment_id)
        self.service.resume_collection(self.state.assessment_id)
        new = self.download()
        self.assertNotEqual(old['downloadCredential'],new['downloadCredential'])
        response = requests.post(old['serverUrl']+'/api/v1/collector-package',headers={'Authorization':'CSA-Launcher '+old['downloadCredential']},verify=self.session.tls_certificate_path,timeout=5)
        self.assertEqual(response.status_code,403)

    def test_tampered_zip_is_not_bound_into_a_new_launcher(self):
        state = self.service.create_assessment(AssessmentWizardRequest(name='Synthetic',expected_endpoints=1,
            listener_address='127.0.0.1',listener_port=_free_port(),source_subnet='127.0.0.0/8',network_profile='Private'))
        Path(state.collector_path).with_name('CSA-PowerShell-Collector.zip').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'transport package mismatch'):
            self.service.start_collection(state.assessment_id)


@unittest.skipUnless(os.name=='nt','Windows PowerShell and Windows sharing violations required')
class LauncherWindowsTests(LauncherCase):
    def run_ps(self, mode, binding, payload=None, target=None, timeout=60):
        binding_path = self.root/'binding.json'
        binding_path.write_text(json.dumps(binding),encoding='utf-8')
        harness = self.root/'harness.ps1'
        harness.write_text('''param($Template,$Mode,$BindingPath,$Payload,$Target,$Launcher)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Template,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Launcher syntax failed' }
foreach($node in $ast.EndBlock.Statements) {
 if($node -is [Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
}
$binding=Get-Content -LiteralPath $BindingPath -Raw | ConvertFrom-Json
try {
 if($Mode -eq 'expand') { Expand-CSABootstrapPackage ([IO.File]::ReadAllBytes($Payload)) $binding $Target }
 elseif($Mode -eq 'receive') { $bytes=Receive-CSABootstrapPackage $binding; Write-Output ('Downloaded bytes: '+$bytes.Length) }
 elseif($Mode -eq 'signature') { Test-CSABootstrapSignature $Payload }
 elseif($Mode -eq 'binding') { Test-CSABootstrapBinding $binding }
 elseif($Mode -eq 'bootstrap') {
   # Synthetic-collection integration on elevated hosted runners. The real
   # production privilege gate is tested separately and has no bypass switch.
   function Test-CSABootstrapPrivilege { }
   $result=Invoke-CSABootstrap -Binding $binding -LauncherPath $Launcher
   exit $result
 }
 elseif($Mode -eq 'privilege') { Test-CSABootstrapPrivilege }
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
''',encoding='utf-8-sig')
        return subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(harness),
            str(TEMPLATE),mode,str(binding_path),str(payload or ''),str(target or ''),str(getattr(self,'launcher',TEMPLATE))],
            capture_output=True,text=True,timeout=timeout)

    def archive(self):
        return Path(self.state.collector_path).with_name('CSA-PowerShell-Collector.zip')

    def test_pinned_download_and_whole_launcher_with_synthetic_shared_engine_submission(self):
        self.create(synthetic=True)
        binding = self.download()
        receive = self.run_ps('receive',binding)
        self.assertEqual(receive.returncode,0,receive.stderr)
        before = set(Path(tempfile.gettempdir()).glob('CSA-Launcher-*'))
        result = self.run_ps('bootstrap',binding,timeout=120)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Submission accepted',result.stdout)
        self.assertIn('Bootstrap temporary files removed: YES',result.stdout)
        self.assertFalse(binding['downloadCredential'] in result.stdout+result.stderr)
        self.assertEqual(before,set(Path(tempfile.gettempdir()).glob('CSA-Launcher-*')))
        submissions = self.service.submissions.list_submissions(self.state.assessment_id)
        self.assertEqual(len(submissions),1)
        analysis = self.service.storage.read_json(self.state.assessment_id,'findings',submissions[0]['submissionId']+'.json')
        self.assertTrue(analysis['findings'])

    def test_rejected_shared_engine_exit_is_not_reported_as_success(self):
        self.create(synthetic=True)
        binding=self.download()
        original = PortalBinding.authorize_launcher
        def pause_after_download_authorization(portal, credential, source):
            allowed = original(portal, credential, source)
            if allowed:
                self.service.sessions.set_session_status(self.state.assessment_id,self.state.session_id,SessionStatus.PAUSED)
            return allowed
        with mock.patch.object(PortalBinding,'authorize_launcher',new=pause_after_download_authorization):
            result=self.run_ps('bootstrap',binding)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('Submission accepted',result.stdout)
        self.assertIn('CSA-BOOT-COLLECTOR',result.stderr)
        self.assertIn('Bootstrap temporary files removed: YES',result.stdout)
        self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])
        self.service.sessions.set_session_status(self.state.assessment_id,self.state.session_id,SessionStatus.OPEN)

    def test_wrong_pin_network_loss_and_expiry_fail_without_execution(self):
        self.create()
        binding = self.download()
        wrong = dict(binding,serverCertificateFingerprint='sha256:'+'0'*64)
        self.assertIn('CSA-BOOT-TLS',self.run_ps('receive',wrong).stderr)
        offline = dict(binding,serverUrl='https://127.0.0.1:'+str(_free_port()))
        self.assertIn('CSA-BOOT-NETWORK',self.run_ps('receive',offline).stderr)
        expired = dict(binding,expiration=utc_text(utc_now()-timedelta(seconds=1)))
        self.assertIn('CSA-BOOT-EXPIRED',self.run_ps('binding',expired).stderr)

    def test_interrupted_tls_download_is_recoverable_without_partial_execution(self):
        self.create()
        binding=self.download()
        expected_size=binding['packageSize']
        class Interrupted(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.send_header('Content-Type','application/zip')
                self.send_header('Content-Length',str(expected_size))
                self.end_headers()
                self.wfile.write(b'PK')
                self.wfile.flush()
                self.close_connection=True
                self.connection.shutdown(socket.SHUT_RDWR)
            def log_message(self,*args):
                pass
        server=http.server.HTTPServer(('127.0.0.1',0),Interrupted)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.session.tls_certificate_path,self.session.tls_private_key_path)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            interrupted=dict(binding,serverUrl='https://127.0.0.1:'+str(server.server_port))
            result=self.run_ps('receive',interrupted)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('CSA-BOOT-NETWORK',result.stderr)
            self.assertFalse(binding['downloadCredential'] in result.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_archive_and_manifest_tampering_fail_closed(self):
        self.create()
        binding = self.download()
        target = self.root/'extracted'
        target.mkdir()
        initial = self.run_ps('expand',binding,self.archive(),target)
        self.assertEqual(initial.returncode,0,initial.stdout+initial.stderr)
        tampered = self.root/'tampered.zip'
        tampered.write_bytes(self.archive().read_bytes()+b'altered')
        bad_target = self.root/'bad-extracted'
        bad_target.mkdir()
        self.assertIn('CSA-BOOT-DIGEST',self.run_ps('expand',binding,tampered,bad_target).stderr)
        self.assertEqual(list(bad_target.iterdir()),[])
        with zipfile.ZipFile(self.archive()) as archive:
            files = {name:archive.read(name) for name in archive.namelist()}
        files['trusted-manifest.json'] += b' '
        with zipfile.ZipFile(tampered,'w') as archive:
            for name,data in files.items(): archive.writestr(name,data)
        rebound = dict(binding,packageDigest=sha256_file(tampered))
        self.assertIn('CSA-BOOT-MANIFEST',self.run_ps('expand',rebound,tampered,bad_target).stderr)
        self.assertEqual(list(bad_target.iterdir()),[])

        # Rebind the archive digest only: entry hashing must independently
        # reject changed executable bytes against the original trusted manifest.
        with zipfile.ZipFile(self.archive()) as archive:
            files={name:archive.read(name) for name in archive.namelist()}
        original=files['collector/modules/General.psm1']
        files['collector/modules/General.psm1']=bytes([original[0]^1])+original[1:]
        with zipfile.ZipFile(tampered,'w') as archive:
            for name,data in files.items(): archive.writestr(name,data)
        entry_target=self.root/'entry-tamper'
        entry_target.mkdir()
        rebound=dict(binding,packageDigest=sha256_file(tampered))
        self.assertIn('CSA-BOOT-DIGEST',self.run_ps('expand',rebound,tampered,entry_target).stderr)

    def test_unsafe_duplicate_and_undeclared_paths_fail_before_writes(self):
        self.create()
        binding = self.download()
        for path in ['../escape.ps1','C:/escape.ps1','collector/modules/CON.psm1','session-config.json']:
            with self.subTest(path=path):
                output = self.root/'unsafe.zip'
                with zipfile.ZipFile(self.archive()) as source, zipfile.ZipFile(output,'w') as archive:
                    for item in source.infolist(): archive.writestr(item,source.read(item))
                    # Avoid Python's duplicate-name warning while testing the
                    # Windows case-insensitive inventory collision.
                    archive.writestr(path.upper() if path=='session-config.json' else path,b'unsafe')
                rebound = dict(binding,packageDigest=sha256_file(output))
                target = self.root/('unsafe-'+str(len(path)))
                target.mkdir(exist_ok=True)
                result = self.run_ps('expand',rebound,output,target)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(list(target.iterdir()),[])

    def test_signature_claim_with_invalid_signature_is_rejected(self):
        script = self.root/'invalid.ps1'
        script.write_text('# SIG # Begin signature block\n# invalid signature\n# SIG # End signature block\n',encoding='utf-8-sig')
        result = self.run_ps('signature',{},payload=script)
        self.assertIn('CSA-BOOT-SIGNATURE',result.stderr)

    def test_signature_scan_waits_for_a_real_several_second_module_lock(self):
        script = self.root/'locked.psm1'
        script.write_text('# synthetic unsigned module\n')
        ready = self.root/'lock-ready'
        child = subprocess.Popen([sys.executable,str(ROOT/'tests/fixtures/hold_collector_file.py'),str(script),str(ready),'3'])
        try:
            deadline=time.monotonic()+10
            while not ready.exists() and time.monotonic()<deadline: time.sleep(.01)
            self.assertTrue(ready.exists())
            result=self.run_ps('signature',{},payload=script)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('TRANSIENT_FILE_LOCK',result.stdout)
        finally:
            if child.poll() is None: child.terminate()
            child.wait(timeout=5)

    def test_persistent_scanner_lock_fails_closed_after_bounded_wait(self):
        script=self.root/'persistent.psm1'
        script.write_text('# synthetic unsigned module\n')
        ready=self.root/'persistent-ready'
        child=subprocess.Popen([sys.executable,str(ROOT/'tests/fixtures/hold_collector_file.py'),str(script),str(ready),'60'])
        try:
            deadline=time.monotonic()+10
            while not ready.exists() and time.monotonic()<deadline: time.sleep(.01)
            self.assertTrue(ready.exists())
            started=time.monotonic()
            result=self.run_ps('signature',{},payload=script,timeout=35)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('CSA-BOOT-FILELOCK',result.stderr)
            self.assertLess(time.monotonic()-started,25)
        finally:
            if child.poll() is None: child.terminate()
            child.wait(timeout=5)
