"""Opt-in live-provider recovery check against an actual packaged Windows Lab.

Use a PRIVATE test data root previously populated by Test-PackagedCustomerJourney.
This deliberately terminates only its own test process to simulate interruption.
It never imports application modules or substitutes the packaged NVD transport.
Keep the data root, logs, checkpoints and generated reports out of Git/CI uploads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', required=True)
    parser.add_argument('--data-root', required=True)
    parser.add_argument('--execute', action='store_true', help='Authorize live NVD requests on this private test data')
    args = parser.parse_args()
    if not args.execute:
        parser.error('--execute is required for the live-provider check')
    root = Path(args.data_root).resolve()
    assessments = [p.parent for p in root.glob('*/lab-state.json')]
    if len(assessments) != 1:
        raise ValueError('Use an isolated test data root containing exactly one assessment')
    assessment = assessments[0]
    api = '/api/v1/assessments/' + assessment.name
    env = dict(os.environ)
    env.pop('PSModulePath', None)
    env['CSA_CVE_PRODUCT_DEADLINE_SECONDS'] = '2'
    child = None
    origin = csrf = None
    latencies = []

    def accepted_hashes():
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (assessment/'submissions'/'accepted').glob('*') if p.is_file()}

    def start():
        nonlocal child, origin, csrf
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        origin = 'http://127.0.0.1:' + str(port)
        child = subprocess.Popen([str(Path(args.executable).resolve()), '--no-browser',
            '--admin-port', str(port), '--data-root', str(root)], env=env,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for _ in range(160):
            if child.poll() is not None:
                raise AssertionError('Packaged Lab exited before becoming ready')
            try:
                page = requests.get(origin, timeout=2)
                csrf = re.search(r'name="csa-csrf" content="([^\"]+)"', page.text).group(1)
                return
            except (requests.RequestException, AttributeError):
                time.sleep(.25)
        raise AssertionError('Packaged Lab startup timed out')

    def get(path):
        started = time.monotonic()
        response = requests.get(origin+path, timeout=5)
        latencies.append(time.monotonic()-started)
        assert response.status_code == 200, 'Packaged read API refused'
        return response.json()

    def post(path, data=None):
        response = requests.post(origin+path, json=data or {},
            headers={'X-CSA-Lab-CSRF': csrf}, timeout=30)
        assert response.status_code in (200, 201, 202), 'Packaged action refused'
        return response.json()

    def progress():
        return get(api+'/cve-analysis-status')['progress']

    def wait_for(predicate, timeout=40):
        until = time.monotonic()+timeout
        while time.monotonic() < until:
            value = progress()
            if predicate(value):
                return value
            assert value['state'] not in {'FAILED', 'COMPLETED'}, 'Test job ended before the intended checkpoint'
            get('/api/v1/heartbeat')
            time.sleep(.15)
        raise AssertionError('Packaged CVE state timed out')

    def cancel():
        started = time.monotonic()
        value = post(api+'/cve-analysis-cancel')['progress']
        assert value['state'] in {'CANCELLING', 'CANCELLED'}
        result = wait_for(lambda p: p['state'] == 'CANCELLED', timeout=12)
        return time.monotonic()-started, result

    def incomplete_report():
        result = post(api+'/report', {'allowWithoutCve': True})
        response = requests.get(origin+result['reportUrl'], timeout=30)
        assert response.status_code == 200 and '<!doctype html>' in response.text.lower()
        assert any(word in response.text.lower() for word in ('incomplete', 'cancelled', 'partial'))

    before = accepted_hashes()
    assert before, 'No accepted evidence in private test assessment'
    try:
        start()
        configured = get('/api/v1/nvd-settings')
        assert configured['savedKey'], 'Provision the existing encrypted user-store key in the private test root'
        probe = post('/api/v1/nvd-settings', {'action': 'test'})
        assert probe['connection'] == 'SUCCESS', 'Live NVD connection probe failed'
        post(api+'/cve-analysis')
        observed = wait_for(lambda p: bool(p.get('provider')) and
            bool(list(assessment.rglob('*.cve-checkpoint.json'))))
        cancel_seconds, _ = cancel()
        incomplete_report()
        checkpoints = list(assessment.rglob('*.cve-checkpoint.json'))
        assert checkpoints and all(json.loads(p.read_bytes())['summary']['scan_complete'] is False for p in checkpoints)
        post(api+'/cve-analysis')
        wait_for(lambda p: bool(p.get('provider')))
        # Terminate this helper's own isolated process, never a user's open Lab.
        child.kill()
        child.wait(timeout=20)
        start()
        recovered = progress()
        assert recovered['state'] == 'INTERRUPTED' and recovered['result'] == 'PARTIAL'
        incomplete_report()
        post(api+'/cve-analysis')
        wait_for(lambda p: bool(p.get('provider')))
        resumed_cancel_seconds, _ = cancel()
        incomplete_report()
        assert accepted_hashes() == before, 'Accepted evidence changed during CVE recovery'
        assert max(latencies) < 5, 'Local read API was unresponsive'
        summary = dict(actualPackagedCve=True, liveNvdConnection=True,
            encryptedKeyConfigured=True, checkpointFiles=len(checkpoints),
            cancellationSeconds=round(cancel_seconds, 3), resumedCancellationSeconds=round(resumed_cancel_seconds, 3),
            maxReadApiSeconds=round(max(latencies), 3), unexpectedShutdownRecovered=True,
            incompleteHtmlReport=True, acceptedEvidenceUnchanged=True,
            providerStageObserved=bool(observed.get('provider')), freshEndpoint=False,
            pmLiveAcceptance='PENDING', publicRelease='HOLD')
        (root.parent/'cve-recovery-summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        print(json.dumps(summary))
    finally:
        if child is not None and child.poll() is None:
            try:
                post('/api/v1/shutdown')
                child.wait(timeout=20)
            except (requests.RequestException, subprocess.TimeoutExpired):
                child.kill()
                child.wait(timeout=20)


if __name__ == '__main__':
    main()
