"""Local API remains responsive during an actual blocked NVD request."""
import json
import threading
import time
import unittest
from unittest import mock
import requests

from cve.client import NvdClient
from csa_lab.web import LabAdminServer
from csa_lab.service import LabApplicationService
from csa_lab.firewall import NullFirewallManager
from tests import test_lab_sprint51 as lab_fixtures
from tests.test_nvd_client import _MemoryCache,_Response


class LabReliabilityTests(unittest.TestCase):
    setUp=lab_fixtures.LabServiceTests.setUp
    request=lab_fixtures.LabServiceTests.request

    def test_late_provider_callback_cannot_reopen_a_completed_job(self):
        state=self.service.create_assessment(self.request());callbacks=[]
        state.report_path='synthetic-prior-report.html'
        self.service._write_state(state)
        def run(_assessment_id,progress_callback=None,cancel_event=None):callbacks.append(progress_callback);return []
        with mock.patch('csa_lab.service.FleetAnalyzer.load_latest_endpoint_data',return_value=([{'submissionId':'SUB-SYNTHETIC'}],[],[])),mock.patch.object(self.service,'run_cve_analysis',side_effect=run):
            self.service.start_cve_analysis(state.assessment_id)
            self.assertEqual(self.service.load_state(state.assessment_id).report_path,'')
            for _ in range(100):
                if self.service.cve_analysis_progress(state.assessment_id)['state']=='COMPLETED':break
                time.sleep(.01)
            before=self.service.cve_analysis_progress(state.assessment_id)
            callbacks[0]({'state':'RUNNING','phase':'SYNTHETIC_LATE'})
            after=self.service.cve_analysis_progress(state.assessment_id)
            self.assertEqual(after['state'],'COMPLETED');self.assertEqual(after['jobId'],before['jobId'])

    def test_stale_browser_does_not_kill_analysis_and_cancel_api_interrupts_active_request(self):
        state=self.service.create_assessment(self.request())
        release,entered=threading.Event(),threading.Event()
        class Slow:
            def get(self,*args,**kwargs): entered.set();release.wait(6);return _Response({'products':[],'totalResults':0})
        def run(_assessment_id,progress_callback=None,cancel_event=None):
            client=NvdClient(session=Slow(),cache=_MemoryCache(),cancel_event=cancel_event,max_retries=0)
            client.progress_callback=lambda detail:progress_callback({'phase':detail['phase'],'provider':'NVD CPES'})
            client.get_cpes({})
            return []
        app=LabAdminServer(self.service,browser_timeout_seconds=.05)
        thread=threading.Thread(target=app.run,kwargs={'open_browser':False},daemon=True);thread.start()
        self.addCleanup(app.shutdown);self.addCleanup(lambda:thread.join(5))
        with mock.patch('csa_lab.service.FleetAnalyzer.load_latest_endpoint_data',return_value=([{'submissionId':'SUB-SYNTHETIC'}],[],[])),mock.patch.object(self.service,'run_cve_analysis',side_effect=run):
            self.service.start_cve_analysis(state.assessment_id);self.assertTrue(entered.wait(2))
            app._heartbeat_seen.set();app._last_heartbeat=time.monotonic()-100
            time.sleep(2.1)
            self.assertFalse(app._shutdown_requested.is_set())
            start=time.monotonic()
            response=requests.get(app.url+'api/v1/heartbeat',timeout=2);self.assertEqual(response.status_code,200)
            response=requests.post(app.url+'api/v1/assessments/'+state.assessment_id+'/cve-analysis-cancel',
                headers={'X-CSA-Lab-CSRF':app.csrf_token},timeout=2)
            self.assertEqual(response.status_code,200);self.assertLess(time.monotonic()-start,1)
            self.assertEqual(response.json()['progress']['state'],'CANCELLING')
            for _ in range(30):
                if self.service.cve_analysis_progress(state.assessment_id)['state']=='CANCELLED':break
                time.sleep(.05)
            self.assertEqual(self.service.cve_analysis_progress(state.assessment_id)['state'],'CANCELLED')
            release.set()
        app.shutdown();thread.join(5)

    def test_startup_recovers_a_durable_running_job_without_claiming_completion(self):
        state=self.service.create_assessment(self.request())
        self.service.storage.write_json(state.assessment_id,('cve','job.json'),{'state':'RUNNING','phase':'PROVIDER_REQUEST','productsProcessed':27})
        resumed=LabApplicationService(self.service.storage.root,firewall=NullFirewallManager(),collector_bootstrap=self.bootstrap)
        self.addCleanup(resumed.shutdown)
        result=resumed.cve_analysis_progress(state.assessment_id)
        self.assertEqual(result['state'],'INTERRUPTED');self.assertEqual(result['productsProcessed'],27)
        self.assertEqual(result['result'],'PARTIAL')
