"""Wall-clock, cancellation and checkpoint regressions; no external provider."""
from dataclasses import replace
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
import requests

from cve.client import NvdClient
from cve.checkpoint import ProductCheckpoint
from cve.exceptions import CveProductDeadline,CveScanCancelled
from cve.models import CveAssessment,ApplicabilityStatus
from cve.rate_limiter import SlidingWindowRateLimiter
from cve.service import CveService
from cve.control import interruptible_call
from software.models import SoftwareInventory
from tests.test_nvd_client import _MemoryCache,_Session,_Response
from tests.test_cve_engine import _software,_cpe,_cve_record


class CveReliabilityTests(unittest.TestCase):
    def test_cancellation_during_enrichment_discards_late_result(self):
        cancel,entered,release=threading.Event(),threading.Event(),threading.Event();errors=[]
        def task(combined):entered.set();release.wait(2);return 'synthetic late result'
        def run():
            try:interruptible_call(task,cancel)
            except Exception as error:errors.append(error)
        worker=threading.Thread(target=run);worker.start()
        try:
            self.assertTrue(entered.wait(1));cancel.set();worker.join(.6)
            self.assertFalse(worker.is_alive());self.assertIsInstance(errors[0],CveScanCancelled)
        finally:release.set();worker.join(2)

    def test_cancel_active_request_returns_before_the_provider_and_never_caches_late_data(self):
        release,entered,cancel=threading.Event(),threading.Event(),threading.Event()
        class Slow:
            def get(self,*args,**kwargs):
                entered.set();release.wait(3);return _Response({'totalResults':0,'products':[]})
        cache=_MemoryCache();client=NvdClient(session=Slow(),cache=cache,cancel_event=cancel,max_retries=0)
        errors=[]
        def run():
            try:client.get_cpes({})
            except Exception as error:errors.append(error)
        worker=threading.Thread(target=run);worker.start()
        try:
            self.assertTrue(entered.wait(1));cancel.set();worker.join(.7)
            self.assertFalse(worker.is_alive());self.assertIsInstance(errors[0],CveScanCancelled)
        finally:release.set();worker.join(2)
        self.assertEqual(client.metrics['cpeCacheHits'],0)
        self.assertTrue(client._request_lock.acquire(timeout=1));client._request_lock.release()
        self.assertEqual(cache.values,{})

    def test_product_deadline_bounds_slow_request_rate_limit_and_http429_wait(self):
        for mode in ('slow','limiter','429'):
            release=threading.Event()
            limiter=SlidingWindowRateLimiter(1,30)
            if mode=='limiter':limiter.acquire()
            class Slow:
                def get(self,*args,**kwargs):
                    release.wait(2);return _Response({'totalResults':0,'products':[]})
            session=Slow() if mode=='slow' else _Session([_Response({},status_code=429,headers={'Retry-After':'30'})])
            client=NvdClient(session=session,cache=_MemoryCache(),limiter=limiter,max_retries=2)
            client.product_deadline=time.monotonic()+.12;start=time.monotonic()
            try:
                with self.assertRaises(CveProductDeadline):client.get_cpes({})
                self.assertLess(time.monotonic()-start,.8)
            finally:release.set()

    def test_cancellation_interrupts_network_retry_backoff(self):
        cancel=threading.Event()
        client=NvdClient(session=_Session([requests.Timeout('synthetic')]),cache=_MemoryCache(),cancel_event=cancel)
        client.progress_callback=lambda event: cancel.set() if event['phase']=='RETRY_WAIT' else None
        started=time.monotonic()
        with self.assertRaises(CveScanCancelled):client.get_cves({})
        self.assertLess(time.monotonic()-started,.8)

    def test_deadline_preserves_confirmed_findings_continues_and_retries_only_incomplete_product(self):
        products=[replace(_software(),product='Synthetic '+str(i),normalized_product='synthetic_'+str(i)) for i in range(3)]
        inventory=SoftwareInventory(products=products,product_count=3)
        calls=[]
        class Resolver:
            def resolve(self,software):calls.append(software.product);return _cpe()
        class Client:
            def get_cves(self,params):
                if len(calls)==2:raise CveProductDeadline()
                return [{}]
        def assess(software,*args):
            return CveAssessment(software,_cpe(),_cve_record([]),ApplicabilityStatus.AFFECTED,'Synthetic confirmed',100)
        with tempfile.TemporaryDirectory() as directory, mock.patch('cve.service.parse_cve_items',return_value=[_cve_record([])]),mock.patch('cve.service._assess',side_effect=assess):
            checkpoint=ProductCheckpoint(Path(directory)/'progress.json','synthetic-input-scope')
            first=CveService(client=Client(),resolver=Resolver()).scan_inventory(inventory,checkpoint=checkpoint)
            self.assertEqual(first.confirmed_vulnerabilities,2)
            self.assertEqual(first.product_evaluations[1].terminal_reason_code,'PRODUCT_DEADLINE_EXCEEDED')
            self.assertEqual(len(first.product_evaluations),3)
            self.assertFalse(first.coverage_complete)
            before=len(calls)
            second=CveService(client=Client(),resolver=Resolver()).scan_inventory(inventory,checkpoint=checkpoint)
            self.assertEqual(len(calls)-before,1)
            self.assertEqual(second.confirmed_vulnerabilities,3)
            self.assertTrue(second.coverage_complete)
            self.assertIsNone(ProductCheckpoint(Path(directory)/'progress.json','different-input').load())

    def test_cancelled_product_checkpoint_retains_completed_and_confirmed_rows(self):
        cancel=threading.Event();calls=[]
        products=[replace(_software(),product='Synthetic '+str(i),normalized_product='synthetic_'+str(i)) for i in range(3)]
        class Resolver:
            def resolve(self,software):calls.append(software.product);return _cpe()
        class Client:
            def get_cves(self,params):
                if len(calls)==2:cancel.set();raise CveScanCancelled('Synthetic cancel')
                return [{}]
        def assess(software,*args):return CveAssessment(software,_cpe(),_cve_record([]),ApplicabilityStatus.AFFECTED,'Synthetic',100)
        with tempfile.TemporaryDirectory() as directory,mock.patch('cve.service.parse_cve_items',return_value=[_cve_record([])]),mock.patch('cve.service._assess',side_effect=assess):
            checkpoint=ProductCheckpoint(Path(directory)/'progress.json','input')
            with self.assertRaises(CveScanCancelled) as caught:
                CveService(client=Client(),resolver=Resolver()).scan_inventory(SoftwareInventory(products=products,product_count=3),cancel_event=cancel,checkpoint=checkpoint)
            self.assertEqual(caught.exception.partial_summary.confirmed_vulnerabilities,1)
            saved=checkpoint.load();self.assertEqual(saved.confirmed_vulnerabilities,1)
            self.assertFalse(saved.scan_complete);self.assertTrue(saved.telemetry['cancelled'])

    def test_cancelled_analysis_keeps_confirmed_cve_in_metadata_findings_and_html(self):
        import json
        from analyzer import analyze_file
        from cve.service import empty_summary
        from tests.test_console_sprint5 import Sprint5TestCase
        cancel=threading.Event();software=_software();record=_cve_record([])
        assessment=CveAssessment(software,_cpe(),record,ApplicabilityStatus.AFFECTED,'Synthetic confirmed finding',100)
        summary=replace(empty_summary(),scanned_products=1,unique_products=1,eligible_products=1,
            products_with_cpe=1,confirmed_vulnerabilities=1,assessments=[assessment],telemetry={'cancelled':True})
        def interrupted(*args,**kwargs):
            cancel.set();error=CveScanCancelled('Synthetic cancellation');error.partial_summary=summary;raise error
        raw=Sprint5TestCase().evidence()
        raw['software']['items']=[{'Vendor':software.vendor,'Product':software.product,'Version':software.version}]
        with tempfile.TemporaryDirectory() as directory,mock.patch('analyzer.NvdCache'),mock.patch('analyzer.CveService') as service:
            path=Path(directory)/'synthetic.json';path.write_text(json.dumps(raw),encoding='utf-8')
            service.return_value.scan_inventory.side_effect=interrupted
            metadata={}
            findings,_,_,report=analyze_file(path,output_dir=Path(directory)/'report',skip_enrichment=True,
                validate_input=True,analysis_metadata=metadata,cve_cancel_event=cancel)
            self.assertEqual(metadata['status'],'CANCELLED')
            self.assertIn(record.cve_id,metadata['confirmedCveIds'])
            self.assertTrue(report.is_file());self.assertIn(record.cve_id,report.read_text(encoding='utf-8'))
            self.assertTrue(any('CVE' in finding.finding.rule_id and finding.finding.status.value=='FAIL' for finding in findings))
