"""REP-1 completion boundaries, including honest zero-CVE rule evidence."""
from dataclasses import replace
import unittest

from analyzer import _cve_analysis_metadata
from analysis_context import AnalysisContext
from cve.service import CveService
from cve.status import normalize_metadata
from csa_lab.unified_report import _aggregate_cve, _software_intelligence_coverage, _aggregate_software_intelligence
from rules.cve import KnownVulnerabilitiesRule
from software.models import SoftwareInventory
from tests.test_audit_correction_a import DeterministicProvider, cve_context
from tests.test_sprint521_reporting import _endpoint


def metadata(eligible=1, evaluated=1, scan=True, collection='SUCCESS', **extra):
    return {'softwareCollectionStatus':collection,'scanCompleted':scan,
            'cveEligibleProducts':eligible,'successfullyEvaluatedProducts':evaluated,
            'providerStatus':'SUCCESS',**extra}


class CveCompletionBoundaryTests(unittest.TestCase):
    def test_completion_requires_positive_scope_successful_collection_and_finished_scan(self):
        for eligible,evaluated,scan,collection,expected in [
            (0,0,True,'SUCCESS','NOT_EVALUATED'),
            (1,1,False,'SUCCESS','PARTIAL'),
            (1,1,True,'SUCCESS','COMPLETE'),
            (2,1,True,'SUCCESS','PARTIAL'),
            (1,1,True,'ERROR','NOT_EVALUATED'),
            (1,1,True,'PARTIAL','PARTIAL'),
            (1,1,None,'SUCCESS','PARTIAL'),
        ]:
            with self.subTest(eligible=eligible,evaluated=evaluated,scan=scan,collection=collection):
                result=normalize_metadata(metadata(eligible,evaluated,scan,collection))
                self.assertEqual(result['status'],expected)
                self.assertEqual(result['providerStatus'],'SUCCESS')
                self.assertEqual(result['coverageComplete'],expected=='COMPLETE')

    def test_empty_scope_has_a_reason_and_zero_assessment_coverage(self):
        result=normalize_metadata(metadata(0,0))
        self.assertEqual(result['status'],'NOT_EVALUATED')
        self.assertEqual(result['coveragePercent'],0.0)
        self.assertEqual(result['assessmentScope'],'EMPTY')
        self.assertEqual(result['assessmentReasonCode'],'NO_ELIGIBLE_PRODUCTS')

    def test_unfinished_scan_keeps_counts_without_a_full_assessment_percentage(self):
        result=normalize_metadata(metadata(scan=False))
        self.assertEqual(result['status'],'PARTIAL')
        self.assertEqual(result['successfullyEvaluatedProducts'],1)
        self.assertIsNone(result['coveragePercent'])
        self.assertEqual(result['assessmentReasonCode'],'SCAN_NOT_COMPLETED')

    def test_unresolved_eligible_evidence_blocks_complete_even_if_totals_match(self):
        for extra in [
            {'notEvaluatedProducts':1},
            {'unresolvedCveEvaluations':1},
            {'productEvaluations':[{'eligibilityStatus':'ELIGIBLE','terminalStatus':'PENDING'}]},
        ]:
            with self.subTest(extra=extra):
                result=normalize_metadata(metadata(**extra))
                self.assertEqual(result['status'],'PARTIAL')
                self.assertNotEqual(result['coveragePercent'],100.0)

    def test_actual_empty_service_summary_does_not_claim_full_coverage_or_clean_rule(self):
        inventory=SoftwareInventory(products=[],product_count=0,collection_status='SUCCESS')
        summary=CveService(client=DeterministicProvider()).scan_inventory(inventory)
        context=AnalysisContext(raw_data={},software_inventory=inventory,cve_summary=summary)
        self.assertEqual(summary.coverage_percent,0.0)
        self.assertFalse(summary.coverage_complete)
        result=_cve_analysis_metadata(context)
        self.assertEqual(result['status'],'NOT_EVALUATED')
        self.assertEqual(result['assessmentReasonCode'],'NO_ELIGIBLE_PRODUCTS')
        self.assertEqual(KnownVulnerabilitiesRule().check({},context)[0].status.value,'NOT_EVALUATED')

    def test_zero_cve_pass_requires_completed_nonempty_successful_inventory(self):
        for collection,scan,expected in [('SUCCESS',True,'PASS'),('SUCCESS',False,'NOT_EVALUATED'),
                                           ('PARTIAL',True,'NOT_EVALUATED'),('ERROR',True,'NOT_EVALUATED')]:
            with self.subTest(collection=collection,scan=scan):
                context=cve_context(collection=collection)
                context.cve_summary=replace(context.cve_summary,scan_complete=scan)
                result=KnownVulnerabilitiesRule().check({},context)[0]
                self.assertEqual(result.status.value,expected)
                self.assertEqual(result.evidence['assessment_status'],_cve_analysis_metadata(context)['status'])

    def test_empty_and_unfinished_report_scopes_never_look_clean_or_fully_covered(self):
        for eligible,evaluated,scan in [(0,0,True),(1,1,False)]:
            endpoint=_endpoint(eligible=eligible,evaluated=evaluated)
            endpoint['cveSummary'].update(scanCompleted=scan)
            result=_aggregate_cve([endpoint])
            with self.subTest(eligible=eligible,scan=scan):
                self.assertNotEqual(result['status'],'COMPLETE')
                self.assertNotEqual(result['coveragePercent'],100.0)
                self.assertNotIn('No known vulnerabilities found',result['coverageStatement'])
                self.assertFalse(result['coverageComplete'])
                if eligible==0:
                    self.assertEqual(result['primaryDisplay'],'NOT EVALUATED')
                    self.assertIn('No eligible',result['coverageStatement'])
        self.assertEqual(_software_intelligence_coverage([])['eligibleCveCoveragePercent'],0.0)
        self.assertEqual(_aggregate_software_intelligence([{'softwareResults':[]}])['eligibleCveCoveragePercent'],0.0)

    def test_report_cannot_reuse_a_complete_label_when_its_instance_scope_is_empty(self):
        endpoint=_endpoint()
        endpoint['softwareIntelligence']={'cveEligible':0,'cveEvaluated':0}
        result=_aggregate_cve([endpoint])
        self.assertEqual(result['status'],'NOT_EVALUATED')
        self.assertEqual(result['coveragePercent'],0.0)
        self.assertFalse(result['coverageComplete'])

    def test_partial_product_evidence_remains_partial_without_a_fully_completed_product(self):
        endpoint=_endpoint(status='PARTIAL',eligible=1,evaluated=0)
        endpoint['cveSummary']['productEvaluations']=[{'eligibilityStatus':'ELIGIBLE','terminalStatus':'PARTIAL'}]
        result=_aggregate_cve([endpoint])
        self.assertEqual(result['status'],'PARTIAL')
        self.assertFalse(result['coverageComplete'])
        self.assertEqual(result['coveragePercent'],0.0)

    def test_confirmed_vulnerability_retains_its_failure_and_risk_with_incomplete_inventory(self):
        from cve.models import ApplicabilityStatus, CveAssessment
        from tests.test_cve_engine import _software, _cpe, _cve_record
        context=cve_context(collection='ERROR')
        confirmed=CveAssessment(_software(),_cpe(),_cve_record([]),ApplicabilityStatus.AFFECTED,'Synthetic confirmed finding',100)
        context.cve_summary=replace(context.cve_summary,assessments=[confirmed],confirmed_vulnerabilities=1)
        finding=KnownVulnerabilitiesRule().check({},context)[0]
        self.assertEqual((finding.status.value,finding.score),('FAIL',20))

    def test_endpoint_html_scope_uses_assessment_completion_instead_of_scan_counters(self):
        import tempfile
        from pathlib import Path
        from report import generate_html_report
        for collection,scan,expected in [('SUCCESS',True,'Complete'),('SUCCESS',False,'Incomplete'),('ERROR',True,'Incomplete')]:
            context=cve_context(collection=collection)
            context.cve_summary=replace(context.cve_summary,scan_complete=scan)
            with self.subTest(collection=collection,scan=scan), tempfile.TemporaryDirectory() as directory:
                output=generate_html_report({},[],100,context.software_inventory,{},context.cve_summary,Path(directory)/'report.html')
                html=output.read_text(encoding='utf-8')
                self.assertIn('Software vulnerability evaluation scope</span><strong>'+expected,html)
                if expected=='Incomplete':
                    self.assertIn('Coverage not established',html)
