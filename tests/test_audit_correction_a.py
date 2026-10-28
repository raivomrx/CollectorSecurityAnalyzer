"""Independent audit correction A: original cross-component defect regressions."""
from __future__ import annotations

import copy
import json
import os
from unittest import mock
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest

from analyzer import _cve_analysis_metadata
from analysis_context import AnalysisContext
from collector_schema.loader import _parse_setting
from compliance.enums import EvidenceResult
from compliance.evidence.finding_evidence import FindingEvidenceExtractor
from compliance.loader import load_framework
from cve.cpe_resolver import CpeResolver
from cve.service import CveService
from evidence.registry import WindowsEvidenceRegistry
from knowledge.repository import KnowledgeRepository
from risk import AuditFinding, Finding, Severity, Status
from rules.windows.remote_access_rules import SPECS as REMOTE, Remote001Rule, Remote002Rule
from rules.windows.update_rules import SPECS as UPDATES, Upd002Rule
from software.models import SoftwareInventory, SoftwareProduct
from tests.test_console_sprint5 import Sprint5TestCase
from tests.test_sprint561_reporting import build_review_fixture

ROOT=Path(__file__).resolve().parents[1]

class DeterministicProvider:
    def get_cpes(self, params):
        return []
    def get_cves(self, params):
        return []


def cve_context(unknown=False, collection='SUCCESS'):
    products=[SoftwareProduct(vendor='Google',product='Google Chrome',version='120.0.0.0',normalized_vendor='Google',
        normalized_product='Google Chrome',normalized_version='120.0.0.0',confidence=100)]
    if unknown:
        products.append(SoftwareProduct(vendor='Synthetic',product='Synthetic Unmapped Product',version='1.0',
            normalized_vendor='Synthetic',normalized_product='Synthetic Unmapped Product',normalized_version='1.0',confidence=100))
    inventory=SoftwareInventory(products=products,product_count=len(products),collection_status=collection)
    provider=DeterministicProvider()
    context=AnalysisContext(raw_data={},software_inventory=inventory)
    context.cve_summary=CveService(client=provider,resolver=CpeResolver(client=provider)).scan_inventory(inventory)
    return context


class CveStatusRegressionTests(unittest.TestCase):
    def test_successful_provider_is_separate_from_complete_evaluation(self):
        metadata=_cve_analysis_metadata(cve_context())
        self.assertEqual(metadata['status'],'COMPLETE')
        self.assertEqual(metadata['providerCoverage'][0]['status'],'SUCCESS')

    def test_successful_provider_cannot_hide_an_unmapped_eligible_product(self):
        metadata=_cve_analysis_metadata(cve_context(unknown=True))
        self.assertEqual(metadata['status'],'PARTIAL')
        self.assertLess(metadata['successfullyEvaluatedProducts'],metadata['cveEligibleProducts'])
        self.assertEqual(metadata['providerCoverage'][0]['status'],'SUCCESS')


class PrerequisiteRegressionTests(unittest.TestCase):
    def test_missing_failed_unreadable_or_inactive_gate_is_never_pass(self):
        specs=[row for row in REMOTE+UPDATES if row.rule_id in {'REMOTE-001','REMOTE-002','UPD-002'}]
        rules={'REMOTE-001':Remote001Rule,'REMOTE-002':Remote002Rule,'UPD-002':Upd002Rule}
        self.assertEqual(len(specs),3)
        for spec in specs:
            for collected,value,expected in [(None,None,'NOT_EVALUATED'),('FAILED',True,'NOT_EVALUATED'),
                    ('PARTIAL',True,'NOT_EVALUATED'),('ACCESS_DENIED',False,'NOT_EVALUATED'),
                    ('SUCCESS',None,'NOT_EVALUATED'),('SUCCESS','false','NOT_EVALUATED'),('DUPLICATE',True,'NOT_EVALUATED'),
                    ('SUCCESS',False,'NOT_APPLICABLE')]:
                settings=[] if collected is None else [_parse_setting({'settingId':spec.only_when_setting_id,
                    'category':'Test','source':'RUNTIME_STATE','effectiveValue':value,'collectionStatus':'SUCCESS' if collected=='DUPLICATE' else collected,
                    'confidence':100,'collectedAt':'2026-10-28T08:00:00Z','provider':'Synthetic'})]
                if collected=='DUPLICATE': settings+=copy.deepcopy(settings)
                context=AnalysisContext(raw_data={},software_inventory=SoftwareInventory(),evidence_registry=WindowsEvidenceRegistry(settings))
                with self.subTest(rule=spec.rule_id,collected=collected,value=value):
                    result=rules[spec.rule_id]().check({},context)[0]
                    self.assertEqual(result.status.value,expected)
                    self.assertEqual(result.score,0)


class ComplianceEvidenceRegressionTests(unittest.TestCase):
    def test_unavailable_findings_never_contradict_any_status_is_requirement(self):
        count=0
        for path in (ROOT/'compliance/frameworks').glob('*/framework.json'):
            framework=load_framework(path)
            for control in framework.controls:
                for requirement in control.evidence_requirements:
                    if requirement.operator!='STATUS_IS': continue
                    count+=1
                    for status in [Status.NOT_EVALUATED,Status.ERROR,Status.PARTIAL,Status.INFO,Status.NOT_APPLICABLE]:
                        finding=AuditFinding(Finding(requirement.source_reference,Severity.INFO,status=status),
                                             KnowledgeRepository().get(requirement.source_reference))
                        record=FindingEvidenceExtractor().extract(requirement,AnalysisContext(raw_data={},software_inventory=SoftwareInventory()),[finding])
                        with self.subTest(requirement=requirement.evidence_id,status=status.value):
                            self.assertNotEqual(record.result,EvidenceResult.CONTRADICTS)
                            from compliance.evaluator import ComplianceEvaluator
                            from compliance.loader import load_profile
                            profile=load_profile(ROOT/'compliance/profiles/windows_11_workstation.json')
                            assessment=ComplianceEvaluator().evaluate_control(replace(control,evidence_requirements=[requirement]),profile,
                                AnalysisContext(raw_data={},software_inventory=SoftwareInventory()),[finding])
                            self.assertNotEqual(assessment.status.value,'NON_COMPLIANT')
                    if requirement.expected_result == 'PASS':
                        failed=AuditFinding(Finding(requirement.source_reference,Severity.HIGH,status=Status.FAIL),
                                            KnowledgeRepository().get(requirement.source_reference))
                        record=FindingEvidenceExtractor().extract(requirement,AnalysisContext(raw_data={},software_inventory=SoftwareInventory()),[failed])
                        self.assertEqual((record.result,record.confidence),(EvidenceResult.CONTRADICTS,95))
        self.assertGreater(count,50)


class IntegrityRegressionTests(Sprint5TestCase):
    def test_privacy_context_is_assessment_scoped_and_absent_from_evidence(self):
        from csa_console.collection_privacy import assessment_privacy_context
        first=assessment_privacy_context(self.session)
        again=assessment_privacy_context(self.session)
        self.assertEqual(first,again)
        second,_=self.sessions.open_session(self.assessment.assessment_id,listen_address='127.0.0.1',listen_port=0)
        self.assertEqual(first,assessment_privacy_context(second))
        other=self.sessions.create_assessment('Synthetic other','SYNTHETIC',assessment_id='CSA-2026-OTHER')
        third,_=self.sessions.open_session(other.assessment_id,listen_address='127.0.0.1',listen_port=0)
        self.assertNotEqual(first['key'],assessment_privacy_context(third)['key'])
        self.assertNotIn(first['key'],json.dumps(self.evidence()))

    def test_report_does_not_claim_its_own_integrity_before_independent_verification(self):
        generator=build_review_fixture(self)
        model=generator.build_model(self.assessment.assessment_id)
        self.assertEqual(model['integrity']['reportIntegrity'],'NOT_EVALUATED')
        # Source packages were accepted, but this fixture deliberately changes
        # normalized evidence afterwards. That derivative must not be VERIFIED.
        self.assertNotEqual(model['integrity']['evidencePackageIntegrity'],'VERIFIED')

    def test_corresponding_checks_detect_receipt_package_normalized_and_allowlist_changes(self):
        from csa_console.submission import SubmissionService
        from csa_console.pipeline import ConsoleAnalysisPipeline
        from csa_lab.unified_report import UnifiedReportGenerator
        submission='SUB-AUDIT-INTEGRITY'
        service=SubmissionService(self.storage)
        nonce=service.request_nonce(self.assessment.assessment_id,self.session.session_id,submission,self.token,'127.0.0.1')
        _,package,_=service.accept(assessment_id=self.assessment.assessment_id,session_id=self.session.session_id,
            submission_id=submission,enrollment_token=self.token,nonce=nonce,source_address='127.0.0.1',
            archive_bytes=self.package(submission,nonce).read_bytes())
        ConsoleAnalysisPipeline(self.storage).analyze(package)
        generator=UnifiedReportGenerator(self.storage)
        check=lambda:generator.build_model(self.assessment.assessment_id)['integrity']
        self.assertEqual(check()['evidencePackageIntegrity'],'VERIFIED')
        for parts in [('submissions','accepted',submission+'.csa.zip'),('submissions','accepted',submission+'.receipt.json'),
                      ('normalized',submission+'.json')]:
            path=self.storage.path(self.assessment.assessment_id,*parts)
            original=path.read_bytes()
            try:
                path.write_bytes(b'{}' if path.suffix=='.json' else b'not a zip')
                self.assertEqual(check()['evidencePackageIntegrity'],'NOT_VERIFIED',parts)
                path.unlink()
                self.assertEqual(check()['evidencePackageIntegrity'],'NOT_EVALUATED',parts)
            finally:
                path.write_bytes(original)
        self.session.report_configuration['trustedCollectorBuildDigests']=[]
        self.sessions._write_session(self.session)
        self.assertEqual(check()['collectorBuildTrusted'],'NOT_VERIFIED')


class AuditEndToEndTests(Sprint5TestCase):
    def accepted_case(self, label, *, unmapped=False, collection='SUCCESS'):
        from tests.test_audit_privacy import PrivacySerializationTests, privacy_document
        from csa_console.submission import SubmissionService
        from csa_console.pipeline import ConsoleAnalysisPipeline
        raw=self.evidence()
        private=privacy_document()
        raw['device'].update(private['device'])
        raw['security']['settings'] = [row for row in raw['security']['settings'] if row['settingId'] not in
            {'CURRENT_EXECUTION_USER','LOCAL_ADMINISTRATORS','EXECUTION_TOKEN_ADMIN_MEMBERSHIP'}]
        raw['security']['settings'] += private['security']['settings'][:3]
        if unmapped:
            members=raw['security']['settings'][-2]
            members['effectiveValue']=members['effectiveValue'][1:]
            members['configuredValue']=copy.deepcopy(members['effectiveValue'])
        raw['metadata'].update(private['metadata'])
        raw['software']={'collectionStatus':collection,'recordsCollected':1,'items':[
            {'displayName':'Google Chrome','displayVersion':'120.0.0.0','publisher':'Google','scope':'MACHINE','source':'HKLM_UNINSTALL'}]}
        if unmapped:
            raw['software']['items'].append({'displayName':'Microsoft Visual Studio Code','displayVersion':'1.99.0',
                                            'publisher':'Microsoft Corporation','scope':'MACHINE','source':'HKLM_UNINSTALL'})
            raw['software']['recordsCollected']=2
        serializer=PrivacySerializationTests('test_default_policy_is_enforced_before_output_including_metadata_copies')
        serializer.setUp()
        self.addCleanup(serializer.doCleanups)
        from csa_console.collection_privacy import assessment_privacy_context
        import base64
        privacy_context=assessment_privacy_context(self.session)
        sanitized,_=serializer.serialize(source=raw,key=base64.b64decode(privacy_context['key']),assessment_id=self.assessment.assessment_id)
        service=SubmissionService(self.storage)
        submission='SUB-AUDIT-'+label
        nonce=service.request_nonce(self.assessment.assessment_id,self.session.session_id,submission,self.token,'127.0.0.1')
        _,package,_=service.accept(assessment_id=self.assessment.assessment_id,session_id=self.session.session_id,
            submission_id=submission,enrollment_token=self.token,nonce=nonce,source_address='127.0.0.1',
            archive_bytes=self.package(submission,nonce,evidence=sanitized).read_bytes())
        pipeline=ConsoleAnalysisPipeline(self.storage)
        pipeline.analyze(package)
        from cve.cache import NvdCache
        class Provider(DeterministicProvider):
            def __init__(self, **kwargs):
                self.cache=kwargs.get('cache')
                self.session=SimpleNamespace(close=lambda:None)
        with mock.patch('analyzer.NvdClient',Provider), mock.patch('analyzer.NvdCache',side_effect=lambda:NvdCache(self.storage.root/'fake-cve.db')), \
                mock.patch('analyzer._run_cve_enrichment',return_value=None):
            result=pipeline.retry_analysis(self.assessment.assessment_id,submission,run_cve=True)
        return result

    @unittest.skipUnless(os.name=='nt','Windows serialization end-to-end path')
    def test_fake_provider_drives_analysis_pipeline_lab_and_report_without_complete_injection(self):
        from csa_lab.unified_report import UnifiedReportGenerator
        from csa_lab.service import LabApplicationService
        from csa_lab.firewall import NullFirewallManager
        for label,unknown,collected,expected in [('FULL',False,'SUCCESS','COMPLETE'),
                ('PARTIAL',True,'SUCCESS','PARTIAL'),('COLLECTION-FAILED',False,'ERROR','NOT_EVALUATED')]:
            result=self.accepted_case(label,unmapped=unknown,collection=collected)
            self.assertEqual(result.cve_analysis_status,expected,label)
            self.assertEqual(result.cve_summary['providerStatus'],'SUCCESS')
        generator=UnifiedReportGenerator(self.storage)
        model=generator.build_model(self.assessment.assessment_id)
        states={row['submissionId']:row['cveAnalysisStatus'] for row in model['endpoints']}
        self.assertEqual(states,{'SUB-AUDIT-FULL':'COMPLETE','SUB-AUDIT-PARTIAL':'PARTIAL','SUB-AUDIT-COLLECTION-FAILED':'NOT_EVALUATED'})
        self.assertEqual(model['cve']['status'],'PARTIAL')
        self.assertEqual(model['integrity']['evidencePackageIntegrity'],'VERIFIED')
        self.assertEqual(model['integrity']['collectorBuildTrusted'],'VERIFIED')
        report=generator.generate(self.assessment.assessment_id)
        html=report.read_text(encoding='utf-8')
        for prohibited in ['AuditAlice_OnlyFixture','AUDIT-HOST-ONLYFIXTURE','S-1-5-21-111-222-333','AUDITDOMAIN']:
            self.assertFalse(prohibited in html)
        self.assertEqual(model['administrativePrivileges']['observedAdminUsers'],1)
        lab=LabApplicationService(self.storage.root,firewall=NullFirewallManager())
        try:
            rows=lab.dashboard(self.assessment.assessment_id)
            self.assertEqual({row.submission_id:row.cve_analysis_status for row in rows},states)
        finally:
            lab.shutdown()
