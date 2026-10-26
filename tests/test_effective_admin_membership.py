"""ACC-011 effective membership, token failures and report-scope regressions."""
from __future__ import annotations

import copy
import unittest

from analysis_context import AnalysisContext
from collector_schema.loader import _parse_setting
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import _administrative_privileges_summary
from evidence.administrative_privileges import administrative_privilege_posture
from evidence.administrator_membership import ADMIN_SID, membership_observation, resolve_administrator_membership
from evidence.registry import WindowsEvidenceRegistry
from knowledge.repository import KnowledgeRepository
from risk import AuditFinding
from rules.windows.account_rules import Acc011Rule
from software.models import SoftwareInventory
from tests.test_console_sprint5 import Sprint5TestCase

SID = 'S-1-5-21-100-200-300-1001'
GROUP = 'S-1-5-21-100-200-300-512'


def membership_settings(kind='DIRECT', *, sid=SID, classification='DOMAIN'):
    group = 'id-111111111111' if sid.startswith('id-') else GROUP
    current = {'Name': 'DEMO\\execution õäöü', 'Sid': sid, 'Classification': classification}
    principal = {'Name': 'DEMO\\execution õäöü', 'Sid': sid, 'Classification': classification, 'ObjectClass': 'User'}
    members = [principal] if kind in {'DIRECT', 'CONFLICT', 'LOCAL'} else [
        {'Name': 'DEMO\\Endpoint administrators', 'Sid': group, 'Classification': 'DOMAIN', 'ObjectClass': 'Group'}]
    present = kind not in {'STANDARD', 'CONFLICT'}
    attrs = (16 if kind in {'DIRECT', 'INHERITED', 'LOCAL', 'PRIVACY'} else 4) if present else None
    token = {'schemaVersion': '1.0', 'provider': 'GetTokenInformation', 'collectionStatus': 'SUCCESS',
             'subjectSid': sid, 'administratorSid': ADMIN_SID, 'groupsComplete': True,
             'administratorSidPresent': present, 'administratorGroupAttributes': attrs,
             'administratorGroupEnabled': bool(attrs and attrs & 4),
             'administratorGroupDenyOnly': bool(attrs and attrs & 16),
             'elevationType': 'LIMITED' if attrs == 16 else 'DEFAULT',
             'matchedAdministratorGroups': [{'sid': group, 'attributes': attrs}] if kind in {'INHERITED', 'PRIVACY'} else []}
    if kind == 'UNAVAILABLE':
        token.update(collectionStatus='FAILED', groupsComplete=False, administratorSidPresent=None,
                     administratorGroupAttributes=None, administratorGroupEnabled=None, administratorGroupDenyOnly=None,
                     errorCode='TOKEN_GROUPS_QUERY_FAILED')
    settings = []
    for key, value, provider, status in (
        ('CURRENT_EXECUTION_USER', current, 'WindowsIdentity', 'SUCCESS'),
        ('LOCAL_ADMINISTRATORS', members, 'Get-LocalGroupMember', 'ACCESS_DENIED' if kind == 'TOKEN' else 'SUCCESS'),
        ('EXECUTION_TOKEN_ADMIN_MEMBERSHIP', token, 'GetTokenInformation', token['collectionStatus']),
    ):
        settings.append({'settingId': key, 'effectiveValue': value, 'configuredValue': value, 'category': 'Accounts',
                         'source': 'RUNTIME_STATE', 'collectionStatus': status, 'confidence': 100 if status == 'SUCCESS' else 0,
                         'collectedAt': '2026-10-26T08:00:00Z', 'provider': provider})
    return settings


def evaluate(settings):
    context = AnalysisContext(raw_data={}, software_inventory=SoftwareInventory(),
                              evidence_registry=WindowsEvidenceRegistry([_parse_setting(row) for row in settings]))
    finding = Acc011Rule().check({}, context)[0]
    row = AuditFinding(finding, KnowledgeRepository().get('ACC-011')).to_dict()
    evidence = {'securityPolicies': {'settings': settings}, 'privilegeContext': {'isElevated': False}}
    return finding, administrative_privilege_posture(evidence, [row])


class EffectiveMembershipTests(unittest.TestCase):
    def test_direct_and_domain_inherited_membership_are_confirmed_without_elevation(self):
        for kind, expected in [('DIRECT', 'DIRECT'), ('INHERITED', 'INHERITED_DOMAIN_GROUP'), ('TOKEN', 'TOKEN_BASED')]:
            with self.subTest(kind=kind):
                finding, posture = evaluate(membership_settings(kind))
                self.assertEqual(finding.status.value, 'FAIL')
                self.assertEqual(finding.score, 20)
                self.assertEqual(posture['membershipType'], expected)
                self.assertTrue(posture['isAdministratorMember'])
                self.assertFalse(posture['processElevation']['isElevated'])
                self.assertEqual(posture['desktopUsersState'], 'NOT_EVALUATED')

    def test_uac_filtered_and_other_deny_only_tokens_are_not_elevated(self):
        settings = membership_settings('INHERITED')
        self.assertEqual(evaluate(settings)[1]['tokenState'], 'UAC_FILTERED_DENY_ONLY')
        settings[2]['effectiveValue']['elevationType'] = 'DEFAULT'
        self.assertEqual(evaluate(settings)[1]['tokenState'], 'DENY_ONLY')

    def test_nested_group_token_matching_does_not_depend_on_user_sid_in_direct_list(self):
        settings = membership_settings('INHERITED')
        settings[1]['effectiveValue'][0]['Name'] = 'DEMO\\Nested administrators'
        finding, posture = evaluate(settings)
        self.assertFalse(finding.evidence['matched'])
        self.assertEqual(posture['membershipType'], 'INHERITED_DOMAIN_GROUP')

    def test_complete_standard_token_proves_non_membership(self):
        finding, posture = evaluate(membership_settings('STANDARD'))
        self.assertEqual(finding.status.value, 'PASS')
        self.assertFalse(posture['isAdministratorMember'])
        self.assertEqual(posture['tokenState'], 'ABSENT')

    def test_conflicts_never_become_pass_or_silent_zero(self):
        for kind in ['CONFLICT', 'ENABLED_WITHOUT_PATH']:
            finding, posture = evaluate(membership_settings(kind))
            self.assertEqual(finding.status.value, 'PARTIAL')
            self.assertEqual(posture['state'], 'SOURCE_CONFLICT')
            self.assertIsNone(posture['isAdministratorMember'])

        rows = membership_settings('INHERITED')
        rows[2]['effectiveValue'].update(administratorSidPresent=False, administratorGroupAttributes=None,
                                        administratorGroupEnabled=False, administratorGroupDenyOnly=False)
        self.assertEqual(evaluate(rows)[1]['state'], 'SOURCE_CONFLICT')

    def test_failed_query_and_old_negative_direct_list_are_unknown(self):
        settings = membership_settings('UNAVAILABLE')
        for mutation in ['FAILED', 'WHOAMI', 'INCOMPLETE', 'MISSING']:
            rows = copy.deepcopy(settings)
            if mutation == 'WHOAMI':
                rows[2]['collectionStatus'] = 'SUCCESS'
                rows[2]['effectiveValue'].update(collectionStatus='SUCCESS', provider='whoami', groupsComplete=True)
                rows[2]['provider'] = 'whoami'
            elif mutation == 'INCOMPLETE':
                rows[2]['collectionStatus'] = 'SUCCESS'
                rows[2]['effectiveValue'].update(collectionStatus='SUCCESS', groupsComplete=False)
            elif mutation == 'MISSING':
                rows.pop()
            self.assertEqual(evaluate(rows)[0].status.value, 'NOT_EVALUATED', mutation)
            self.assertIsNone(evaluate(rows)[1]['isAdministratorMember'])

        legacy = {'finding': {'rule_id': 'ACC-011', 'status': 'PASS', 'evidence': {
            'current_user_sid': SID, 'matched': False, 'membership_source': 'LOCAL_ADMINISTRATORS_SID_CORRELATION'}}}
        self.assertEqual(administrative_privilege_posture({}, [legacy])['status'], 'NOT_EVALUATED')

    def test_malformed_attributes_and_subject_conflicts_remain_partial(self):
        for field, value in [('subjectSid', SID[:-1]+'2'), ('administratorGroupAttributes', True),
                             ('administratorGroupEnabled', True), ('administratorGroupAttributes', 20)]:
            rows = membership_settings('INHERITED')
            rows[2]['effectiveValue'][field] = value
            self.assertEqual(evaluate(rows)[1]['state'], 'SOURCE_CONFLICT', field)

    def test_disabled_sid_without_direct_proof_does_not_prove_standard_user(self):
        rows = membership_settings('INHERITED')
        rows[2]['effectiveValue'].update(administratorGroupAttributes=0, administratorGroupDenyOnly=False)
        finding, posture = evaluate(rows)
        self.assertEqual(finding.status.value, 'PARTIAL')
        self.assertEqual(posture['tokenState'], 'DISABLED')
        self.assertIsNone(posture['isAdministratorMember'])

    def test_failed_direct_list_does_not_discard_successful_identity_bound_token(self):
        rows = membership_settings('TOKEN')
        self.assertEqual(evaluate(rows)[1]['membershipType'], 'TOKEN_BASED')
        rows[2]['effectiveValue']['subjectSid'] = None
        self.assertEqual(evaluate(rows)[0].status.value, 'NOT_EVALUATED')

    def test_duplicate_sources_and_stored_result_tampering_fail_closed(self):
        rows = membership_settings('INHERITED')
        self.assertEqual(evaluate(rows+[copy.deepcopy(rows[2])])[0].status.value, 'PARTIAL')
        finding, _ = evaluate(rows)
        finding.status = __import__('risk').Status.PASS
        row = AuditFinding(finding, KnowledgeRepository().get('ACC-011')).to_dict()
        posture = administrative_privilege_posture({'securityPolicies': {'settings': rows}}, [row])
        self.assertEqual(posture['state'], 'SOURCE_CONFLICT')

    def test_raw_source_conflict_cannot_reuse_stored_positive_proof(self):
        rows = membership_settings('INHERITED')
        finding, _ = evaluate(rows)
        stored = AuditFinding(finding, KnowledgeRepository().get('ACC-011')).to_dict()
        rows = copy.deepcopy(rows)
        rows[2]['effectiveValue']['subjectSid'] = SID[:-1]+'2'
        posture = administrative_privilege_posture({'securityPolicies': {'settings': rows}}, [stored])
        self.assertEqual(posture['state'], 'SOURCE_CONFLICT')

    def test_private_sid_inheritance_and_device_scoped_local_identities(self):
        endpoints = []
        for label, kind, sid, scope in [('A','INHERITED',SID,'DOMAIN'), ('B','DIRECT',SID,'DOMAIN'),
                ('C','LOCAL',SID,'LOCAL'), ('D','LOCAL',SID,'LOCAL'),
                ('E','PRIVACY','id-012345abcdef','DOMAIN'), ('F','PRIVACY','id-012345abcdef','DOMAIN'),
                ('G','CONFLICT',SID,'DOMAIN')]:
            posture = evaluate(membership_settings(kind, sid=sid, classification=scope))[1]
            endpoints.append({'deviceId': label, 'displayName': label, 'anchorId': label, 'administrativePrivileges': posture})
        summary = _administrative_privileges_summary(endpoints)
        self.assertEqual((summary['observedAdminUsers'],summary['affectedEndpoints'],summary['notEvaluatedEndpoints']), (4,6,1))
        self.assertEqual(summary['sourceConflictEndpoints'], 1)
        self.assertEqual(summary['elevatedCollectorProcesses'], 0)
        self.assertEqual(summary, _administrative_privileges_summary(endpoints[::-1]))

    def test_observation_is_nonmutating_and_unknown_identity_is_not_an_account(self):
        rows = membership_settings('INHERITED')
        before = copy.deepcopy(rows)
        observation = membership_observation(*rows)
        original = copy.deepcopy(observation)
        resolve_administrator_membership(observation)
        self.assertEqual(rows, before)
        self.assertEqual(observation, original)
        for sid in [None, 'same-name', 'S-1-5-18', ADMIN_SID]:
            observation['identity']['sid'] = sid
            self.assertEqual(resolve_administrator_membership(observation)['status'], 'NOT_EVALUATED')


def build_effective_membership_review_fixture(case):
    from tests.test_sprint561_reporting import build_review_fixture
    generator = build_review_fixture(case)
    service = SubmissionService(case.storage)
    cases = [('ENABLED', 'DIRECT'), ('DISABLED', 'INHERITED'), ('UNKNOWN', 'STANDARD'),
             ('TOKEN', 'TOKEN'), ('CONFLICT', 'CONFLICT'), ('UNAVAILABLE', 'UNAVAILABLE'),
             ('LOCAL', 'LOCAL'), ('PRIVACY', 'PRIVACY')]
    for label, kind in cases:
        submission = 'SUB-531-' + label
        if label not in {'ENABLED','DISABLED','UNKNOWN'}:
            evidence = case.evidence()
            evidence['device'].update(hostname='DEMO-'+label, computerName='DEMO-'+label)
            nonce = service.request_nonce(case.assessment.assessment_id, case.session.session_id, submission, case.token, '127.0.0.1')
            _, package, _ = service.accept(assessment_id=case.assessment.assessment_id, session_id=case.session.session_id,
                submission_id=submission, enrollment_token=case.token, nonce=nonce, source_address='127.0.0.1',
                archive_bytes=case.package(submission, nonce, evidence=evidence).read_bytes())
            ConsoleAnalysisPipeline(case.storage).analyze(package)
        normalized = case.storage.read_json(case.assessment.assessment_id, 'normalized', submission+'.json')
        sid = 'id-012345abcdef' if kind == 'PRIVACY' else SID[:-1]+'2' if kind == 'TOKEN' else SID
        settings = membership_settings(kind, sid=sid, classification='LOCAL' if kind == 'LOCAL' else 'DOMAIN')
        if kind == 'PRIVACY':
            settings[0]['effectiveValue']['Name'] = 'id-000000000001'
            settings[1]['effectiveValue'][0]['Name'] = 'id-000000000002'
        normalized['securityPolicies'] = {'settings': settings}
        normalized['privilegeContext'] = {'isElevated': False}
        case.storage.write_json(case.assessment.assessment_id, ('normalized',submission+'.json'), normalized)
        analysis = case.storage.read_json(case.assessment.assessment_id, 'findings', submission+'.json')
        finding, _ = evaluate(settings)
        analysis['findings'] = [row for row in analysis['findings'] if row['finding']['rule_id'] != 'ACC-011']
        analysis['findings'].append(AuditFinding(finding, KnowledgeRepository().get('ACC-011')).to_dict())
        case.storage.write_json(case.assessment.assessment_id, ('findings',submission+'.json'), analysis)
    return generator


class EffectiveMembershipReportTests(Sprint5TestCase):
    def test_authenticated_package_analysis_preserves_token_proof_and_nullable_unknown(self):
        from csa_lab.unified_report import UnifiedReportGenerator
        service = SubmissionService(self.storage)
        for kind, expected in [('INHERITED', 'FAIL'), ('UNAVAILABLE', 'NOT_EVALUATED')]:
            submission = 'SUB-EFFECTIVE-' + kind
            evidence = self.evidence()
            relevant = {'CURRENT_EXECUTION_USER', 'LOCAL_ADMINISTRATORS', 'EXECUTION_TOKEN_ADMIN_MEMBERSHIP'}
            evidence['security']['settings'] = [row for row in evidence['security']['settings'] if row['settingId'] not in relevant]
            evidence['security']['settings'] += membership_settings(kind)
            evidence['privilegeContext']['isLocalAdministratorMember'] = True if kind == 'INHERITED' else None
            nonce = service.request_nonce(self.assessment.assessment_id, self.session.session_id, submission, self.token, '127.0.0.1')
            _, package, _ = service.accept(assessment_id=self.assessment.assessment_id, session_id=self.session.session_id,
                submission_id=submission, enrollment_token=self.token, nonce=nonce, source_address='127.0.0.1',
                archive_bytes=self.package(submission, nonce, evidence=evidence).read_bytes())
            analysis = ConsoleAnalysisPipeline(self.storage).analyze(package)
            finding = next(row['finding'] for row in analysis.findings if row['finding']['rule_id'] == 'ACC-011')
            self.assertEqual(finding['status'], expected)
        model = UnifiedReportGenerator(self.storage).build_model(self.assessment.assessment_id)
        states = {row['submissionId']: row['administrativePrivileges'] for row in model['endpoints']}
        self.assertEqual(states['SUB-EFFECTIVE-INHERITED']['membershipType'], 'INHERITED_DOMAIN_GROUP')
        self.assertIsNone(states['SUB-EFFECTIVE-UNAVAILABLE']['isAdministratorMember'])

    def test_eight_endpoint_acceptance_fixture_preserves_cve_fix_and_exposes_all_states(self):
        generator = build_effective_membership_review_fixture(self)
        model = generator.build_model(self.assessment.assessment_id)
        summary = model['administrativePrivileges']
        self.assertEqual((summary['observedAdminUsers'],summary['affectedEndpoints'],summary['evaluatedEndpoints'],
                          summary['notEvaluatedEndpoints'],summary['sourceConflictEndpoints']), (4,5,6,2,1))
        self.assertEqual(summary['elevatedCollectorProcesses'], 0)
        self.assertEqual(model['cve']['confirmedUniqueCves'], 3)
        self.assertFalse(any(row['ruleId']=='CVE-001' and row.get('kind') != 'SOFTWARE_CVE' for row in model['findings']))
        html = generator.generate(self.assessment.assessment_id).read_text(encoding='utf-8')
        for value in ['INHERITED DOMAIN GROUP', 'UAC FILTERED DENY ONLY', 'SOURCE CONFLICT',
                      'Actual interactive desktop users', 'TOKEN BASED', 'õäöü']:
            self.assertIn(value, html)
        self.assertNotIn('distinct observed interactive administrator', html)
        self.assertNotIn('daily user SID', html)
        self.assertIn('Review direct and inherited group assignments', html)
