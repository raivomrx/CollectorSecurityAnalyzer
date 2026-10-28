"""Synthetic regression through the production Collector serialization path."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
USER='AuditAlice_OnlyFixture'
HOST='AUDIT-HOST-ONLYFIXTURE'
SID='S-1-5-21-111-222-333-1001'
GROUP='S-1-5-21-111-222-333-512'


def privacy_document():
    def setting(key,value,category='Accounts'):
        return {'settingId':key,'category':category,'effectiveValue':value,'configuredValue':copy.deepcopy(value),
                'collectionStatus':'SUCCESS','confidence':100,'source':'RUNTIME_STATE','provider':'Synthetic',
                'collectedAt':'2026-10-28T08:00:00Z'}
    current={'Name':'AUDITDOMAIN\\'+USER,'Sid':SID,'Classification':'DOMAIN'}
    members=[current,{'Name':'AUDITDOMAIN\\AuditAdmins_OnlyFixture','Sid':GROUP,'Classification':'DOMAIN','ObjectClass':'Group'}]
    token={'schemaVersion':'1.0','collectionStatus':'SUCCESS','provider':'GetTokenInformation','groupsComplete':True,'subjectSid':SID,
           'administratorSid':'S-1-5-32-544','administratorSidPresent':True,'administratorGroupEnabled':False,
           'administratorGroupDenyOnly':True,'administratorGroupAttributes':16,'elevationType':'LIMITED',
           'matchedAdministratorGroups':[{'sid':GROUP,'attributes':16}]}
    settings=[setting('CURRENT_EXECUTION_USER',current),setting('LOCAL_ADMINISTRATORS',members),
              setting('EXECUTION_TOKEN_ADMIN_MEMBERSHIP',token),
              setting('SYNTHETIC_NETWORK',[{'IPAddress':'10.77.88.99','IPv6Address':'fd01:77::99','MacAddress':'AA:BB:CC:DD:EE:99'}],'Network')]
    settings[2]['provider']='GetTokenInformation'
    return {'schemaVersion':'2.0','collectionProfile':'windows-standard-v1','device':{'hostname':HOST,'computerName':HOST,
        'fqdn':HOST+'.audit.example','domain':'AUDITDOMAIN','currentUser':'AUDITDOMAIN\\'+USER,'currentUserSid':SID,
        'domainJoined':True,'entraTenantId':'11111111-2222-3333-4444-555555555555'},
        'security':{'settings':settings},'software':{'collectionStatus':'SUCCESS','recordsCollected':1,'items':[
            {'displayName':'Google Chrome','displayVersion':'120.0.0.0','publisher':'Google',
             'installLocation':'C:\\Users\\'+USER+'\\AppData\\Chrome'}]},
        'privilegeContext':{'isElevated':False,'administratorMembership':token},
        'certificates':{'items':[{'SubjectIdentifier':'CN='+USER,'IssuerIdentifier':'CN=AuditOrgOnlyFixture'}]},
        'errors':[{'errorCode':'SYNTHETIC','message':'Failed for '+HOST+' at C:\\Users\\'+USER+'\\secret 10.77.88.99'}],
        'metadata':{'privacyMode':'Standard','moduleResults':[{'Module':'Accounts','Settings':copy.deepcopy(settings),
                    'Warnings':['User '+USER+' on '+HOST]}]}}


@unittest.skipUnless(os.name=='nt','Windows PowerShell serialization regression')
class PrivacySerializationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def serialize(self, key=b'A'*32, source=None, policy=None, assessment_id='CSA-AUDIT-SYNTHETIC'):
        document=self.root/'input.json'
        document.write_text(json.dumps(privacy_document() if source is None else source),encoding='utf-8')
        output=self.root/'output.json'
        policy_path=self.root/'policy.json'
        if policy is None:
            policy=json.loads((ROOT/'collector/windows/profiles/privacy-default.json').read_text())
        policy_path.write_text(json.dumps(policy),encoding='utf-8')
        harness=self.root/'serialize.ps1'
        harness.write_text('''param($Repo,$InputFile,$OutputPath,$Key,$PolicyPath,$AssessmentId)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $Repo 'collector/windows/modules/General.psm1') -Force
$privacyModule=Join-Path $Repo 'collector/windows/modules/Privacy.psm1'
if(Test-Path $privacyModule) { Import-Module $privacyModule -Force }
$document=Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json
$PrivacyMode='Standard'
$PrivacyContext=@{assessmentId=$AssessmentId;key=$Key}
$privacyPolicy=Get-Content $PolicyPath -Raw | ConvertFrom-Json
$source=Get-Content (Join-Path $Repo 'collector/windows/Collect-CSAWindowsEvidence.ps1') -Raw
# Execute the production final-write path, with synthetic in-memory collection.
$tail=$source.Substring($source.IndexOf('$resolvedOutput ='))
. ([scriptblock]::Create($tail))
''',encoding='utf-8-sig')
        result=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(harness),str(ROOT),
            str(document),str(output),base64.b64encode(key).decode(),str(policy_path),assessment_id],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(output.read_text(encoding='utf-8-sig')),result.stdout+result.stderr

    def test_default_policy_is_enforced_before_output_including_metadata_copies(self):
        result,diagnostics=self.serialize()
        encoded=json.dumps(result)+diagnostics
        for prohibited in [USER,HOST,SID,GROUP,'AUDITDOMAIN','10.77.88.99','fd01:77::99','AA:BB:CC:DD:EE:99',
                           '11111111-2222-3333-4444-555555555555','AuditOrgOnlyFixture']:
            with self.subTest(identifier=prohibited): self.assertFalse(prohibited in encoded)
        self.assertEqual(result['software']['items'][0]['displayVersion'],'120.0.0.0')
        self.assertEqual(result['metadata']['privacyMode'],'PROFILE_ENFORCED')

    def test_assessment_scope_preserves_sid_token_correlations_and_changes_between_assessments(self):
        first,_=self.serialize()
        second,_=self.serialize()
        other,_=self.serialize(b'B'*32)
        self.assertEqual(first['device']['currentUserSid'],second['device']['currentUserSid'])
        self.assertNotEqual(first['device']['currentUserSid'],other['device']['currentUserSid'])
        settings={row['settingId']:row for row in first['security']['settings']}
        identity=settings['CURRENT_EXECUTION_USER']['effectiveValue']['Sid']
        self.assertEqual(identity,first['device']['currentUserSid'])
        self.assertEqual(identity,settings['LOCAL_ADMINISTRATORS']['effectiveValue'][0]['Sid'])
        self.assertEqual(identity,settings['EXECUTION_TOKEN_ADMIN_MEMBERSHIP']['effectiveValue']['subjectSid'])
        self.assertEqual(settings['EXECUTION_TOKEN_ADMIN_MEMBERSHIP']['effectiveValue']['administratorSid'],'S-1-5-32-544')

    def test_inherited_domain_administrator_membership_survives_profile_enforcement(self):
        from tests.test_effective_admin_membership import membership_settings, evaluate
        source=privacy_document()
        source['security']['settings']=membership_settings('INHERITED')
        result,_=self.serialize(source=source)
        finding,posture=evaluate(result['security']['settings'])
        self.assertEqual(finding.status.value,'FAIL')
        self.assertEqual(posture['membershipType'],'INHERITED_DOMAIN_GROUP')
        self.assertFalse(posture['processElevation']['isElevated'])

    def test_policy_blocks_inventory_and_raw_copies_despite_forged_metadata_stamp(self):
        original,_=self.serialize()
        source=privacy_document()
        source['metadata'].update(privacyScopeId=original['metadata']['privacyScopeId'])
        source['metadata']['rawRegistryDump']={'RawPrivateValue':'AuditRawOnlyFixture'}
        source['metadata']['moduleResults'][0]['SoftwareItems']=copy.deepcopy(source['software']['items'])
        policy=json.loads((ROOT/'collector/windows/profiles/privacy-default.json').read_text())
        policy.update(includeSoftwareInventory=False,includeFilePaths='NONE')
        result,logs=self.serialize(source=source,policy=policy)
        self.assertEqual(result['software']['items'],[])
        self.assertEqual(result['software']['collectionStatus'],'NOT_EVALUATED')
        self.assertEqual(result['metadata']['moduleResults'][0]['SoftwareItems'],[])
        self.assertNotIn('rawRegistryDump',result['metadata'])
        self.assertNotIn(USER,json.dumps(result)+logs)
        self.assertEqual(result['metadata']['privacyPolicyApplied'],policy)

    def test_policy_can_allow_identifiers_without_changing_public_software_identity(self):
        policy=json.loads((ROOT/'collector/windows/profiles/privacy-default.json').read_text())
        policy.update(includeHostname=True,hashUsername=False,hashTenantId=False,includeIpAddresses=True,
            includeMacAddresses=True,includeCertificateSubjects=True,includeLocalAdminNames=True)
        result,_=self.serialize(policy=policy)
        self.assertEqual(result['device']['hostname'],HOST)
        self.assertEqual(result['device']['currentUser'],'AUDITDOMAIN\\'+USER)
        self.assertEqual(result['certificates']['items'][0]['SubjectIdentifier'],'CN='+USER)
        self.assertEqual(result['software']['items'][0]['displayVersion'],'120.0.0.0')
        self.assertNotIn(USER,result['software']['items'][0]['installLocation'])
