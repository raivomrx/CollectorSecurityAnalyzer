"""Generate and independently verify the synthetic audit-A acceptance report."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))

from csa_console.canonical import read_json, sha256_bytes, sha256_value, write_canonical_json
from csa_lab.unified_report import UnifiedReportGenerator
from tests.test_audit_correction_a import AuditEndToEndTests


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    output=Path(args.output).resolve()
    output.parent.mkdir(parents=True,exist_ok=True)
    case=AuditEndToEndTests('runTest')
    case.setUp()
    try:
        for label,unmapped,collection in [('FULL',False,'SUCCESS'),('PARTIAL',True,'SUCCESS'),('COLLECTION-FAILED',False,'ERROR')]:
            case.accepted_case(label,unmapped=unmapped,collection=collection)
        case.storage.write_json(case.assessment.assessment_id,('lab-state.json',),{
            'organization':'Synthetic audit review',
            'description':'Synthetic fixture only. Deterministic fake CVE provider; no live collection. Release HOLD pending architecture acceptance.'})
        generator=UnifiedReportGenerator(case.storage)
        original=generator.build_model
        captured={}
        def capture(*a,**kw):
            model=original(*a,**kw)
            captured.update(model)
            return model
        generator.build_model=capture
        report=generator.generate(case.assessment.assessment_id)
        model=captured
        states={row['submissionId']:row['cveAnalysisStatus'] for row in model['endpoints']}
        assert states=={'SUB-AUDIT-FULL':'COMPLETE','SUB-AUDIT-PARTIAL':'PARTIAL','SUB-AUDIT-COLLECTION-FAILED':'NOT_EVALUATED'},states
        assert model['cve']['status']=='PARTIAL'
        assert all(row['cveSummary']['providerStatus']=='SUCCESS' for row in model['endpoints'])
        assert model['integrity']['evidencePackageIntegrity']=='VERIFIED'
        assert model['integrity']['reportIntegrity']=='NOT_EVALUATED'
        assert model['administrativePrivileges']['observedAdminUsers']==1
        inherited=next(row for row in model['endpoints'] if row['submissionId']=='SUB-AUDIT-PARTIAL')
        assert inherited['administrativePrivileges']['membershipType']=='INHERITED_DOMAIN_GROUP'
        shutil.copyfile(report,output)
        sidecar=read_json(report.with_suffix('.integrity.json'))
        sidecar['reportPath']=output.name
        write_canonical_json(output.with_suffix('.integrity.json'),sidecar)
        write_canonical_json(output.with_suffix('.model.json'),model)
        # Independently reread saved bytes; never inject a VERIFIED assertion
        # into the report that is being verified.
        saved=read_json(output.with_suffix('.model.json'))
        recorded=saved['integrity'].pop('reportModelDigest')
        assert recorded==sha256_value(saved)==sidecar['reportModelDigest']
        assert sha256_bytes(output.read_bytes())==sidecar['reportDigest']
        combined=output.read_text(encoding='utf-8')+json.dumps(model)
        for identifier in ['AuditAlice_OnlyFixture','AUDIT-HOST-ONLYFIXTURE','S-1-5-21-111-222-333','AUDITDOMAIN','10.77.88.99']:
            assert identifier not in combined,'Prohibited synthetic identifier leaked'
        print('Synthetic audit report verified: COMPLETE / PARTIAL / NOT_EVALUATED; provider SUCCESS; privacy correlations and independent sidecar PASS.')
    finally:
        case.doCleanups()


if __name__=='__main__':
    main()
