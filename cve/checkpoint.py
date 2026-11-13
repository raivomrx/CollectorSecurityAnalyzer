"""Private, input/version-bound product checkpoints for interrupted analysis."""
from dataclasses import asdict
from datetime import datetime
from enum import Enum
import hashlib
import json
from pathlib import Path
import time

from csa_console.canonical import write_canonical_json
from cve.models import (CveAssessment,CveRecord,CpeCandidate,CveScanSummary,CveProductEvaluation,
                        CveScanError,ApplicabilityStatus,CveDataQuality,CpeMatchStatus)
from software.models import SoftwareProduct


def encode(value):
    if isinstance(value,Enum): return value.value
    if isinstance(value,datetime): return value.isoformat()
    raise TypeError(type(value).__name__)


def restore_summary(value):
    value=dict(value)
    rows=[]
    for row in value['assessments']:
        row=dict(row);record=dict(row['cve'])
        for key in ('published','last_modified'):
            if record[key]: record[key]=datetime.fromisoformat(record[key])
        record['data_quality']=CveDataQuality(record['data_quality'])
        cpe=dict(row['cpe']) if row['cpe'] else None
        if cpe: cpe['match_status']=CpeMatchStatus(cpe['match_status']);cpe=CpeCandidate(**cpe)
        software=dict(row['software'])
        if software.get('install_date'): software['install_date']=datetime.fromisoformat(software['install_date'])
        rows.append(CveAssessment(**{**row,'software':SoftwareProduct(**software),
            'cve':CveRecord(**record),'cpe':cpe,'applicability':ApplicabilityStatus(row['applicability'])}))
    value['assessments']=rows
    value['product_evaluations']=[CveProductEvaluation(**row) for row in value['product_evaluations']]
    value['errors']=[CveScanError(**row) for row in value['errors']]
    return CveScanSummary(**value)


class ProductCheckpoint:
    def __init__(self,path,scope,ttl_seconds=86400):
        self.path=Path(path);self.scope=scope;self.ttl_seconds=ttl_seconds

    def load(self):
        try:
            value=json.loads(self.path.read_bytes())
            if value['schema']!=1 or value['scope']!=self.scope or time.time()<value['savedAt']:
                return None
            summary=restore_summary(value['summary'])
            summary.telemetry.update(checkpointSavedAt=value['savedAt'],checkpointStale=time.time()-value['savedAt']>=self.ttl_seconds)
            return summary
        except (OSError,ValueError,KeyError,TypeError): return None

    def save(self,summary):
        serialized=json.loads(json.dumps(asdict(summary),default=encode,ensure_ascii=False))
        write_canonical_json(self.path,{'schema':1,'scope':self.scope,'savedAt':time.time(),'summary':serialized})


def checkpoint_scope(raw_data,configuration):
    from csa_console.collector_package import COLLECTOR_VERSION
    from cve.cpe_resolver import DEFAULT_MAPPING_PATH
    mappings=[hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None for p in (
        DEFAULT_MAPPING_PATH,DEFAULT_MAPPING_PATH.with_name('cpe_discovery_aliases.json'))]
    return hashlib.sha256(json.dumps([COLLECTOR_VERSION,raw_data,configuration,mappings],sort_keys=True,
        separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest()
