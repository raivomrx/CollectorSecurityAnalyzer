"""HTML report generation for Collector Security Analyzer."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from risk import AuditFinding
from rules.metadata import RuleMetadata
from software.models import SoftwareInventory, SoftwareProduct
from utils import safe_get

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
REPORT_TEMPLATE = "report.html"
STYLE_FILE = "style.css"


def generate_html_report(
    data: dict[str, Any],
    audit_findings: list[AuditFinding],
    score: int,
    software_inventory: SoftwareInventory,
    rule_metadata: dict[str, RuleMetadata],
    output_path: str | Path,
) -> Path:
    """Generate an HTML audit report from analyzer results."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    _copy_stylesheet(output.parent)

    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    environment.filters["json"] = _to_pretty_json
    environment.filters["confidence_class"] = _confidence_class
    template = environment.get_template(REPORT_TEMPLATE)
    html = template.render(
        data=data,
        summary=_build_summary(data, audit_findings, score),
        audit_findings=audit_findings,
        high_findings=_high_findings(audit_findings),
        score=score,
        software_inventory=software_inventory,
        metadata=_build_metadata(audit_findings),
        rule_metadata=rule_metadata,
    )
    output.write_text(html, encoding="utf-8")
    return output


def _build_summary(
    data: dict[str, Any],
    audit_findings: list[AuditFinding],
    score: int,
) -> dict[str, Any]:
    """Build executive summary values for the report template."""

    findings = [audit_finding.finding for audit_finding in audit_findings]
    status_counts = Counter(finding.status.value for finding in findings)
    severity_counts = Counter(finding.severity.value for finding in findings)
    return {
        "computer_name": _first_value(data, "ComputerName", "Computer.Name"),
        "os": _first_value(data, "OS", "OperatingSystem", "Computer.OS"),
        "domain": _first_value(data, "Domain", "Workgroup", "Computer.Domain"),
        "forensics_date": _first_value(data, "ForensicsDate", "Forensics.Date"),
        "current_user": _first_value(data, "Current_user", "CurrentUser"),
        "score": score,
        "finding_count": len(audit_findings),
        "status_counts": status_counts,
        "severity_counts": severity_counts,
    }


def _build_metadata(audit_findings: list[AuditFinding]) -> list[dict[str, Any]]:
    """Build rule metadata rows from audit findings."""

    return [
        {
            "rule_id": item.finding.rule_id,
            "knowledge_version": item.knowledge.knowledge_version,
            "title": item.knowledge.title,
            "status": item.finding.status.value,
            "severity": item.finding.severity.value,
        }
        for item in audit_findings
    ]


def _high_findings(audit_findings: list[AuditFinding]) -> list[AuditFinding]:
    """Return critical and high findings."""

    return [
        item
        for item in audit_findings
        if item.finding.severity.value in {"CRITICAL", "HIGH"}
        and item.finding.status.value != "PASS"
    ]


def _first_value(data: dict[str, Any], *paths: str) -> Any:
    """Return the first non-empty value from supported summary paths."""

    for path in paths:
        value = safe_get(data, path)
        if value not in (None, ""):
            return value
    return "Unknown"


def _to_pretty_json(value: Any) -> str:
    """Format values as readable JSON."""

    return json.dumps(value, indent=2, default=str, ensure_ascii=False)


def _confidence_class(product: SoftwareProduct) -> str:
    """Return a CSS class for software confidence."""

    if product.confidence >= 95:
        return "confidence-high"
    if product.confidence >= 60:
        return "confidence-medium"
    return "confidence-low"


def _copy_stylesheet(output_dir: Path) -> None:
    """Copy report stylesheet next to the generated report."""

    source = TEMPLATE_DIR / STYLE_FILE
    if source.exists():
        shutil.copyfile(source, output_dir / STYLE_FILE)
