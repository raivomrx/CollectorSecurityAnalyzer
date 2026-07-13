"""Command-line analyzer orchestration for Collector Security Analyzer."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from analysis_context import AnalysisContext
from logger import setup_logging
from knowledge.repository import KnowledgeRepository
from parser import parse_collector_file
from report import generate_html_report
from risk import AuditFinding, Finding
from rules.loader import load_registry
from scoring import calculate_score
from software.inventory import build_inventory
from software.models import SoftwareInventory

LOGGER = logging.getLogger(__name__)


def analyze_file(
    path: str | Path,
    output_dir: str | Path = "output",
) -> tuple[list[AuditFinding], int, SoftwareInventory, Path]:
    """Analyze a collector JSON file and generate an HTML report."""

    input_path = Path(path)
    data = parse_collector_file(input_path)
    repository = KnowledgeRepository()
    registry = load_registry()
    software_items = data.get("Software", [])
    software_inventory = build_inventory(
        software_items if isinstance(software_items, list) else []
    )
    context = AnalysisContext(
        raw_data=data,
        software_inventory=software_inventory,
    )
    findings: list[Finding] = []

    for rule in registry.get_enabled():
        findings.extend(rule.run(data, context))

    score = calculate_score(findings)
    audit_findings = enrich_findings(findings, repository)
    rule_metadata = {
        execution.rule_id: metadata
        for execution in registry.get_execution_info()
        for metadata in [registry.get_metadata(execution.rule_id)]
        if metadata is not None
    }
    output_path = Path(output_dir) / f"{input_path.stem}.html"
    report_path = generate_html_report(
        data=data,
        audit_findings=audit_findings,
        score=score,
        software_inventory=software_inventory,
        rule_metadata=rule_metadata,
        output_path=output_path,
    )
    LOGGER.info("Total Findings: %s", len(findings))
    LOGGER.info("Security Score: %s", score)
    LOGGER.info("HTML report generated: %s", report_path)
    return audit_findings, score, software_inventory, report_path


def enrich_findings(
    findings: list[Finding],
    repository: KnowledgeRepository | None = None,
) -> list[AuditFinding]:
    """Merge technical findings with knowledge-base entries."""

    repository = KnowledgeRepository() if repository is None else repository
    return [
        AuditFinding(finding=finding, knowledge=repository.get(finding.rule_id))
        for finding in findings
    ]


def main() -> None:
    """Run the analyzer from command-line arguments."""

    argument_parser = argparse.ArgumentParser(description="Collector Security Analyzer")
    argument_parser.add_argument("input", help="Path to collector JSON file")
    argument_parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level, for example DEBUG, INFO, WARNING, or ERROR",
    )
    args = argument_parser.parse_args()

    setup_logging(level=args.log_level)
    analyze_file(args.input)


if __name__ == "__main__":
    main()
