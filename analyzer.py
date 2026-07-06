"""Command-line analyzer orchestration for Collector Security Analyzer."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from logger import setup_logging
from knowledge.repository import KnowledgeRepository
from parser import parse_collector_file
from risk import AuditFinding, Finding
from rules.loader import load_rules
from scoring import calculate_score

LOGGER = logging.getLogger(__name__)


def analyze_file(path: str | Path) -> tuple[list[AuditFinding], int]:
    """Analyze a collector JSON file and return audit findings with the score."""

    data = parse_collector_file(path)
    repository = KnowledgeRepository()
    rules = load_rules()
    findings: list[Finding] = []

    for rule in rules:
        findings.extend(rule.check(data))

    score = calculate_score(findings)
    audit_findings = enrich_findings(findings, repository)
    LOGGER.info("Total Findings: %s", len(findings))
    LOGGER.info("Security Score: %s", score)
    return audit_findings, score


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
