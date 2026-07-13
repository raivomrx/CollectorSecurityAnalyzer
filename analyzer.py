"""Command-line analyzer orchestration for Collector Security Analyzer."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from analysis_context import AnalysisContext
from config import load_config
from cve.cache import NvdCache
from cve.client import NvdClient
from cve.cpe_resolver import CpeResolver
from cve.rate_limiter import SlidingWindowRateLimiter
from cve.service import CveService, empty_summary
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
    skip_cve: bool = False,
    refresh_cve_cache: bool = False,
    cve_debug: bool = False,
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
    _run_cve_scan(context, skip_cve, refresh_cve_cache, cve_debug)
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
        cve_summary=context.cve_summary,
        output_path=output_path,
    )
    LOGGER.info("Total Findings: %s", len(findings))
    LOGGER.info("Security Score: %s", score)
    LOGGER.info("HTML report generated: %s", report_path)
    return audit_findings, score, software_inventory, report_path


def _run_cve_scan(
    context: AnalysisContext,
    skip_cve: bool,
    refresh_cve_cache: bool,
    cve_debug: bool,
) -> None:
    """Run the CVE scan and store results on the analysis context."""

    config = load_config()
    cve_config = config.get("CVE", {}) if isinstance(config.get("CVE", {}), dict) else {}
    if cve_debug:
        logging.getLogger("cve").setLevel(logging.DEBUG)
    if skip_cve or not cve_config.get("Enabled", True):
        context.cve_summary = None
        return

    cache = NvdCache()
    if refresh_cve_cache:
        cache.clear_all()
    else:
        cache.clear_expired()

    has_api_key = bool(__import__("os").getenv(str(cve_config.get("ApiKeyEnvironmentVariable", "NVD_API_KEY"))))
    rate_config_key = "RateLimitWithApiKey" if has_api_key else "RateLimitWithoutApiKey"
    rate_config = cve_config.get(rate_config_key, {})
    if not isinstance(rate_config, dict):
        rate_config = {}

    try:
        limiter = SlidingWindowRateLimiter(
            requests=int(rate_config.get("Requests", 50 if has_api_key else 5)),
            window_seconds=int(rate_config.get("WindowSeconds", 30)),
        )
        client = NvdClient(
            timeout=int(cve_config.get("RequestTimeoutSeconds", 30)),
            max_retries=int(cve_config.get("MaxRetries", 3)),
            cache_ttl_hours=int(cve_config.get("CacheTtlHours", 24)),
            api_key_env_var=str(cve_config.get("ApiKeyEnvironmentVariable", "NVD_API_KEY")),
            cache=cache,
            limiter=limiter,
        )
        resolver = CpeResolver(
            client=client,
            minimum_confidence=int(cve_config.get("MinimumCpeConfidence", 80)),
            ambiguous_score_difference=int(cve_config.get("AmbiguousScoreDifference", 5)),
        )
        service = CveService(
            client=client,
            resolver=resolver,
            minimum_cpe_confidence=int(cve_config.get("MinimumCpeConfidence", 80)),
        )
        context.cve_summary = service.scan_inventory(context.software_inventory)
    except Exception as error:
        LOGGER.exception("CVE service failed")
        context.cve_summary = empty_summary(scan_complete=False, message=str(error))


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
    argument_parser.add_argument("--skip-cve", action="store_true", help="Skip CVE scanning")
    argument_parser.add_argument(
        "--refresh-cve-cache",
        action="store_true",
        help="Clear CVE cache before scanning",
    )
    argument_parser.add_argument("--cve-debug", action="store_true", help="Enable CVE debug logging")
    args = argument_parser.parse_args()

    setup_logging(level=args.log_level)
    analyze_file(
        args.input,
        skip_cve=args.skip_cve,
        refresh_cve_cache=args.refresh_cve_cache,
        cve_debug=args.cve_debug,
    )


if __name__ == "__main__":
    main()
