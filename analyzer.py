"""Command-line analyzer orchestration for Collector Security Analyzer."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from active_validation.authorization import load_authorization
from active_validation.engine import disabled_run, execute_active_validation
from active_validation.models import ActiveValidationRun
from active_validation.policy import load_policy
from analysis_context import AnalysisContext
from collector_schema.enums import PrivacyMode
from collector_schema.loader import load_collector_document
from collector_schema.validation import validate_schema_version, validate_v2_document
from compliance.engine import ComplianceEngine
from compliance.profile_resolver import ComplianceProfileResolver
from compliance.repository import FrameworkRepository
from config import load_config
from csa_console.identifiers import utc_text
from cve.cache import NvdCache
from cve.client import NvdClient
from cve.cpe_resolver import CpeResolver
from cve.enrichment_service import VulnerabilityEnrichmentService
from cve.providers.cisa_kev import (
    CisaKevProvider,
    DEFAULT_KEV_CACHE_PATH,
    DEFAULT_KEV_FEED_URL,
)
from cve.providers.cve_program import CveProgramCache, CveProgramProvider, DEFAULT_CVE_PROGRAM_CACHE_PATH
from cve.rate_limiter import SlidingWindowRateLimiter
from cve.service import CveService, empty_summary
from logger import setup_logging
from knowledge.repository import KnowledgeRepository
from parser import parse_collector_file
from evidence.normalization import normalize_windows_evidence
from frameworks.evaluator import FrameworkEvaluator
from frameworks.exceptions import FrameworkPackError
from frameworks.models import FrameworkPack
from frameworks.registry import FrameworkPackRegistry
from frameworks.serialization import write_analysis_json
from frameworks.validation import FrameworkPackValidator
from policies.loader import load_policy_profile
from report import generate_html_report
from risk import AuditFinding, Finding
from rules.loader import load_registry
from rules.registry import RuleRegistry
from scoring import calculate_score
from software.inventory import build_inventory
from software.lifecycle import LifecycleRepository
from software.models import LifecycleStatus, SoftwareInventory, SoftwareProduct

LOGGER = logging.getLogger(__name__)


def analyze_file(
    path: str | Path,
    output_dir: str | Path = "output",
    skip_cve: bool = False,
    refresh_cve_cache: bool = False,
    cve_debug: bool = False,
    skip_enrichment: bool = False,
    skip_kev: bool = False,
    skip_cve_program: bool = False,
    refresh_enrichment_cache: bool = False,
    cvelist_path: str | Path | None = None,
    skip_compliance: bool = False,
    compliance_profiles: list[str] | None = None,
    framework_filter: list[str] | None = None,
    framework_versions: dict[str, str] | None = None,
    cis_ig: str | None = None,
    validate_input: bool = False,
    policy_profile: str | Path | None = None,
    privacy_mode: str = "standard",
    skipped_categories: list[str] | None = None,
    skip_framework_packs: bool = False,
    framework_packs: list[str] | None = None,
    allow_unreviewed_frameworks: bool = False,
    active_validation: bool = False,
    active_policy: str | Path | None = None,
    active_authorization: str | Path | None = None,
    active_validators: list[str] | None = None,
    active_profile: str | None = None,
    active_plan_digest: str | None = None,
    analysis_metadata: dict[str, Any] | None = None,
    cve_progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[AuditFinding], int, SoftwareInventory, Path]:
    """Analyze a collector JSON file and generate an HTML report."""

    input_path = Path(path)
    if validate_input and input_path.suffix.casefold() == ".tmp":
        raise ValueError("Atomic incomplete collector output rejected")
    data = parse_collector_file(input_path)
    collector_document = load_collector_document(data, validate=validate_input)
    evidence_registry = normalize_windows_evidence(collector_document)
    policy = load_policy_profile(policy_profile)
    repository = KnowledgeRepository()
    registry = load_registry()
    software_items = collector_document.software.items or data.get("Software", [])
    software_inventory = build_inventory(
        software_items if isinstance(software_items, list) else [],
        collection_status=collector_document.software.collection_status,
        collection_errors=[
            str(item.get("code", "SOFTWARE_COLLECTION_ERROR"))
            for item in collector_document.software.errors
        ],
    )
    context = AnalysisContext(
        raw_data=data,
        software_inventory=software_inventory,
        collector_document=collector_document,
        evidence_registry=evidence_registry,
        policy_profile=policy,
        privacy_mode=PrivacyMode(privacy_mode),
        skipped_categories=skipped_categories or [],
    )
    _run_cve_scan(
        context,
        skip_cve,
        refresh_cve_cache,
        cve_debug,
        cve_progress_callback,
    )
    _emit_cve_progress(
        cve_progress_callback,
        phase="ENRICHING",
        products_processed=(
            context.cve_summary.eligible_products
            if context.cve_summary is not None
            else 0
        ),
        products_total=(
            context.cve_summary.eligible_products
            if context.cve_summary is not None
            else 0
        ),
    )
    _run_cve_enrichment(
        context=context,
        skip_enrichment=skip_enrichment,
        skip_kev=skip_kev,
        skip_cve_program=skip_cve_program,
        refresh_enrichment_cache=refresh_enrichment_cache,
        cvelist_path=cvelist_path,
        progress_callback=cve_progress_callback,
    )
    _emit_cve_progress(
        cve_progress_callback,
        phase="FINALIZING",
        products_processed=(
            context.cve_summary.eligible_products
            if context.cve_summary is not None
            else 0
        ),
        products_total=(
            context.cve_summary.eligible_products
            if context.cve_summary is not None
            else 0
        ),
    )
    if analysis_metadata is not None:
        analysis_metadata.update(_cve_analysis_metadata(context))
    findings: list[Finding] = []

    for rule in registry.get_enabled():
        findings.extend(rule.run(data, context))

    context.active_validation = _run_active_validation(
        enabled=active_validation,
        data=data,
        findings=findings,
        input_path=input_path,
        output_dir=output_dir,
        policy_path=active_policy,
        authorization_path=active_authorization,
        validators=active_validators,
        profile=active_profile,
        required_plan_digest=active_plan_digest,
    )

    score = calculate_score(findings)
    audit_findings = enrich_findings(findings, repository)
    _run_compliance_assessment(
        context=context,
        audit_findings=audit_findings,
        skip_compliance=skip_compliance,
        compliance_profiles=compliance_profiles,
        framework_filter=framework_filter,
        framework_versions=framework_versions,
        cis_ig=cis_ig,
    )
    _run_framework_evaluation(
        context,
        audit_findings,
        skip_framework_packs,
        framework_packs,
        registry,
        allow_unreviewed_frameworks,
    )
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
        cve_enrichment=context.cve_enrichment,
        compliance_summary=context.compliance_summary,
        collector_document=context.collector_document,
        evidence_registry=context.evidence_registry,
        policy_profile=context.policy_profile,
        privacy_mode=context.privacy_mode,
        framework_evaluations=context.framework_evaluations,
        active_validation=context.active_validation,
        output_path=output_path,
    )
    analysis_path = output_path.with_suffix(".analysis.json")
    write_analysis_json(
        context.framework_evaluations or [],
        analysis_path,
        active_validation=context.active_validation,
    )
    LOGGER.info("Total Findings: %s", len(findings))
    LOGGER.info("Security Score: %s", score)
    LOGGER.info("HTML report generated: %s", report_path)
    LOGGER.info("Framework analysis generated: %s", analysis_path)
    return audit_findings, score, software_inventory, report_path


def _cve_analysis_metadata(
    context: AnalysisContext,
) -> dict[str, Any]:
    """Build a JSON-safe CVE lifecycle and metric summary."""

    summary = context.cve_summary
    installed_count = context.software_inventory.product_count
    normalized_count = len(
        {
            (
                item.normalized_vendor,
                item.normalized_product,
                item.normalized_version,
                item.architecture,
            )
            for item in context.software_inventory.products
        }
    )
    lifecycle_repository = LifecycleRepository()
    lifecycle_results = lifecycle_repository.assess_inventory(
        context.software_inventory.products
    )
    base_metadata = {
        "softwareCollectionStatus": context.software_inventory.collection_status,
        "softwareCollectionErrors": context.software_inventory.collection_errors,
        "lifecycleDataVersion": lifecycle_repository.data_version,
        "operatingSystemLifecycle": _operating_system_lifecycle(
            context, lifecycle_repository
        ),
    }
    if summary is None:
        initial_status = (
            "NOT_EVALUATED"
            if context.software_inventory.collection_status != "SUCCESS"
            else "NOT_PERFORMED"
        )
        return {
            **base_metadata,
            "status": initial_status,
            "timestamp": "",
            "installedSoftwareRecords": installed_count,
            "normalizedProducts": normalized_count,
            "cveEligibleProducts": 0,
            "successfullyEvaluatedProducts": 0,
            "notEvaluatedProducts": 0,
            "uniqueCves": 0,
            "uniqueCveIds": [],
            "confirmedUniqueCves": 0,
            "confirmedCveIds": [],
            "confirmedProductCveRelationships": 0,
            "possibleUniqueCves": 0,
            "possibleCveIds": [],
            "possibleProductCveRelationships": 0,
            "criticalUniqueCves": 0,
            "criticalCveIds": [],
            "highUniqueCves": 0,
            "highCveIds": [],
            "cisaKevUniqueCves": 0,
            "cisaKevCveIds": [],
            "coveragePercent": 0.0,
            "providerCoverage": [],
            "productEvaluations": [],
            "softwareResults": _software_results(
                context.software_inventory,
                [],
                lifecycle_results,
                scan_status=initial_status,
                kev_ids=set(),
                product_evaluations=[],
            ),
        }

    assessments = summary.assessments
    confirmed = [
        item
        for item in assessments
        if item.applicability.value == "AFFECTED"
    ]
    possible = [
        item
        for item in assessments
        if item.applicability.value == "POSSIBLY_AFFECTED"
    ]
    confirmed_ids = {item.cve.cve_id for item in confirmed}
    possible_ids = {item.cve.cve_id for item in possible}
    relevant = confirmed + possible
    unique_ids = confirmed_ids | possible_ids
    critical_ids = {
        item.cve.cve_id
        for item in relevant
        if item.cve.severity.upper() == "CRITICAL"
    }
    high_ids = {
        item.cve.cve_id
        for item in relevant
        if item.cve.severity.upper() == "HIGH"
    }
    enrichment = context.cve_enrichment
    nvd_status = (
        "COMPLETE"
        if summary.scan_complete and summary.coverage_complete
        else "PARTIAL"
        if summary.scanned_products > 0 or summary.evaluated_products > 0
        else "FAILED"
    )
    provider_coverage = [
        {
            "provider": "NVD",
            "status": nvd_status,
            "recordsLoaded": len({item.cve.cve_id for item in assessments}),
            "usedStaleCache": False,
        }
    ]
    if enrichment is not None:
        provider_coverage.extend(
            [
                {
                    "provider": item.provider,
                    "status": (
                        "COMPLETE"
                        if item.succeeded and not item.partial
                        else "PARTIAL"
                        if item.succeeded or item.partial
                        else "FAILED"
                    ),
                    "recordsLoaded": item.records_loaded,
                    "usedStaleCache": item.used_stale_cache,
                }
                for item in enrichment.provider_statuses
                if item.enabled
            ]
        )
    kev_ids = (
        {
            item.base_assessment.cve.cve_id
            for item in enrichment.assessments
            if item.kev is not None
            and item.base_assessment.applicability.value
            in {"AFFECTED", "POSSIBLY_AFFECTED"}
        }
        if enrichment is not None
        else set()
    )
    status = (
        "NOT_EVALUATED"
        if context.software_inventory.collection_status != "SUCCESS"
        else nvd_status
    )
    return {
        **base_metadata,
        "status": status,
        "timestamp": utc_text(),
        "installedSoftwareRecords": summary.scanned_products,
        "normalizedProducts": summary.unique_products,
        "cveEligibleProducts": summary.eligible_products,
        "successfullyEvaluatedProducts": summary.evaluated_products,
        "notEvaluatedProducts": max(
            0, summary.eligible_products - summary.evaluated_products
        ),
        "uniqueCves": len(unique_ids),
        "uniqueCveIds": sorted(unique_ids),
        "confirmedUniqueCves": len(confirmed_ids),
        "confirmedCveIds": sorted(confirmed_ids),
        "confirmedProductCveRelationships": len(confirmed),
        "possibleUniqueCves": len(possible_ids),
        "possibleCveIds": sorted(possible_ids),
        "possibleProductCveRelationships": len(possible),
        "criticalUniqueCves": len(critical_ids),
        "criticalCveIds": sorted(critical_ids),
        "highUniqueCves": len(high_ids),
        "highCveIds": sorted(high_ids),
        "cisaKevUniqueCves": (
            enrichment.unique_known_exploited_cves
            if enrichment is not None
            else 0
        ),
        "cisaKevCveIds": sorted(kev_ids),
        "coveragePercent": summary.coverage_percent,
        "providerCoverage": provider_coverage,
        "productEvaluations": [
            _product_evaluation_dict(item)
            for item in summary.product_evaluations
        ],
        "softwareResults": _software_results(
            context.software_inventory,
            assessments,
            lifecycle_results,
            scan_status=status,
            kev_ids=kev_ids,
            product_evaluations=summary.product_evaluations,
        ),
    }


def _software_results(
    inventory: SoftwareInventory,
    assessments: list[Any],
    lifecycle_results: list[Any],
    *,
    scan_status: str,
    kev_ids: set[str],
    product_evaluations: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Build report-safe software/CVE/lifecycle relationships."""

    rows: list[dict[str, Any]] = []
    evaluation_by_key = {
        item.product_key: item for item in (product_evaluations or [])
    }
    for product, lifecycle in zip(inventory.products, lifecycle_results):
        pipeline = evaluation_by_key.get(_cve_product_key(product))
        related = [
            item for item in assessments
            if _software_key(item.software) == _software_key(product)
        ]
        confirmed = [item for item in related if item.applicability.value == "AFFECTED"]
        possible = [item for item in related if item.applicability.value == "POSSIBLY_AFFECTED"]
        not_evaluated = [item for item in related if item.applicability.value == "NOT_EVALUATED"]
        if product.confidence < 60:
            evaluation_status = "NOT_EVALUATED"
        elif confirmed:
            evaluation_status = "CONFIRMED"
        elif possible:
            evaluation_status = "POSSIBLE"
        elif scan_status == "COMPLETE" and not not_evaluated:
            evaluation_status = "NO_KNOWN_VULNERABILITIES"
        else:
            evaluation_status = "NOT_EVALUATED"
        relevant = confirmed + possible + not_evaluated
        details = [
            {
                "cveId": item.cve.cve_id,
                "severity": item.cve.severity,
                "cvssScore": item.cve.cvss_score,
                "matchStatus": item.applicability.value,
                "matchRationale": item.reason,
                "affectedVersionRange": ", ".join(item.matched_criteria),
                "cisaKev": item.cve.cve_id in kev_ids,
                "fixedVersions": [],
                "vendorAdvisoryUrls": [],
                "references": list(item.cve.references),
                "publishedDate": (
                    item.cve.published.isoformat()
                    if item.cve.published
                    else None
                ),
                "lastModifiedDate": (
                    item.cve.last_modified.isoformat()
                    if item.cve.last_modified
                    else None
                ),
                "source": "NVD",
            }
            for item in sorted(relevant, key=lambda value: value.cve.cve_id)
        ]
        lifecycle_status = lifecycle.status.value
        if lifecycle.status == LifecycleStatus.OUT_OF_SUPPORT and confirmed:
            security_status = "Both vulnerable and out of support"
        elif lifecycle.status == LifecycleStatus.OUT_OF_SUPPORT:
            security_status = "Out of support"
        elif confirmed:
            security_status = "Known vulnerabilities"
        elif possible:
            security_status = "Possible vulnerabilities"
        elif product.confidence < 60:
            security_status = "Normalization failed"
        elif evaluation_status == "NO_KNOWN_VULNERABILITIES":
            security_status = "No known issue"
        else:
            security_status = "Not evaluated"
        rows.append(
            {
                "productKey": "|".join(_software_key(product)),
                "displayName": product.product,
                "displayVersion": product.version,
                "publisher": product.vendor,
                "architecture": product.architecture or "UNKNOWN",
                "scope": product.scope,
                "source": product.source,
                "installDate": (
                    product.install_date.isoformat()
                    if product.install_date
                    else None
                ),
                "installLocation": product.install_location,
                "normalizedVendor": product.normalized_vendor,
                "normalizedProduct": product.normalized_product,
                "normalizedVersion": product.normalized_version,
                "normalizationConfidence": product.confidence,
                "normalizationStatus": product.normalization_status,
                "cpe": product.cpe,
                "cvePipeline": (
                    _product_evaluation_dict(pipeline)
                    if pipeline is not None
                    else {
                        "productKey": _cve_product_key(product),
                        "normalizationStatus": product.normalization_status,
                        "normalizationConfidence": product.confidence,
                        "eligibilityStatus": "NOT_EVALUATED",
                        "provider": "NVD",
                        "productMappingStatus": "NOT_RUN",
                        "cpeCandidateCount": 0,
                        "providerQueryStatus": "NOT_RUN",
                        "providerReason": "CVE analysis was not performed",
                        "reason": "CVE analysis was not performed",
                        "versionEvaluationStatus": "NOT_RUN",
                        "cveResultStatus": "NOT_EVALUATED",
                        "terminalStatus": "NOT_EVALUATED",
                        "failureStage": "CVE_SCAN",
                        "failureReason": "CVE analysis was not performed",
                        "retryable": False,
                    }
                ),
                "securityStatus": security_status,
                "cveEvaluationStatus": evaluation_status,
                "confirmedCves": len(
                    {item.cve.cve_id for item in confirmed}
                ),
                "possibleCves": len(
                    {item.cve.cve_id for item in possible}
                ),
                "cisaKevCves": len(
                    {
                        item.cve.cve_id
                        for item in relevant
                        if item.cve.cve_id in kev_ids
                    }
                ),
                "highestSeverity": _highest_cve_severity(relevant),
                "cveDetails": details,
                "lifecycleStatus": lifecycle_status,
                "endOfSupportDate": (
                    lifecycle.end_of_support_date.isoformat()
                    if lifecycle.end_of_support_date
                    else None
                ),
                "lifecycleSource": lifecycle.source,
                "lifecycleDataVersion": lifecycle.data_version,
                "lifecycleConfidence": lifecycle.confidence,
                "lifecycleRationale": lifecycle.rationale,
            }
        )
    return rows


def _operating_system_lifecycle(
    context: AnalysisContext,
    repository: LifecycleRepository,
) -> dict[str, Any]:
    """Assess the endpoint operating system using the same content pack."""

    operating_system = (
        context.collector_document.operating_system
        if context.collector_document
        else None
    )
    name = str(operating_system.name or "") if operating_system else ""
    if "Windows 11" in name:
        product_name = "Windows 11"
    elif "Windows 10" in name:
        product_name = "Windows 10"
    elif "Windows Server" in name:
        product_name = "Windows Server"
    else:
        product_name = name
    version = (
        str(operating_system.version or operating_system.build or "")
        if operating_system
        else ""
    )
    product = SoftwareProduct(
        vendor="Microsoft",
        product=product_name,
        version=version,
        normalized_vendor="Microsoft",
        normalized_product=product_name,
        normalized_version=version,
        confidence=100 if product_name else 0,
    )
    result = repository.assess(product)
    return {
        "product": product_name,
        "version": product.version,
        "status": result.status.value,
        "endOfSupportDate": (
            result.end_of_support_date.isoformat()
            if result.end_of_support_date
            else None
        ),
        "source": result.source,
        "dataVersion": result.data_version,
        "confidence": result.confidence,
        "rationale": result.rationale,
    }


def _software_key(product: SoftwareProduct) -> tuple[str, str, str, str, str]:
    return (
        product.normalized_vendor,
        product.normalized_product,
        product.normalized_version,
        product.architecture or "",
        product.scope,
    )


def _cve_product_key(product: SoftwareProduct) -> str:
    """Return the product identity used by the CVE scan audit trail."""

    return "|".join(
        [
            product.normalized_vendor,
            product.normalized_product,
            product.normalized_version,
            product.architecture or "",
        ]
    )


def _product_evaluation_dict(evaluation: Any) -> dict[str, Any]:
    """Serialize a product evaluation without provider response bodies."""

    return {
        "productKey": evaluation.product_key,
        "displayName": evaluation.display_name,
        "version": evaluation.version,
        "normalizationStatus": evaluation.normalization_status,
        "normalizationConfidence": evaluation.normalization_confidence,
        "eligibilityStatus": evaluation.eligibility_status,
        "provider": evaluation.provider,
        "productMappingStatus": evaluation.product_mapping_status,
        "cpeCandidateCount": evaluation.cpe_candidate_count,
        "cpe": evaluation.cpe,
        "providerQueryStatus": evaluation.provider_query_status,
        "providerReason": evaluation.provider_reason,
        "reason": evaluation.provider_reason,
        "versionEvaluationStatus": evaluation.version_evaluation_status,
        "cveResultStatus": evaluation.cve_result_status,
        "recordsReceived": evaluation.records_received,
        "confirmedCves": evaluation.confirmed_cves,
        "possibleCves": evaluation.possible_cves,
        "notAffectedCves": evaluation.not_affected_cves,
        "terminalStatus": evaluation.terminal_status,
        "failureStage": evaluation.failure_stage,
        "failureReason": evaluation.failure_reason,
        "retryable": evaluation.retryable,
    }


def _highest_cve_severity(values: list[Any]) -> str:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return min(
        (str(item.cve.severity).upper() for item in values),
        key=lambda value: order.get(value, 9),
        default="NONE",
    )


def _run_active_validation(
    enabled: bool,
    data: dict[str, object],
    findings: list[Finding],
    input_path: Path,
    output_dir: str | Path,
    policy_path: str | Path | None,
    authorization_path: str | Path | None,
    validators: list[str] | None,
    profile: str | None,
    required_plan_digest: str | None,
) -> ActiveValidationRun:
    """Run active validation only with explicit policy and authorization."""

    if not enabled:
        return disabled_run()
    missing = []
    if policy_path is None:
        missing.append("active policy")
    if authorization_path is None:
        missing.append("active authorization")
    if not validators and not profile:
        missing.append("validator selection or profile")
    if missing:
        return ActiveValidationRun(
            enabled=True,
            state="BLOCKED",
            warnings=[
                "Active validation blocked: missing " + ", ".join(missing)
            ],
        )
    policy = load_policy(policy_path)
    if not policy.enabled:
        return ActiveValidationRun(
            enabled=True,
            state="BLOCKED",
            policy_digest=policy.digest,
            warnings=["Active validation blocked: policy is disabled"],
        )
    authorization = load_authorization(active_authorization)
    audit_path = (
        Path(output_dir) / f"{input_path.stem}.active-validation.audit.jsonl"
    )
    return execute_active_validation(
        data=data,
        findings=findings,
        policy=policy,
        authorization=authorization,
        requested_validator_ids=validators or [],
        audit_path=audit_path,
        profile=profile,
        required_plan_digest=required_plan_digest,
    )


def _run_cve_scan(
    context: AnalysisContext,
    skip_cve: bool,
    refresh_cve_cache: bool,
    cve_debug: bool,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
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
        context.cve_summary = service.scan_inventory(
            context.software_inventory,
            context.raw_data,
            progress_callback,
        )
    except Exception as error:
        LOGGER.exception("CVE service failed")
        context.cve_summary = empty_summary(scan_complete=False, message=str(error))


def _emit_cve_progress(
    callback: Callable[[dict[str, Any]], None] | None,
    **details: Any,
) -> None:
    """Publish optional CVE orchestration progress without affecting results."""

    if callback is None:
        return
    try:
        callback(details)
    except Exception:
        LOGGER.exception("CVE progress callback failed")


def _run_cve_enrichment(
    context: AnalysisContext,
    skip_enrichment: bool,
    skip_kev: bool,
    skip_cve_program: bool,
    refresh_enrichment_cache: bool,
    cvelist_path: str | Path | None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """Run multi-source CVE enrichment when enabled."""

    if context.cve_summary is None:
        context.cve_enrichment = None
        return

    config = load_config()
    enrichment_config = config.get("VulnerabilityEnrichment", {})
    if not isinstance(enrichment_config, dict):
        enrichment_config = {}
    if skip_enrichment or not enrichment_config.get("Enabled", True):
        context.cve_enrichment = None
        return

    if refresh_enrichment_cache and DEFAULT_KEV_CACHE_PATH.exists():
        DEFAULT_KEV_CACHE_PATH.unlink()
    if refresh_enrichment_cache and DEFAULT_CVE_PROGRAM_CACHE_PATH.exists():
        CveProgramCache().clear_all()

    providers = []
    kev_config = enrichment_config.get("CisaKev", {})
    if not isinstance(kev_config, dict):
        kev_config = {}
    if not skip_kev and kev_config.get("Enabled", True):
        providers.append(
            CisaKevProvider(
                feed_url=str(kev_config.get("FeedUrl", DEFAULT_KEV_FEED_URL)),
                cache_ttl_hours=int(kev_config.get("CacheTtlHours", 6)),
                allow_stale_cache=bool(kev_config.get("AllowStaleCache", True)),
            )
        )

    cve_program_config = enrichment_config.get("CveProgram", {})
    if not isinstance(cve_program_config, dict):
        cve_program_config = {}
    if not skip_cve_program and cve_program_config.get("Enabled", True):
        providers.append(
            CveProgramProvider(
                mode=str(cve_program_config.get("Mode", "REMOTE_RECORD")),
                local_repository_path=cvelist_path or str(cve_program_config.get("LocalRepositoryPath", "")),
                raw_base_url=str(cve_program_config.get("RawBaseUrl", "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves")),
                cache_ttl_hours=int(cve_program_config.get("CacheTtlHours", 24)),
                allow_stale_cache=bool(cve_program_config.get("AllowStaleCache", True)),
            )
        )

    priority_config = config.get("Prioritization", {})
    if not isinstance(priority_config, dict):
        priority_config = {}
    try:
        context.cve_enrichment = VulnerabilityEnrichmentService(
            providers=providers,
            prioritization_weights=priority_config,
            enrich_not_affected=bool(enrichment_config.get("EnrichNotAffected", False)),
        ).enrich_summary(
            context.cve_summary,
            progress_callback=lambda details: _emit_cve_progress(
                progress_callback,
                phase="ENRICHING",
                products_processed=context.cve_summary.eligible_products,
                products_total=context.cve_summary.eligible_products,
                **details,
            ),
        )
    except Exception:
        LOGGER.exception("CVE enrichment failed")
        context.cve_enrichment = None


def _run_compliance_assessment(
    context: AnalysisContext,
    audit_findings: list[AuditFinding],
    skip_compliance: bool,
    compliance_profiles: list[str] | None,
    framework_filter: list[str] | None,
    framework_versions: dict[str, str] | None,
    cis_ig: str | None,
) -> None:
    """Run compliance assessment and store it on context."""

    if skip_compliance:
        context.compliance_summary = None
        return
    try:
        repository = FrameworkRepository()
        resolver = ComplianceProfileResolver(repository)
        profiles = resolver.resolve(context, compliance_profiles, cis_ig)
        engine = ComplianceEngine(
            repository=repository,
            framework_filter=framework_filter,
            framework_versions=framework_versions,
        )
        context.compliance_summary = engine.assess(context, audit_findings, profiles)
        context.compliance_summary.warnings.extend(resolver.warnings)
    except Exception:
        LOGGER.exception("Compliance assessment failed")
        context.compliance_summary = None


def _run_framework_evaluation(
    context: AnalysisContext,
    audit_findings: list[AuditFinding],
    skip_framework_packs: bool,
    selections: list[str] | None,
    rule_registry: RuleRegistry,
    allow_unreviewed_frameworks: bool,
) -> None:
    """Evaluate selected versioned framework packs from technical findings."""

    if skip_framework_packs:
        context.framework_evaluations = None
        return
    try:
        registry = FrameworkPackRegistry()
        packs = (
            [_resolve_framework_pack(registry, selection) for selection in selections]
            if selections
            else registry.load_defaults()
        )
        evaluator = FrameworkEvaluator()
        validator = FrameworkPackValidator(rule_registry)
        evaluations = []
        for pack in packs:
            errors = validator.validate(pack)
            if errors:
                raise FrameworkPackError(
                    f"Invalid framework pack {pack.framework_id}:{pack.version}: "
                    + "; ".join(errors)
                )
            evaluations.append(
                evaluator.evaluate(
                    pack,
                    audit_findings,
                    allow_unreviewed=allow_unreviewed_frameworks,
                )
            )
        context.framework_evaluations = evaluations
    except FrameworkPackError:
        LOGGER.exception("Framework pack evaluation failed")
        context.framework_evaluations = None
        raise
    except Exception:
        LOGGER.exception("Framework pack evaluation failed")
        context.framework_evaluations = None


def _resolve_framework_pack(
    registry: FrameworkPackRegistry,
    selection: str,
) -> FrameworkPack:
    """Resolve FRAMEWORK[:VERSION] selection syntax."""

    framework_id, separator, version = selection.partition(":")
    return registry.resolve(framework_id, version if separator else "latest")


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
    argument_parser.add_argument("input", nargs="?", help="Path to collector JSON file")
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
    argument_parser.add_argument("--skip-enrichment", action="store_true", help="Skip CVE enrichment")
    argument_parser.add_argument("--skip-kev", action="store_true", help="Skip CISA KEV enrichment")
    argument_parser.add_argument("--skip-cve-program", action="store_true", help="Skip CVE Program enrichment")
    argument_parser.add_argument(
        "--refresh-enrichment-cache",
        action="store_true",
        help="Clear enrichment cache before scanning",
    )
    argument_parser.add_argument("--cvelist-path", help="Path to local cvelistV5 repository")
    argument_parser.add_argument("--skip-compliance", action="store_true", help="Skip compliance assessment")
    argument_parser.add_argument(
        "--compliance-profile",
        action="append",
        help="Compliance profile ID to use; may be repeated",
    )
    argument_parser.add_argument(
        "--framework",
        action="append",
        help="Framework ID to assess; may be repeated",
    )
    argument_parser.add_argument(
        "--framework-pack",
        action="append",
        help="Versioned framework pack as FRAMEWORK[:VERSION]; may be repeated",
    )
    argument_parser.add_argument(
        "--skip-framework-packs",
        action="store_true",
        help="Skip versioned framework traceability evaluation",
    )
    argument_parser.add_argument(
        "--allow-unreviewed-frameworks",
        action="store_true",
        help="Allow REVIEW_REQUIRED packs in traceability-only mode",
    )
    argument_parser.add_argument(
        "--framework-version",
        action="append",
        default=[],
        help="Framework version override in FRAMEWORK=VERSION format",
    )
    argument_parser.add_argument("--cis-ig", choices=["IG1", "IG2", "IG3"], help="Add CIS IG endpoint profile")
    argument_parser.add_argument("--list-compliance-profiles", action="store_true", help="List compliance profiles")
    argument_parser.add_argument("--list-frameworks", action="store_true", help="List compliance frameworks")
    argument_parser.add_argument("--validate-input", action="store_true", help="Validate collector schema before analysis")
    argument_parser.add_argument("--show-schema-version", action="store_true", help="Print input collector schema version")
    argument_parser.add_argument("--policy-profile", help="Policy profile path or ID")
    argument_parser.add_argument(
        "--privacy-mode",
        choices=[mode.value for mode in PrivacyMode],
        default=PrivacyMode.STANDARD.value,
        help="Report privacy mode",
    )
    argument_parser.add_argument("--list-evidence-categories", action="store_true", help="List normalized evidence categories")
    argument_parser.add_argument("--skip-category", action="append", default=[], help="Skip rules in an evidence category")
    argument_parser.add_argument(
        "--active-validation",
        action="store_true",
        help="Request explicitly authorized active validation",
    )
    argument_parser.add_argument(
        "--active-policy",
        help="Path to active validation safety policy",
    )
    argument_parser.add_argument(
        "--active-authorization",
        "--authorization-file",
        dest="active_authorization",
        help="Path to active validation authorization",
    )
    argument_parser.add_argument(
        "--validator",
        action="append",
        help="Explicit active validator ID; may be repeated",
    )
    argument_parser.add_argument(
        "--active-profile",
        choices=[
            "safe-read-only",
            "safe-local",
            "controlled-temporary",
            "deep-responder-validation",
        ],
        help="Explicit active validation risk profile",
    )
    argument_parser.add_argument(
        "--require-plan-digest",
        help="Require the exact previously previewed active validation plan",
    )
    args = argument_parser.parse_args()

    setup_logging(level=args.log_level)
    if args.list_compliance_profiles or args.list_frameworks:
        _print_compliance_catalog(args.list_compliance_profiles, args.list_frameworks)
        return
    if args.show_schema_version or args.list_evidence_categories:
        if not args.input:
            argument_parser.error("input is required for schema or evidence listing")
        data = parse_collector_file(args.input)
        if args.show_schema_version:
            validate_schema_version(data)
            print(str(data.get("schemaVersion") or data.get("schema_version") or "1.x"))
        if args.list_evidence_categories:
            document = load_collector_document(data, validate=args.validate_input)
            registry = normalize_windows_evidence(document)
            for category in sorted({setting.category for setting in registry.all()}):
                print(category)
        return
    if not args.input:
        argument_parser.error("input is required unless listing compliance profiles or frameworks")
    if args.validate_input:
        if Path(args.input).suffix.casefold() == ".tmp":
            raise ValueError("Atomic incomplete collector output rejected")
        data = parse_collector_file(args.input)
        if str(data.get("schemaVersion") or data.get("schema_version") or "1.0").startswith("2."):
            validate_v2_document(data)
    compliance_frameworks, framework_packs = _partition_framework_args(
        args.framework,
        args.framework_pack,
    )
    analyze_file(
        args.input,
        skip_cve=args.skip_cve,
        refresh_cve_cache=args.refresh_cve_cache,
        cve_debug=args.cve_debug,
        skip_enrichment=args.skip_enrichment,
        skip_kev=args.skip_kev,
        skip_cve_program=args.skip_cve_program,
        refresh_enrichment_cache=args.refresh_enrichment_cache,
        cvelist_path=args.cvelist_path,
        skip_compliance=args.skip_compliance,
        compliance_profiles=args.compliance_profile,
        framework_filter=compliance_frameworks,
        framework_versions=_parse_framework_versions(args.framework_version),
        cis_ig=args.cis_ig,
        validate_input=args.validate_input,
        policy_profile=args.policy_profile,
        privacy_mode=args.privacy_mode,
        skipped_categories=args.skip_category,
        skip_framework_packs=args.skip_framework_packs,
        framework_packs=framework_packs,
        allow_unreviewed_frameworks=args.allow_unreviewed_frameworks,
        active_validation=args.active_validation,
        active_policy=args.active_policy,
        active_authorization=args.active_authorization,
        active_validators=args.validator,
        active_profile=args.active_profile,
        active_plan_digest=args.require_plan_digest,
    )


def _parse_framework_versions(values: list[str]) -> dict[str, str]:
    """Parse FRAMEWORK=VERSION CLI values."""

    versions: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"Invalid framework version override: {value}")
        framework_id, version = value.split("=", 1)
        versions[framework_id] = version
    return versions


def _partition_framework_args(
    legacy_values: list[str] | None,
    pack_values: list[str] | None,
) -> tuple[list[str] | None, list[str] | None]:
    """Separate legacy compliance IDs from versioned pack selections."""

    legacy: list[str] = []
    packs = list(pack_values or [])
    if not legacy_values:
        return None, packs or None
    pack_ids = set(FrameworkPackRegistry().list_framework_ids())
    for value in legacy_values or []:
        framework_id = value.partition(":")[0]
        if ":" in value or framework_id in pack_ids:
            packs.append(value)
            if framework_id == "EITS" and ":" not in value:
                legacy.append(value)
        else:
            legacy.append(value)
    return legacy or None, packs or None


def _print_compliance_catalog(list_profiles: bool, list_frameworks: bool) -> None:
    """Print compliance catalog details."""

    repository = FrameworkRepository()
    if list_profiles:
        for profile in repository.list_profiles():
            print(f"{profile.profile_id}\t{profile.version}\t{profile.name}")
    if list_frameworks:
        for framework in repository.list_frameworks():
            print(f"{framework.framework_id}\t{framework.version}\t{framework.name}")


if __name__ == "__main__":
    main()
