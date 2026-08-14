"""CVE inventory scanning service."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from cve.applicability import evaluate_applicability
from cve.client import NvdClient
from cve.cpe_resolver import CpeResolver, replace_cpe23_version
from cve.exceptions import NvdRequestError
from cve.models import (
    ApplicabilityStatus,
    CpeMatchStatus,
    CveAssessment,
    CveRecord,
    CveProductEvaluation,
    CveScanError,
    CveScanSummary,
)
from cve.parser import parse_cve_items
from software.models import SoftwareInventory, SoftwareProduct

LOGGER = logging.getLogger(__name__)
CveProgressCallback = Callable[[dict[str, Any]], None]
MINIMUM_SOFTWARE_CONFIDENCE = 80


class CveService:
    """Scan software inventory for known vulnerabilities."""

    def __init__(
        self,
        client: NvdClient | None = None,
        resolver: CpeResolver | None = None,
        minimum_cpe_confidence: int = 80,
    ) -> None:
        """Create a CVE scanning service."""

        self.client = NvdClient() if client is None else client
        self.resolver = resolver or CpeResolver(
            client=self.client,
            minimum_confidence=minimum_cpe_confidence,
        )
        self.minimum_cpe_confidence = minimum_cpe_confidence

    def scan_inventory(
        self,
        inventory: SoftwareInventory,
        raw_data: dict[str, Any] | None = None,
        progress_callback: CveProgressCallback | None = None,
    ) -> CveScanSummary:
        """Scan a software inventory for CVEs."""

        unique_products = _deduplicate(inventory.products)
        eligible_total = sum(1 for item in unique_products if _is_eligible(item))
        LOGGER.info("CVE scan started: %s unique software products", len(unique_products))
        assessments: list[CveAssessment] = []
        errors: list[CveScanError] = []
        products_with_cpe = 0
        products_without_cpe = 0
        ambiguous = 0
        eligible_products = 0
        evaluated_products = 0
        product_evaluations: list[CveProductEvaluation] = []

        _notify(
            progress_callback,
            phase="SCANNING_PRODUCTS",
            products_processed=0,
            products_total=eligible_total,
        )

        for software in unique_products:
            product_key = _product_key(software)
            eligible = _is_eligible(software)
            evaluation = CveProductEvaluation(
                product_key=product_key,
                display_name=software.product,
                version=software.version,
                normalization_status=_normalization_stage_status(software),
                normalization_confidence=software.confidence,
                eligibility_status="ELIGIBLE" if eligible else "NOT_ELIGIBLE",
                provider_reason=(
                    None if eligible else _ineligible_reason(software)
                ),
            )
            product_evaluations.append(evaluation)
            if not eligible:
                products_without_cpe += 1
                continue

            eligible_products += 1
            _notify(
                progress_callback,
                phase="MAPPING_PRODUCT",
                products_processed=eligible_products - 1,
                products_total=eligible_total,
                current_product=software.product,
                current_version=software.version,
            )
            try:
                resolution_method = getattr(
                    self.resolver, "resolve_with_trace", None
                )
                if callable(resolution_method):
                    resolution = resolution_method(software)
                    cpe = resolution.candidate
                    evaluation.cpe_candidate_count = resolution.candidate_count
                    evaluation.product_mapping_status = resolution.status
                    evaluation.provider_reason = resolution.reason
                else:
                    cpe = self.resolver.resolve(software)
                    evaluation.cpe_candidate_count = 1 if cpe else 0
                    evaluation.product_mapping_status = (
                        "SUCCESS" if cpe else "NO_RELIABLE_MAPPING"
                    )
                if cpe is None:
                    products_without_cpe += 1
                    continue
                if cpe.match_status == CpeMatchStatus.AMBIGUOUS:
                    ambiguous += 1
                    products_without_cpe += 1
                    evaluation.product_mapping_status = "AMBIGUOUS"
                    continue
                if cpe.confidence < self.minimum_cpe_confidence:
                    products_without_cpe += 1
                    evaluation.product_mapping_status = "NO_RELIABLE_MAPPING"
                    evaluation.provider_reason = (
                        f"CPE confidence {cpe.confidence} is below "
                        f"{self.minimum_cpe_confidence}"
                    )
                    continue

                products_with_cpe += 1
                software.cpe = cpe.cpe_name
                evaluation.cpe = cpe.cpe_name
                evaluation.product_mapping_status = "SUCCESS"
                _notify(
                    progress_callback,
                    phase="QUERYING_PROVIDER",
                    products_processed=eligible_products - 1,
                    products_total=eligible_total,
                    current_product=software.product,
                    current_version=software.version,
                )
                cve_items = self.client.get_cves(
                    _cve_query(cpe.cpe_name, software.normalized_version)
                )
                evaluation.provider_query_status = "SUCCESS"
                evaluation.provider_reason = None
                evaluated_products += 1
                records = parse_cve_items(cve_items)
                evaluation.records_received = len(records)
                _notify(
                    progress_callback,
                    phase="EVALUATING_VERSIONS",
                    products_processed=eligible_products - 1,
                    products_total=eligible_total,
                    current_product=software.product,
                    current_version=software.version,
                )
                product_assessments = []
                for record in records:
                    assessment = _assess(software, cpe, record, raw_data)
                    assessments.append(assessment)
                    product_assessments.append(assessment)
                _complete_evaluation(evaluation, product_assessments)
            except Exception as error:
                LOGGER.exception("CVE scan failed for a product")
                endpoint = getattr(error, "endpoint_label", None)
                if endpoint == "CPES" or evaluation.product_mapping_status == "NOT_RUN":
                    evaluation.product_mapping_status = "FAILED"
                else:
                    evaluation.provider_query_status = "FAILED"
                evaluation.provider_reason = _safe_error_reason(error)
                errors.append(
                    CveScanError(
                        product_key=product_key,
                        stage="SCAN_PRODUCT",
                        message=_safe_error_reason(error),
                        retryable=bool(getattr(error, "retryable", False)),
                    )
                )
            finally:
                _notify(
                    progress_callback,
                    phase="SCANNING_PRODUCTS",
                    products_processed=eligible_products,
                    products_total=eligible_total,
                    current_product=software.product,
                    current_version=software.version,
                    product_status=evaluation.cve_result_status,
                )

        summary = _summary(
            scanned_products=inventory.product_count,
            unique_products=len(unique_products),
            eligible_products=eligible_products,
            evaluated_products=evaluated_products,
            products_with_cpe=products_with_cpe,
            products_without_cpe=products_without_cpe,
            ambiguous_cpe_matches=ambiguous,
            assessments=assessments,
            errors=errors,
            product_evaluations=product_evaluations,
        )
        LOGGER.info(
            "CVE scan completed: confirmed=%s, possible=%s, not_evaluated=%s",
            summary.confirmed_vulnerabilities,
            summary.possible_vulnerabilities,
            summary.not_evaluated,
        )
        return summary


def empty_summary(
    scan_complete: bool = False,
    message: str | None = None,
) -> CveScanSummary:
    """Return an empty CVE summary for skipped or failed scans."""

    errors = []
    if message:
        errors.append(
            CveScanError(
                product_key=None,
                stage="CVE_SCAN",
                message=message,
                retryable=True,
            )
        )
    return CveScanSummary(
        scanned_products=0,
        unique_products=0,
        eligible_products=0,
        evaluated_products=0,
        coverage_percent=0.0,
        coverage_complete=False,
        products_with_cpe=0,
        products_without_cpe=0,
        ambiguous_cpe_matches=0,
        confirmed_vulnerabilities=0,
        possible_vulnerabilities=0,
        not_evaluated=0,
        api_errors=len(errors),
        assessments=[],
        errors=errors,
        scan_complete=scan_complete,
        product_evaluations=[],
    )


def _assess(
    software: SoftwareProduct,
    cpe,
    record: CveRecord,
    raw_data: dict[str, Any] | None,
) -> CveAssessment:
    """Create an applicability assessment."""

    status, reason, confidence, matched = evaluate_applicability(
        software,
        cpe,
        record,
        raw_data,
    )
    LOGGER.info("CVE applicability: %s = %s", record.cve_id, status.value)
    return CveAssessment(
        software=software,
        cpe=cpe,
        cve=record,
        applicability=status,
        reason=reason,
        confidence=confidence,
        matched_criteria=matched,
    )


def _summary(
    scanned_products: int,
    unique_products: int,
    eligible_products: int,
    evaluated_products: int,
    products_with_cpe: int,
    products_without_cpe: int,
    ambiguous_cpe_matches: int,
    assessments: list[CveAssessment],
    errors: list[CveScanError],
    product_evaluations: list[CveProductEvaluation],
) -> CveScanSummary:
    """Build a scan summary from assessments."""

    confirmed = sum(
        1
        for item in assessments
        if item.applicability == ApplicabilityStatus.AFFECTED
    )
    possible = sum(
        1
        for item in assessments
        if item.applicability == ApplicabilityStatus.POSSIBLY_AFFECTED
    )
    not_evaluated = sum(
        1
        for item in assessments
        if item.applicability == ApplicabilityStatus.NOT_EVALUATED
    )
    coverage_percent = 100.0
    if eligible_products:
        coverage_percent = round((evaluated_products / eligible_products) * 100, 1)
    return CveScanSummary(
        scanned_products=scanned_products,
        unique_products=unique_products,
        eligible_products=eligible_products,
        evaluated_products=evaluated_products,
        coverage_percent=coverage_percent,
        coverage_complete=evaluated_products == eligible_products,
        products_with_cpe=products_with_cpe,
        products_without_cpe=products_without_cpe,
        ambiguous_cpe_matches=ambiguous_cpe_matches,
        confirmed_vulnerabilities=confirmed,
        possible_vulnerabilities=possible,
        not_evaluated=not_evaluated,
        api_errors=len(errors),
        assessments=assessments,
        errors=errors,
        scan_complete=len(errors) == 0,
        product_evaluations=product_evaluations,
    )


def _cve_query(cpe_name: str, installed_version: str = "") -> dict[str, str]:
    """Build the narrowest valid NVD query for an installed product."""

    versioned_cpe = replace_cpe23_version(cpe_name, installed_version)
    if versioned_cpe is not None:
        return {"cpeName": versioned_cpe}
    if "*" in cpe_name:
        return {"virtualMatchString": cpe_name}
    return {"cpeName": cpe_name}


def _complete_evaluation(
    evaluation: CveProductEvaluation,
    assessments: list[CveAssessment],
) -> None:
    """Finalize version and result stages from parsed CVE assessments."""

    evaluation.version_evaluation_status = (
        "PARTIAL"
        if any(
            item.applicability == ApplicabilityStatus.NOT_EVALUATED
            for item in assessments
        )
        else "SUCCESS"
    )
    evaluation.confirmed_cves = len(
        {
            item.cve.cve_id
            for item in assessments
            if item.applicability == ApplicabilityStatus.AFFECTED
        }
    )
    evaluation.possible_cves = len(
        {
            item.cve.cve_id
            for item in assessments
            if item.applicability == ApplicabilityStatus.POSSIBLY_AFFECTED
        }
    )
    evaluation.not_affected_cves = len(
        {
            item.cve.cve_id
            for item in assessments
            if item.applicability == ApplicabilityStatus.NOT_AFFECTED
        }
    )
    if evaluation.confirmed_cves:
        evaluation.cve_result_status = "CONFIRMED"
    elif evaluation.possible_cves:
        evaluation.cve_result_status = "POSSIBLE"
    elif evaluation.version_evaluation_status == "PARTIAL":
        evaluation.cve_result_status = "NOT_EVALUATED"
    else:
        evaluation.cve_result_status = "NO_KNOWN_VULNERABILITIES"


def _ineligible_reason(software: SoftwareProduct) -> str:
    """Explain why a normalized inventory row cannot enter CVE matching."""

    if software.confidence < MINIMUM_SOFTWARE_CONFIDENCE:
        return "Normalization confidence is below the CVE eligibility threshold"
    if not software.version:
        return "Installed version is missing"
    return "Normalized product identity is missing"


def _normalization_stage_status(software: SoftwareProduct) -> str:
    """Translate normalization confidence to a pipeline stage result."""

    if software.confidence >= 95:
        return "SUCCESS"
    if software.confidence >= 60:
        return "PARTIAL"
    return "FAILED"


def _safe_error_reason(error: Exception) -> str:
    """Return structured provider diagnostics without response bodies."""

    if isinstance(error, NvdRequestError):
        endpoint = error.endpoint_label or "UNKNOWN"
        status = f" HTTP {error.status_code}" if error.status_code else ""
        return f"NVD {endpoint}{status}"
    return f"{type(error).__name__}: CVE evaluation stage failed"


def _notify(
    callback: CveProgressCallback | None,
    **details: Any,
) -> None:
    """Emit best-effort progress without allowing UI failures to stop scans."""

    if callback is None:
        return
    try:
        callback(details)
    except Exception:
        LOGGER.exception("CVE progress callback failed")


def _deduplicate(products: list[SoftwareProduct]) -> list[SoftwareProduct]:
    """Deduplicate software inventory by normalized identity."""

    seen: set[tuple[str, str, str, str | None]] = set()
    unique: list[SoftwareProduct] = []
    for product in products:
        key = (
            product.normalized_vendor,
            product.normalized_product,
            product.normalized_version,
            product.architecture,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(product)
    return unique


def _is_eligible(software: SoftwareProduct) -> bool:
    """Return whether a product has enough data for CVE evaluation."""

    return bool(
        software.normalized_product
        and software.version
        and software.confidence >= MINIMUM_SOFTWARE_CONFIDENCE
    )


def _product_key(software: SoftwareProduct) -> str:
    """Return a stable product key for logging and errors."""

    return "|".join(
        [
            software.normalized_vendor,
            software.normalized_product,
            software.normalized_version,
            software.architecture or "",
        ]
    )
