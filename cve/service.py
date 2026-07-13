"""CVE inventory scanning service."""

from __future__ import annotations

import logging
from typing import Any

from cve.applicability import evaluate_applicability
from cve.client import NvdClient
from cve.cpe_resolver import CpeResolver
from cve.exceptions import CveEngineError
from cve.models import (
    ApplicabilityStatus,
    CpeMatchStatus,
    CveAssessment,
    CveRecord,
    CveScanError,
    CveScanSummary,
)
from cve.parser import parse_cve_items
from software.models import SoftwareInventory, SoftwareProduct

LOGGER = logging.getLogger(__name__)


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
    ) -> CveScanSummary:
        """Scan a software inventory for CVEs."""

        unique_products = _deduplicate(inventory.products)
        LOGGER.info("CVE scan started: %s unique software products", len(unique_products))
        assessments: list[CveAssessment] = []
        errors: list[CveScanError] = []
        products_with_cpe = 0
        products_without_cpe = 0
        ambiguous = 0
        eligible_products = 0
        evaluated_products = 0

        for software in unique_products:
            product_key = _product_key(software)
            try:
                if not _is_eligible(software):
                    products_without_cpe += 1
                    continue

                eligible_products += 1
                cpe = self.resolver.resolve(software)
                if cpe is None:
                    products_without_cpe += 1
                    continue
                if cpe.match_status == CpeMatchStatus.AMBIGUOUS:
                    ambiguous += 1
                    products_without_cpe += 1
                    continue
                if cpe.confidence < self.minimum_cpe_confidence:
                    products_without_cpe += 1
                    continue

                products_with_cpe += 1
                cve_items = self.client.get_cves({"cpeName": cpe.cpe_name})
                evaluated_products += 1
                records = parse_cve_items(cve_items)
                for record in records:
                    assessments.append(_assess(software, cpe, record, raw_data))
            except Exception as error:
                LOGGER.exception("CVE scan failed for a product")
                errors.append(
                    CveScanError(
                        product_key=product_key,
                        stage="SCAN_PRODUCT",
                        message=str(error),
                        retryable=isinstance(error, CveEngineError),
                    )
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
        )
        LOGGER.info(
            "CVE scan completed: confirmed=%s, possible=%s, not_evaluated=%s",
            summary.confirmed_vulnerabilities,
            summary.possible_vulnerabilities,
            summary.not_evaluated,
        )
        return summary


def empty_summary(scan_complete: bool = False, message: str | None = None) -> CveScanSummary:
    """Return an empty CVE summary for skipped or failed scans."""

    errors = []
    if message:
        errors.append(CveScanError(product_key=None, stage="CVE_SCAN", message=message, retryable=True))
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
) -> CveScanSummary:
    """Build a scan summary from assessments."""

    confirmed = sum(1 for item in assessments if item.applicability == ApplicabilityStatus.AFFECTED)
    possible = sum(1 for item in assessments if item.applicability == ApplicabilityStatus.POSSIBLY_AFFECTED)
    not_evaluated = sum(1 for item in assessments if item.applicability == ApplicabilityStatus.NOT_EVALUATED)
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
    )


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

    return bool(software.normalized_product and software.version and software.confidence >= 60)


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
