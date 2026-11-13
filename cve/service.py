"""CVE inventory scanning service."""

from __future__ import annotations

import logging
import re
import time
from threading import Event
from collections.abc import Callable
from collections import Counter
from typing import Any

from cve.applicability import evaluate_applicability_result
from cve.client import NvdClient
from cve.cpe_resolver import CpeResolver, parse_cpe23_components, replace_cpe23_version
from cve.environment import OS_KEYS, read_environment
from cve.exceptions import CveScanCancelled, NvdRequestError
from cve.models import (
    ApplicabilityStatus,
    CpeMatchStatus,
    CveAssessment,
    CveRecord,
    CveTerminalReason,
    CveProductEvaluation,
    CveScanError,
    CveScanSummary,
)
from cve.parser import parse_cve_items
from software.models import SoftwareInventory, SoftwareProduct
from software.version import compare_applicability_versions, version_evidence

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
        cancel_event: Event | None = None,
        checkpoint=None,
    ) -> CveScanSummary:
        """Scan a software inventory for CVEs."""

        scan_started = time.perf_counter()
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
        applicability_seconds = 0.0
        current: dict[str, Any] = {"current_product": "", "current_version": "", "products_processed": 0}
        previous=checkpoint.load() if checkpoint is not None else None
        saved={row.product_key:row for row in previous.product_evaluations} if previous else {}
        if previous: assessments.extend(previous.assessments)
        def snapshot(cancelled=False):
            unique={(_product_key(row.software),row.cve.cve_id,row.applicability.value):row for row in assessments}
            result=_summary(scanned_products=inventory.product_count,unique_products=len(unique_products),
                eligible_products=eligible_total,evaluated_products=evaluated_products,
                products_with_cpe=products_with_cpe,products_without_cpe=products_without_cpe,
                ambiguous_cpe_matches=ambiguous,assessments=list(unique.values()),errors=errors,
                product_evaluations=product_evaluations)
            result.scan_complete=False;result.coverage_complete=False
            result.telemetry.update(cancelled=cancelled,checkpointRecovered=bool(previous))
            return result
        def save(cancelled=False):
            result=snapshot(cancelled)
            if checkpoint is not None: checkpoint.save(result)
            return result
        if isinstance(self.client, NvdClient):
            self.client.cancel_event = cancel_event
            self.client.progress_callback = lambda details: _notify(
                progress_callback, **current, products_total=eligible_total, **details
            )

        _notify(
            progress_callback,
            phase="SCANNING_PRODUCTS",
            products_processed=0,
            products_total=eligible_total,
        )

        for software in unique_products:
            if cancel_event is not None and cancel_event.is_set():
                error=CveScanCancelled("CVE scan cancelled");error.partial_summary=save(True);raise error
            product_key = _product_key(software)
            eligible = _is_eligible(software)
            retained=saved.get(product_key)
            retained_at=(retained.discovery_trace.get("checkpointCompletedAt",previous.telemetry.get("checkpointSavedAt",0)) if retained else 0)
            if (retained and retained.terminal_status in {"COMPLETED","NOT_ELIGIBLE"}
                    and 0<=time.time()-retained_at<getattr(checkpoint,"ttl_seconds",86400)):
                product_evaluations.append(retained)
                if eligible:
                    eligible_products+=1; evaluated_products+=int(retained.terminal_status=="COMPLETED")
                    products_with_cpe+=int(bool(retained.cpe)); software.cpe=retained.cpe
                else: products_without_cpe+=1
                _notify(progress_callback,phase="RECOVERED_PRODUCT",products_processed=eligible_products,
                    products_total=eligible_total,current_product=software.product,current_version=software.version)
                continue
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
                discovery_trace={
                    "normalization": software.normalization_trace,
                },
            )
            product_evaluations.append(evaluation)
            if not eligible:
                evaluation.terminal_status = "NOT_ELIGIBLE"
                evaluation.failure_stage = "ELIGIBILITY"
                evaluation.failure_reason = evaluation.provider_reason
                evaluation.terminal_reason_code = _ineligible_reason_code(
                    software
                ).value
                products_without_cpe += 1
                continue

            eligible_products += 1
            current.update(current_product=software.product, current_version=software.version,
                           products_processed=eligible_products - 1)
            _notify(
                progress_callback,
                phase="MAPPING_PRODUCT",
                products_processed=eligible_products - 1,
                products_total=eligible_total,
                current_product=software.product,
                current_version=software.version,
            )
            try:
                old_assessments={id(row) for row in assessments if _product_key(row.software)==product_key}
                if isinstance(self.client,NvdClient):
                    self.client.product_deadline=time.monotonic()+self.client.product_deadline_seconds
                    self.client._check_cancelled()
                version = version_evidence(software.vendor, software.product, software.version)
                comparison = compare_applicability_versions(version.interpreted, version.interpreted, version.scheme)
                version_reason = version.reason or comparison.reason
                if version_reason:
                    evaluation.version_evaluation_status = "PARTIAL"
                    _mark_terminal_failure(evaluation, stage="VERSION_EVALUATION", reason="Installed version evidence does not establish a supported version",
                                           reason_code=CveTerminalReason(version_reason), terminal_status="PARTIAL")
                    products_without_cpe += 1
                    continue
                resolution_method = getattr(
                    self.resolver, "resolve_with_trace", None
                )
                if callable(resolution_method):
                    resolution = (
                        resolution_method(software, raw_data)
                        if isinstance(self.resolver, CpeResolver)
                        else resolution_method(software)
                    )
                    cpe = resolution.candidate
                    evaluation.cpe_candidate_count = resolution.candidate_count
                    evaluation.product_mapping_status = resolution.status
                    evaluation.provider_reason = resolution.reason
                    evaluation.discovery_trace = {
                        "normalization": software.normalization_trace,
                        **getattr(resolution, "trace", {}),
                    }
                else:
                    cpe = self.resolver.resolve(software)
                    evaluation.cpe_candidate_count = 1 if cpe else 0
                    evaluation.product_mapping_status = (
                        "SUCCESS" if cpe else "NO_RELIABLE_MAPPING"
                    )
                if cpe is None:
                    _mark_terminal_failure(
                        evaluation,
                        stage="PRODUCT_MAPPING",
                        reason=(
                            evaluation.provider_reason
                            or "No reliable CPE mapping was found"
                        ),
                        reason_code=(
                            CveTerminalReason.AMBIGUOUS_IDENTITY
                            if evaluation.product_mapping_status == "AMBIGUOUS"
                            else CveTerminalReason(evaluation.discovery_trace.get("reasonCode") or "MISSING_AUTHORITATIVE_PRODUCT_MAPPING")
                        ),
                    )
                    products_without_cpe += 1
                    continue
                if cpe.match_status == CpeMatchStatus.AMBIGUOUS:
                    ambiguous += 1
                    products_without_cpe += 1
                    evaluation.product_mapping_status = "AMBIGUOUS"
                    _mark_terminal_failure(
                        evaluation,
                        stage="PRODUCT_MAPPING",
                        reason=(
                            evaluation.provider_reason
                            or "CPE mapping is ambiguous"
                        ),
                        reason_code=CveTerminalReason.AMBIGUOUS_IDENTITY,
                    )
                    continue
                if cpe.confidence < self.minimum_cpe_confidence or cpe.deprecated or cpe.match_status == CpeMatchStatus.NOT_FOUND:
                    products_without_cpe += 1
                    evaluation.product_mapping_status = "NO_RELIABLE_MAPPING"
                    evaluation.provider_reason = (
                        f"CPE confidence {cpe.confidence} is below "
                        f"{self.minimum_cpe_confidence}"
                    )
                    _mark_terminal_failure(
                        evaluation,
                        stage="PRODUCT_MAPPING",
                        reason=evaluation.provider_reason,
                        reason_code=CveTerminalReason.NO_AUTHORITATIVE_MAPPING,
                    )
                    continue

                products_with_cpe += 1
                software.cpe = cpe.cpe_name
                evaluation.cpe = cpe.cpe_name
                evaluation.product_mapping_status = "SUCCESS"
                evaluation.mapping_source = cpe.source
                _notify(
                    progress_callback,
                    phase="QUERYING_PROVIDER",
                    products_processed=eligible_products - 1,
                    products_total=eligible_total,
                    current_product=software.product,
                    current_version=software.version,
                )
                parsed_cpe = parse_cpe23_components(cpe.cpe_name)
                catalogued_version = bool(parsed_cpe and parsed_cpe.update == "*"
                    and evaluation.discovery_trace.get("installedVersionCatalogued") is True
                    and evaluation.discovery_trace.get("catalogState") != "STALE"
                    and compare_applicability_versions(version.interpreted, parsed_cpe.version, version.scheme).order == 0)
                if catalogued_version:
                    query = {"cpeName": cpe.cpe_name}
                    evaluation.discovery_trace["providerQueryMode"] = "INSTALLED_VERSION"
                else:
                    query = {"virtualMatchString": replace_cpe23_version(cpe.cpe_name, "*") or cpe.cpe_name}
                    evaluation.discovery_trace["providerQueryMode"] = "FAMILY_RANGE"
                cve_items = self.client.get_cves(query)
                evaluation.provider_query_status = "SUCCESS"
                evaluation.provider_reason = None
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
                applicability_started = time.perf_counter()
                for record in records:
                    assessment = _assess(software, cpe, record, raw_data)
                    assessments.append(assessment)
                    product_assessments.append(assessment)
                _complete_evaluation(evaluation, product_assessments, catalogued_version=catalogued_version,
                                     malformed_rows=len(records) != len(cve_items))
                applicability_seconds += time.perf_counter() - applicability_started
                if evaluation.terminal_status == "COMPLETED":
                    evaluated_products += 1
                    evaluation.discovery_trace["checkpointCompletedAt"]=time.time()
                    assessments[:]=[row for row in assessments if id(row) not in old_assessments]
            except CveScanCancelled as error:
                _mark_terminal_failure(evaluation,stage="PROVIDER_QUERY",reason="Analysis cancelled; retry incomplete product",
                    reason_code=CveTerminalReason.ANALYSIS_CANCELLED,terminal_status="PARTIAL",retryable=True)
                error.partial_summary=save(True)
                raise
            except Exception as error:
                evaluation.discovery_trace = getattr(error, "discovery_trace", evaluation.discovery_trace)
                LOGGER.exception("CVE scan failed for a product")
                endpoint = getattr(error, "endpoint_label", None)
                if endpoint == "CPES" or evaluation.product_mapping_status == "NOT_RUN":
                    evaluation.product_mapping_status = "FAILED"
                    failure_stage = "PRODUCT_MAPPING"
                else:
                    evaluation.provider_query_status = "FAILED"
                    failure_stage = "PROVIDER_QUERY"
                error_reason = _safe_error_reason(error)
                evaluation.provider_reason = error_reason
                _mark_terminal_failure(
                    evaluation,
                    stage=failure_stage,
                    reason=error_reason,
                    retryable=bool(getattr(error, "retryable", False)),
                    terminal_status="PARTIAL" if getattr(error,"reason_code",None)=="PRODUCT_DEADLINE_EXCEEDED" else "FAILED",
                    reason_code=_provider_reason_code(
                        error,
                        evaluation.discovery_trace,
                    ),
                )
                errors.append(
                    CveScanError(
                        product_key=product_key,
                        stage="SCAN_PRODUCT",
                        message=_safe_error_reason(error),
                        retryable=bool(getattr(error, "retryable", False)),
                    )
                )
            finally:
                save(bool(cancel_event is not None and cancel_event.is_set()))
                if isinstance(self.client,NvdClient): self.client.product_deadline=None
                _notify(
                    progress_callback,
                    phase="SCANNING_PRODUCTS",
                    products_processed=eligible_products,
                    products_total=eligible_total,
                    current_product=software.product,
                    current_version=software.version,
                    product_status=evaluation.cve_result_status,
                )

        unique={(_product_key(row.software),row.cve.cve_id,row.applicability.value):row for row in assessments}
        summary = _summary(
            scanned_products=inventory.product_count,
            unique_products=len(unique_products),
            eligible_products=eligible_products,
            evaluated_products=evaluated_products,
            products_with_cpe=products_with_cpe,
            products_without_cpe=products_without_cpe,
            ambiguous_cpe_matches=ambiguous,
            assessments=list(unique.values()),
            errors=errors,
            product_evaluations=product_evaluations,
        )
        LOGGER.info(
            "CVE scan completed: confirmed=%s, possible=%s, not_evaluated=%s",
            summary.confirmed_vulnerabilities,
            summary.possible_vulnerabilities,
            summary.not_evaluated,
        )
        summary.telemetry = {
            **getattr(self.client, "metrics", {}), **getattr(self.resolver, "metrics", {}),
            "cveScanSeconds": time.perf_counter() - scan_started,
            "applicabilityEvaluationSeconds": applicability_seconds,
            "providerErrors": summary.api_errors,
        }
        if checkpoint is not None: checkpoint.save(summary)
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

    result = evaluate_applicability_result(
        software,
        cpe,
        record,
        raw_data,
    )
    LOGGER.info("CVE applicability: %s = %s", record.cve_id, result.status.value)
    return CveAssessment(
        software=software,
        cpe=cpe,
        cve=record,
        applicability=result.status,
        reason=result.reason,
        confidence=result.confidence,
        matched_criteria=result.matched_criteria,
        reason_code=result.reason_code,
        operating_system=read_environment(raw_data, OS_KEYS),
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
    coverage_percent = 0.0
    if eligible_products:
        coverage_percent = round((evaluated_products / eligible_products) * 100, 1)
    return CveScanSummary(
        scanned_products=scanned_products,
        unique_products=unique_products,
        eligible_products=eligible_products,
        evaluated_products=evaluated_products,
        coverage_percent=coverage_percent,
        coverage_complete=eligible_products > 0 and evaluated_products == eligible_products and not errors and not not_evaluated,
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


def _complete_evaluation(
    evaluation: CveProductEvaluation,
    assessments: list[CveAssessment],
    *, catalogued_version: bool = False, malformed_rows: bool = False,
) -> None:
    """Finalize version and result stages from parsed CVE assessments."""

    evaluation.applicability_reason_counts = dict(Counter(item.reason_code for item in assessments if item.reason_code))
    incomplete = malformed_rows or (not assessments and not catalogued_version)
    evaluation.version_evaluation_status = (
        "PARTIAL"
        if incomplete or any(
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
    if evaluation.version_evaluation_status == "PARTIAL":
        unresolved = next(
            (
                item
                for item in assessments
                if item.applicability == ApplicabilityStatus.NOT_EVALUATED
            ),
            None,
        )
        evaluation.terminal_status = "PARTIAL"
        evaluation.terminal_reason_code = (unresolved.reason_code if unresolved else None) or (
            "NO_CVE_ROWS" if not assessments and not malformed_rows else "APPLICABILITY_INCOMPLETE")
        evaluation.failure_stage = "VERSION_EVALUATION"
        evaluation.failure_reason = unresolved.reason if unresolved else (
            "Provider returned no CVE rows for a family without confirmed installed-version catalogue evidence"
            if not malformed_rows else "Provider returned rows that could not be evaluated")
    else:
        evaluation.terminal_status = "COMPLETED"
        evaluation.terminal_reason_code = (
            CveTerminalReason.EVALUATION_COMPLETED.value
        )


def _mark_terminal_failure(
    evaluation: CveProductEvaluation,
    *,
    stage: str,
    reason: str,
    retryable: bool = False,
    terminal_status: str = "NOT_EVALUATED",
    reason_code: CveTerminalReason = (
        CveTerminalReason.NO_AUTHORITATIVE_MAPPING
    ),
) -> None:
    """Finalize an auditable product outcome that did not reach evaluation."""

    evaluation.cve_result_status = "NOT_EVALUATED"
    evaluation.terminal_status = terminal_status
    evaluation.terminal_reason_code = reason_code.value
    evaluation.failure_stage = stage
    evaluation.failure_reason = reason
    evaluation.retryable = retryable


def _ineligible_reason(software: SoftwareProduct) -> str:
    """Explain why a normalized inventory row cannot enter CVE matching."""

    if (
        software.confidence < MINIMUM_SOFTWARE_CONFIDENCE
        and not software.discovery_eligible
    ):
        return "Normalization confidence is below the CVE eligibility threshold"
    if not software.version:
        return "Installed version is missing"
    return "Normalized product identity is missing"


def _ineligible_reason_code(
    software: SoftwareProduct,
) -> CveTerminalReason:
    """Classify permanent identity gaps without guessing product mappings."""

    if not software.version:
        return CveTerminalReason.VERSION_UNAVAILABLE
    identity = f"{software.vendor} {software.product}".casefold()
    if re.search(r"\b(?:internal|custom|in-house|proprietary)\b", identity):
        return CveTerminalReason.CUSTOM_OR_INTERNAL_SOFTWARE
    if re.search(
        r"\b(?:helper|updater|add-in|runtime|redistributable|driver package)\b",
        identity,
    ):
        return CveTerminalReason.UNSUPPORTED_COMPONENT
    return CveTerminalReason.NO_AUTHORITATIVE_MAPPING


def _provider_reason_code(
    error: Exception,
    trace: dict[str, Any],
) -> CveTerminalReason:
    """Classify transient provider failures independently from identity gaps."""

    if getattr(error,"reason_code",None)=="PRODUCT_DEADLINE_EXCEEDED":
        return CveTerminalReason.PRODUCT_DEADLINE_EXCEEDED
    if isinstance(error, NvdRequestError) and error.status_code == 429:
        return CveTerminalReason.PROVIDER_RATE_LIMIT
    if trace.get("catalogState") == "STALE":
        return CveTerminalReason.PROVIDER_STALE
    return CveTerminalReason.PROVIDER_ERROR


def _normalization_stage_status(software: SoftwareProduct) -> str:
    """Translate normalization confidence to a pipeline stage result."""

    if software.confidence >= 95:
        return "SUCCESS"
    if software.confidence >= 60:
        return "PARTIAL"
    if software.discovery_eligible:
        return "DISCOVERY_CANDIDATE"
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
        and (
            software.confidence >= MINIMUM_SOFTWARE_CONFIDENCE
            or software.discovery_eligible
        )
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
