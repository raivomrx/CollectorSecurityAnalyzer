"""Coverage-derived CVE assessment state, independent of provider health."""
from __future__ import annotations
from typing import Any

WORKFLOW_STATES = {"RUNNING", "FAILED", "CANCELLED", "SKIPPED", "NOT_PERFORMED"}
REASONS = {
    "INVALID_EVALUATION_COUNTS": "Eligible and evaluated product counts are unavailable or inconsistent.",
    "SOFTWARE_COLLECTION_INCOMPLETE": "Software inventory collection did not complete successfully.",
    "NO_ELIGIBLE_PRODUCTS": "No eligible software products were assessed; vulnerability assessment was not established.",
    "SCAN_NOT_COMPLETED": "CVE scanning has not been confirmed successfully completed.",
    "ELIGIBLE_EVALUATIONS_UNRESOLVED": "Eligible-product or CVE evaluations remain unresolved.",
    "EVALUATION_COMPLETED": "All eligible software products were successfully evaluated.",
    "NO_PRODUCTS_EVALUATED": "No eligible software product was successfully evaluated.",
}


def assessment_status(summary: dict[str, Any], collection_status: str | None = None,
                      workflow_status: str | None = None) -> str:
    return _decision(summary, collection_status, workflow_status)[0]


def _decision(summary, collection_status=None, workflow_status=None):
    declared = workflow_status or str(summary.get("status", "NOT_EVALUATED"))
    if declared in WORKFLOW_STATES:
        return declared, declared
    collection = collection_status or summary.get("softwareCollectionStatus", "NOT_EVALUATED")
    eligible = summary.get("cveEligibleProducts")
    evaluated = summary.get("successfullyEvaluatedProducts")
    if type(eligible) is not int or type(evaluated) is not int or not 0 <= evaluated <= eligible:
        return "NOT_EVALUATED", "INVALID_EVALUATION_COUNTS"
    if collection not in {"SUCCESS", "PARTIAL"}:
        return "NOT_EVALUATED", "SOFTWARE_COLLECTION_INCOMPLETE"
    if eligible == 0:
        return "NOT_EVALUATED", "NO_ELIGIBLE_PRODUCTS"
    if summary.get("scanCompleted") is not True:
        return ("PARTIAL" if evaluated else "NOT_EVALUATED"), "SCAN_NOT_COMPLETED"
    unresolved = (evaluated != eligible or summary.get("coverageComplete") is False
                  or any(summary.get(key, 0) for key in
                         ("notEvaluatedProducts", "unresolvedCveEvaluations", "apiErrorCount"))
                  or any(not isinstance(row, dict) or (row.get("eligibilityStatus") == "ELIGIBLE" and row.get("terminalStatus") != "COMPLETED")
                         for row in summary.get("productEvaluations", [])))
    if collection == "SUCCESS" and not unresolved:
        return "COMPLETE", "EVALUATION_COMPLETED"
    partial = any(isinstance(row, dict) and row.get("terminalStatus") == "PARTIAL"
                  for row in summary.get("productEvaluations", []))
    return ("PARTIAL" if evaluated or partial else "NOT_EVALUATED"), (
        "SOFTWARE_COLLECTION_INCOMPLETE" if collection != "SUCCESS" else
        "ELIGIBLE_EVALUATIONS_UNRESOLVED" if evaluated or partial else "NO_PRODUCTS_EVALUATED")


def normalize_metadata(summary: dict[str, Any], collection_status: str | None = None,
                       workflow_status: str | None = None) -> dict[str, Any]:
    result = dict(summary)
    result["status"], reason = _decision(result, collection_status, workflow_status)
    result["assessmentStatus"] = result["status"]
    result["statusContractVersion"] = "1.1"
    result["assessmentReasonCode"] = reason
    result["assessmentReason"] = REASONS.get(reason, "CVE assessment workflow status: " + result["status"] + ".")
    result["coverageComplete"] = result["status"] == "COMPLETE"
    if collection_status:
        result["softwareCollectionStatus"] = collection_status
    eligible, evaluated = result.get("cveEligibleProducts"), result.get("successfullyEvaluatedProducts")
    result["assessmentScope"] = "EMPTY" if eligible == 0 else "ELIGIBLE_PRODUCTS" if type(eligible) is int and eligible > 0 else "UNKNOWN"
    result["coveragePercent"] = 0.0
    if type(eligible) is int and type(evaluated) is int and 0 <= evaluated <= eligible:
        result["notEvaluatedProducts"] = max(eligible - evaluated, result.get("notEvaluatedProducts", 0))
        percent = round(evaluated * 100.0 / eligible, 1) if eligible else 0.0
        # Keep the counts, but do not publish a full assessment percentage when
        # scan completion or other scope evidence cannot establish completeness.
        result["coveragePercent"] = None if percent == 100.0 and not result["coverageComplete"] else percent
    result["providerCoverage"] = [dict(row, evaluationCoverageStatus=result["status"])
        if row.get("provider") == "NVD" else dict(row) for row in result.get("providerCoverage", [])]
    if "providerStatus" not in result:
        rows = [row for row in result.get("providerCoverage", []) if row.get("provider") == "NVD"]
        result["providerStatus"] = rows[0].get("status", "NOT_EVALUATED") if rows else "NOT_EVALUATED"
    return result


def scan_metadata(summary, collection_status: str) -> dict[str, Any]:
    """Use the same boundary checks in analyzer metadata and CVE-001."""
    return normalize_metadata({
        "scanCompleted": summary.scan_complete,
        "softwareCollectionStatus": collection_status,
        "cveEligibleProducts": summary.eligible_products,
        "successfullyEvaluatedProducts": summary.evaluated_products,
        "notEvaluatedProducts": max(0, summary.eligible_products - summary.evaluated_products),
        "unresolvedCveEvaluations": summary.not_evaluated,
        "apiErrorCount": summary.api_errors,
        "coverageComplete": summary.coverage_complete,
        "productEvaluations": [{"eligibilityStatus": row.eligibility_status,
                                "terminalStatus": row.terminal_status} for row in summary.product_evaluations],
    })


def aggregate_statuses(states) -> str:
    states = set(states)
    if not states:
        return "NOT_EVALUATED"
    if "RUNNING" in states:
        return "RUNNING"
    return next(iter(states)) if len(states) == 1 else "PARTIAL"
