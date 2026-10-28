"""Coverage-derived CVE assessment state, independent of provider health."""
from __future__ import annotations
from typing import Any

WORKFLOW_STATES = {"RUNNING", "FAILED", "CANCELLED", "SKIPPED", "NOT_PERFORMED"}


def assessment_status(summary: dict[str, Any], collection_status: str | None = None,
                      workflow_status: str | None = None) -> str:
    declared = workflow_status or str(summary.get("status", "NOT_EVALUATED"))
    if declared in WORKFLOW_STATES:
        return declared
    collection = collection_status or summary.get("softwareCollectionStatus", "NOT_EVALUATED")
    eligible = summary.get("cveEligibleProducts")
    evaluated = summary.get("successfullyEvaluatedProducts")
    if type(eligible) is not int or type(evaluated) is not int or not 0 <= evaluated <= eligible:
        return "NOT_EVALUATED"
    if collection not in {"SUCCESS", "PARTIAL"}:
        return "NOT_EVALUATED"
    if summary.get("scanCompleted") is False and evaluated == 0:
        return "NOT_EVALUATED"
    if collection == "SUCCESS" and evaluated == eligible:
        return "COMPLETE"
    partial = any(isinstance(row, dict) and row.get("terminalStatus") == "PARTIAL"
                  for row in summary.get("productEvaluations", []))
    return "PARTIAL" if evaluated or partial else "NOT_EVALUATED"


def normalize_metadata(summary: dict[str, Any], collection_status: str | None = None,
                       workflow_status: str | None = None) -> dict[str, Any]:
    result = dict(summary)
    result["status"] = assessment_status(result, collection_status, workflow_status)
    result["assessmentStatus"] = result["status"]
    result["statusContractVersion"] = "1.0"
    if collection_status:
        result["softwareCollectionStatus"] = collection_status
    eligible, evaluated = result.get("cveEligibleProducts"), result.get("successfullyEvaluatedProducts")
    if type(eligible) is int and type(evaluated) is int and 0 <= evaluated <= eligible:
        result["notEvaluatedProducts"] = eligible - evaluated
        result["coveragePercent"] = round(evaluated * 100.0 / eligible, 1) if eligible else (100.0 if result["status"] == "COMPLETE" else 0.0)
    result["providerCoverage"] = [dict(row, evaluationCoverageStatus=result["status"])
        if row.get("provider") == "NVD" else dict(row) for row in result.get("providerCoverage", [])]
    if "providerStatus" not in result:
        rows = [row for row in result.get("providerCoverage", []) if row.get("provider") == "NVD"]
        result["providerStatus"] = rows[0].get("status", "NOT_EVALUATED") if rows else "NOT_EVALUATED"
    return result


def aggregate_statuses(states) -> str:
    states = set(states)
    if not states:
        return "NOT_EVALUATED"
    if "RUNNING" in states:
        return "RUNNING"
    return next(iter(states)) if len(states) == 1 else "PARTIAL"
