"""Evidence extractor for raw collector fields."""

from __future__ import annotations

from typing import Any

from analysis_context import AnalysisContext
from compliance.enums import EvidenceOperator, EvidenceResult
from compliance.evidence.base import EvidenceExtractor, evidence_record
from compliance.models import EvidenceRequirement
from risk import AuditFinding


class FieldEvidenceExtractor(EvidenceExtractor):
    """Extract evidence from raw collector data via safe dot paths."""

    name = "field"

    def extract(
        self,
        requirement: EvidenceRequirement,
        context: AnalysisContext,
        findings: list[AuditFinding],
    ):
        """Evaluate a raw-field requirement."""

        try:
            actual = resolve_path(context.raw_data, requirement.source_reference)
        except ValueError:
            return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, None, 0, "Unsafe field path rejected")
        if actual is _MISSING:
            result = EvidenceResult.SUPPORTS if requirement.operator == EvidenceOperator.NOT_EXISTS.value else EvidenceResult.MISSING
            return evidence_record(requirement, result, None, 0, "Raw collector field missing")

        result = _evaluate(requirement.operator, actual, requirement.expected_result)
        return evidence_record(requirement, result, actual, 85, f"Raw collector field {requirement.source_reference}")


class _Missing:
    pass


_MISSING = _Missing()


def resolve_path(data: Any, path: str) -> Any:
    """Resolve a safe dot path across dicts and lists."""

    if any(token in path for token in ("..", "[", "]", "__", "(", ")")):
        raise ValueError("Unsafe field path")
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part, _MISSING)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if 0 <= index < len(current) else _MISSING
        else:
            return _MISSING
        if current is _MISSING:
            return _MISSING
    return current


def _evaluate(operator: str, actual: Any, expected: Any) -> EvidenceResult:
    """Evaluate a field operator."""

    op = EvidenceOperator(operator)
    if op == EvidenceOperator.EXISTS:
        return EvidenceResult.SUPPORTS
    if op == EvidenceOperator.NOT_EXISTS:
        return EvidenceResult.CONTRADICTS
    if op == EvidenceOperator.EQUALS:
        return EvidenceResult.SUPPORTS if actual == expected else EvidenceResult.CONTRADICTS
    if op == EvidenceOperator.NOT_EQUALS:
        return EvidenceResult.SUPPORTS if actual != expected else EvidenceResult.CONTRADICTS
    if op == EvidenceOperator.IN:
        return EvidenceResult.SUPPORTS if actual in (expected or []) else EvidenceResult.CONTRADICTS
    if op == EvidenceOperator.NOT_IN:
        return EvidenceResult.SUPPORTS if actual not in (expected or []) else EvidenceResult.CONTRADICTS
    if op == EvidenceOperator.CONTAINS:
        return EvidenceResult.SUPPORTS if expected in actual else EvidenceResult.CONTRADICTS
    if op == EvidenceOperator.NOT_CONTAINS:
        return EvidenceResult.SUPPORTS if expected not in actual else EvidenceResult.CONTRADICTS
    if op in {
        EvidenceOperator.GREATER_THAN,
        EvidenceOperator.GREATER_OR_EQUAL,
        EvidenceOperator.LESS_THAN,
        EvidenceOperator.LESS_OR_EQUAL,
    }:
        return _compare_numeric(op, actual, expected)
    return EvidenceResult.INCONCLUSIVE


def _compare_numeric(op: EvidenceOperator, actual: Any, expected: Any) -> EvidenceResult:
    """Compare numeric field values."""

    try:
        left = float(actual)
        right = float(expected)
    except (TypeError, ValueError):
        return EvidenceResult.INCONCLUSIVE
    if op == EvidenceOperator.GREATER_THAN:
        ok = left > right
    elif op == EvidenceOperator.GREATER_OR_EQUAL:
        ok = left >= right
    elif op == EvidenceOperator.LESS_THAN:
        ok = left < right
    else:
        ok = left <= right
    return EvidenceResult.SUPPORTS if ok else EvidenceResult.CONTRADICTS
