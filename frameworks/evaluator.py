"""Conservative rule-to-framework evaluation."""

from __future__ import annotations

from datetime import datetime, timezone

from frameworks.coverage import calculate_coverage
from frameworks.enums import (
    AssessmentMode,
    EvaluationMode,
    FrameworkControlLevel,
    FrameworkControlStatus,
    MappingStatus,
    MappingStrength,
    PackStatus,
)
from frameworks.exceptions import FrameworkPackError
from frameworks.models import (
    AssessmentPolicy,
    FrameworkControl,
    FrameworkControlResult,
    FrameworkEvaluation,
    FrameworkPack,
)
from risk import AuditFinding, Status

PASS_STATUSES = {Status.PASS}
FAIL_STATUSES = {Status.FAIL, Status.WARNING}


class FrameworkEvaluator:
    """Evaluate packs from existing CSA technical findings."""

    def evaluate(
        self,
        pack: FrameworkPack,
        findings: list[AuditFinding],
        policy: AssessmentPolicy | None = None,
        allow_unreviewed: bool = False,
    ) -> FrameworkEvaluation:
        """Evaluate one pack while preserving mapping limitations."""

        mappings = [mapping for control in pack.controls for mapping in control.mappings]
        provisional_count = sum(
            mapping.status == MappingStatus.PROVISIONAL for mapping in mappings
        )
        validated_count = sum(
            mapping.status == MappingStatus.VALIDATED for mapping in mappings
        )
        if pack.status == PackStatus.ACTIVE and provisional_count:
            raise FrameworkPackError("ACTIVE framework pack contains provisional mappings")
        if pack.status == PackStatus.REVIEW_REQUIRED and not allow_unreviewed:
            raise FrameworkPackError(
                "Framework pack is not active and contains unreviewed mappings. "
                "Use --allow-unreviewed-frameworks for traceability-only evaluation."
            )
        if pack.status not in {PackStatus.ACTIVE, PackStatus.REVIEW_REQUIRED}:
            raise FrameworkPackError(
                f"Framework pack is not assessable in {pack.status.value} status"
            )
        formal_assessment = (
            pack.status == PackStatus.ACTIVE
            and pack.assessment_mode == AssessmentMode.FORMAL_ASSESSMENT
        )
        evaluation_mode = (
            EvaluationMode.FORMAL_ASSESSMENT
            if formal_assessment
            else EvaluationMode.TRACEABILITY_ONLY
        )
        policy = policy or AssessmentPolicy()
        finding_map = _findings_by_rule(findings)
        results = tuple(
            self.evaluate_control(pack, control, finding_map, policy)
            for control in pack.controls
        )
        warnings = tuple(
            f"{result.control_id}: provisional mappings require human review"
            for result in results
            if result.provisional_rule_ids
        )
        return FrameworkEvaluation(
            pack=pack,
            results=results,
            coverage=calculate_coverage(pack, results),
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            warnings=warnings,
            evaluation_mode=evaluation_mode,
            formal_assessment_performed=formal_assessment,
            validated_mapping_count=validated_count,
            provisional_mapping_count=provisional_count,
        )

    def evaluate_control(
        self,
        pack: FrameworkPack,
        control: FrameworkControl,
        findings: dict[str, Status],
        policy: AssessmentPolicy,
    ) -> FrameworkControlResult:
        """Evaluate one control using only validated, non-contextual mappings."""

        mapped_ids = tuple(mapping.rule_id for mapping in control.mappings)
        provisional = tuple(
            mapping.rule_id
            for mapping in control.mappings
            if mapping.status == MappingStatus.PROVISIONAL
        )
        limitations = [
            limitation
            for mapping in control.mappings
            for limitation in mapping.evidence_limitations
        ]
        if provisional:
            limitations.append("Provisional mappings are excluded from formal evaluation.")
        if control.control_id in policy.not_applicable_controls:
            return _result(
                pack, control, FrameworkControlStatus.NOT_APPLICABLE, mapped_ids,
                (), (), (), provisional, 100, limitations,
            )
        if not control.mappings:
            return _result(
                pack, control, FrameworkControlStatus.NOT_EVALUATED, (),
                (), (), (), (), 0, ["No CSA rule mapping is available."],
            )

        formal = [
            mapping for mapping in control.mappings
            if mapping.status == MappingStatus.VALIDATED
            and mapping.strength != MappingStrength.CONTEXTUAL
        ]
        direct = [mapping for mapping in formal if mapping.strength == MappingStrength.DIRECT]
        supporting = [
            mapping for mapping in formal if mapping.strength == MappingStrength.SUPPORTING
        ]
        passed = tuple(
            mapping.rule_id
            for mapping in formal
            if findings.get(mapping.rule_id) in PASS_STATUSES
        )
        failed = tuple(
            mapping.rule_id
            for mapping in formal
            if findings.get(mapping.rule_id) in FAIL_STATUSES
        )
        unavailable = tuple(
            mapping.rule_id
            for mapping in formal
            if findings.get(mapping.rule_id) not in PASS_STATUSES | FAIL_STATUSES
        )
        direct_passed = [mapping for mapping in direct if mapping.rule_id in passed]
        direct_failed = [mapping for mapping in direct if mapping.rule_id in failed]
        direct_unavailable = [mapping for mapping in direct if mapping.rule_id in unavailable]

        if not formal:
            status = FrameworkControlStatus.NOT_EVALUATED
            limitations.append("No validated non-contextual mapping is available.")
        elif direct_failed:
            status = FrameworkControlStatus.NOT_SATISFIED
        elif not direct:
            status = (
                FrameworkControlStatus.PARTIALLY_SATISFIED
                if supporting and passed
                else FrameworkControlStatus.NOT_ASSESSABLE
            )
            limitations.append("Supporting evidence alone cannot satisfy a control.")
        elif direct_unavailable:
            status = FrameworkControlStatus.NOT_ASSESSABLE
            limitations.append("Required direct rule evidence is unavailable.")
        elif len(direct_passed) == len(direct):
            if control.level == FrameworkControlLevel.TECHNICAL:
                status = FrameworkControlStatus.SATISFIED
            else:
                status = FrameworkControlStatus.PARTIALLY_SATISFIED
                limitations.append(
                    "Endpoint evidence cannot fully assess procedural, organizational, "
                    "or mixed scope."
                )
        else:
            status = FrameworkControlStatus.NOT_ASSESSABLE

        confidence = _confidence(status, provisional, unavailable)
        return _result(
            pack, control, status, mapped_ids, passed, failed, unavailable,
            provisional, confidence, limitations,
        )


def _findings_by_rule(findings: list[AuditFinding]) -> dict[str, Status]:
    """Choose the most conservative status when a rule produced multiple findings."""

    priority = {
        Status.ERROR: 6,
        Status.FAIL: 5,
        Status.WARNING: 4,
        Status.NOT_EVALUATED: 3,
        Status.INFO: 2,
        Status.NOT_APPLICABLE: 1,
        Status.PASS: 0,
    }
    result: dict[str, Status] = {}
    for item in findings:
        rule_id = item.finding.rule_id
        status = item.finding.status
        if rule_id not in result or priority[status] > priority[result[rule_id]]:
            result[rule_id] = status
    return result


def _confidence(status, provisional, unavailable) -> int:
    """Return a transparent evidence confidence value."""

    if status in {FrameworkControlStatus.NOT_EVALUATED, FrameworkControlStatus.NOT_ASSESSABLE}:
        return 0 if unavailable else 25
    if provisional:
        return 75
    return 100


def _result(
    pack,
    control,
    status,
    mapped,
    passed,
    failed,
    unavailable,
    provisional,
    confidence,
    limitations,
):
    """Build one immutable control result."""

    return FrameworkControlResult(
        framework_id=pack.framework_id,
        framework_version=pack.version,
        control_id=control.control_id,
        title=control.title,
        status=status,
        automation=control.automation,
        mapped_rule_ids=tuple(mapped),
        passed_rule_ids=tuple(passed),
        failed_rule_ids=tuple(failed),
        unavailable_rule_ids=tuple(unavailable),
        provisional_rule_ids=tuple(provisional),
        confidence=confidence,
        limitations=tuple(dict.fromkeys(limitations)),
        presentation_status=_presentation_status(status, mapped, provisional),
    )


def _presentation_status(status, mapped, provisional) -> str:
    """Return wording that does not overstate traceability as compliance."""

    if not mapped:
        return "NOT_MAPPED"
    if provisional:
        return "REVIEW_PENDING"
    labels = {
        FrameworkControlStatus.SATISFIED: "SUPPORTED_BY_TECHNICAL_EVIDENCE",
        FrameworkControlStatus.NOT_SATISFIED: "TECHNICAL_EVIDENCE_INDICATES_GAP",
        FrameworkControlStatus.PARTIALLY_SATISFIED: "PARTIALLY_SUPPORTED",
        FrameworkControlStatus.NOT_ASSESSABLE: "NOT_ASSESSABLE_BY_ENDPOINT",
        FrameworkControlStatus.NOT_APPLICABLE: "NOT_APPLICABLE",
        FrameworkControlStatus.NOT_EVALUATED: "NOT_EVALUATED",
    }
    return labels[status]
