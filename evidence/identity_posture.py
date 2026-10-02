"""Scoped password policy and an explicit authoritative IdP provider boundary.

Endpoint join/Hello/PRT signals are context, never MFA enforcement evidence.
IdP observations are supplied by trusted application providers, not deserialized
from endpoint JSON. No such provider is enabled in this release.
"""

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class MfaPolicyObservation:
    """A provider's effective policy evaluation for the assessed identity scope."""

    state: str
    source: str
    collected_at: str
    scope: str
    policy_reference: str


class MfaPolicyProvider(Protocol):
    """Future authenticated IdP adapter; must resolve effective policy scope."""

    def evaluate(self) -> MfaPolicyObservation: ...


def mfa_posture(providers: tuple[MfaPolicyProvider, ...] = ()) -> dict[str, Any]:
    """Reduce authoritative policy observations; fail closed on missing evidence."""
    observations = []
    incomplete = False
    for provider in providers:
        try:
            row = provider.evaluate()
            valid = isinstance(row, MfaPolicyObservation) and all((
                row.source, row.collected_at, row.scope, row.policy_reference,
                row.state in {"ENFORCED", "PARTIAL", "NOT_ENFORCED", "SOURCE_CONFLICT"},
            ))
            if valid:
                observations.append(row)
            else:
                incomplete = True
        except Exception:
            incomplete = True
    states = {row.state for row in observations}
    scopes = {row.scope for row in observations}
    state = "NOT_EVALUATED"
    if "SOURCE_CONFLICT" in states or len(states) > 1:
        state = "SOURCE_CONFLICT"
    elif states and not incomplete:
        # Different/unreconciled scopes cannot establish full enforcement.
        state = next(iter(states)) if len(scopes) == 1 else "PARTIAL"
    return {
        "state": state,
        "reason": (
            "MFA enforcement was not evaluated. Endpoint evidence alone cannot establish identity-provider enforcement."
            if state == "NOT_EVALUATED" else
            "Authoritative identity-provider policy evaluation: " + state.replace("_", " ") + "."
        ),
        "sources": [{"source": row.source, "collectedAt": row.collected_at,
                     "scope": row.scope, "policyReference": row.policy_reference,
                     "state": row.state} for row in observations],
    }


def identity_posture(evidence: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize local policy without claiming domain policy or password strength."""
    settings = {
        row.get("settingId"): row
        for group in evidence.values() if isinstance(group, dict)
        for row in group.get("settings", []) if isinstance(row, dict)
    }

    def value(key: str) -> int | float | None:
        setting = settings.get(key, {})
        observed = setting.get("effectiveValue")
        return observed if (setting.get("collectionStatus") == "SUCCESS"
                            and type(observed) in {int, float} and observed >= 0) else None

    minimum = value("PASSWORD_POLICY_MIN_LENGTH")
    baseline = 15
    for row in findings:
        finding = row.get("finding", {})
        if finding.get("rule_id") == "ACC-006":
            candidate = finding.get("evidence", {}).get("required_minimum")
            if type(candidate) in {int, float} and candidate > 0:
                baseline = candidate
    device = evidence.get("identity", evidence.get("device", {}))
    domain, entra = device.get("domainJoined"), device.get("entraJoined")
    context = ("HYBRID_JOINED" if domain is True and entra is True else
               "AD_JOINED" if domain is True else "ENTRA_JOINED" if entra is True else
               "WORKGROUP" if domain is False else "NOT_EVALUATED")
    return {
        "passwordPolicy": {
            "state": "NOT_EVALUATED" if minimum is None else "PASS" if minimum >= baseline else "FAIL",
            "scope": "LOCAL_POLICY" if minimum is not None else "NOT_EVALUATED",
            "minimumLength": minimum, "baselineMinimumLength": baseline,
            "history": value("PASSWORD_POLICY_HISTORY"),
            "lockoutThreshold": value("ACCOUNT_LOCKOUT_THRESHOLD"),
            "lockoutDurationMinutes": value("ACCOUNT_LOCKOUT_DURATION_MINUTES"),
            "domainEffectivePolicy": "DOMAIN_POLICY_NOT_EVALUATED" if domain is True else "NOT_EVALUATED",
            "reason": "Local account policy only; actual password strength was not tested.",
        },
        "mfa": mfa_posture(),
        "context": context,
        "signals": {key: device[key] for key in ("domainJoined", "entraJoined", "windowsHelloProvisioned")
                    if type(device.get(key)) is bool},
    }
