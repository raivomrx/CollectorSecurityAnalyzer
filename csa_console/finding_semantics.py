"""Evidence-backed client wording shared by endpoint and fleet reports."""

from __future__ import annotations

import re
from typing import Any


def client_finding_semantics(
    rule_id: str,
    title: str,
    recommendation: str,
    evidence: dict[str, Any] | list[dict[str, Any]] | None,
) -> dict[str, str]:
    """Return concrete reason, action and verification for a security finding."""

    rows = evidence if isinstance(evidence, list) else [evidence or {}]
    reason = next(
        (str(row.get("reason")) for row in rows if row.get("reason")),
        "The assessed control did not meet the configured policy.",
    )
    result = {
        "title": title,
        "reason": reason,
        "recommendation": recommendation,
        "verification": f"Rerun CSA and verify {rule_id} reports PASS.",
    }
    if rule_id == "ACC-009":
        accounts = _affected_accounts(rows)
        account_text = ", ".join(accounts) if accounts else "the affected local accounts"
        result.update(
            title="Enabled local accounts do not require a password",
            reason=(
                f"PasswordRequired=false was collected for: {account_text}."
            ),
            recommendation=(
                f"Require passwords for {account_text}, or disable/remove each "
                "account when it is not needed."
            ),
            verification=(
                "Collect the endpoint again and verify every listed enabled local "
                "account has PasswordRequired=true and ACC-009 reports PASS."
            ),
        )
        return result
    if rule_id != "ACC-006":
        return result

    observed = _unique_values(row.get("observed_value") for row in rows)
    required = _first_number(row.get("required_minimum") for row in rows)
    if not observed:
        fallback = _reason_number(rows, "Value")
        observed = [_number_text(fallback)] if fallback is not None else []
    if required is None:
        required = _reason_number(rows, "minimum")
    if required is None:
        return result
    observed_text = ", ".join(observed) if observed else "unknown"
    required_text = _number_text(required)
    result.update(
        title=(
            f"Local minimum password length {observed_text} is below required "
            f"{required_text}"
        ),
        reason=(
            f"The configured local minimum password length is {observed_text}; "
            f"the assessed policy requires at least {required_text} characters. "
            "This is LOCAL_POLICY evidence and is not presented as the "
            "domain-effective password policy. "
            "This evaluates policy configuration only; CSA did not inspect, "
            "capture, relay or crack passwords."
        ),
        recommendation=(
            f"Set the local minimum password length to at least {required_text} "
            "characters through the applicable local or centrally managed policy, "
            "then apply the policy to the affected endpoints."
        ),
        verification=(
            "Collect the endpoints again and verify PASSWORD_POLICY_MIN_LENGTH is "
            f"at least {required_text} and ACC-006 reports PASS."
        ),
    )
    return result


def _affected_accounts(rows: list[dict[str, Any]]) -> list[str]:
    """Return stable display names from ACC-009 correlated evidence."""

    result: set[str] = set()
    for row in rows:
        accounts = row.get("affected_accounts", [])
        if not isinstance(accounts, list):
            continue
        for account in accounts:
            if not isinstance(account, dict):
                continue
            name = str(account.get("name", "")).strip()
            if name:
                result.add(name)
    return sorted(result, key=str.casefold)


def _unique_values(values: Any) -> list[str]:
    """Return stable unique scalar values for client wording."""

    return sorted(
        {str(value) for value in values if value is not None},
        key=lambda value: (not value.replace(".", "", 1).isdigit(), value),
    )


def _first_number(values: Any) -> int | float | None:
    """Return the first numeric policy threshold."""

    for value in values:
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return value
        try:
            return float(str(value))
        except (TypeError, ValueError):
            continue
    return None


def _number_text(value: int | float) -> str:
    """Format policy numbers without an unnecessary decimal suffix."""

    return str(int(value)) if float(value).is_integer() else str(value)


def _reason_number(
    rows: list[dict[str, Any]],
    label: str,
) -> int | float | None:
    """Read legacy numeric policy evidence from a stable reason field."""

    pattern = re.compile(
        rf"\b{re.escape(label)}\s+(-?\d+(?:\.\d+)?)\b",
        re.IGNORECASE,
    )
    for row in rows:
        match = pattern.search(str(row.get("reason", "")))
        if match:
            value = float(match.group(1))
            return int(value) if value.is_integer() else value
    return None
