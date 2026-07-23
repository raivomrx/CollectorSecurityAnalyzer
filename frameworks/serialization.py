"""JSON serialization for framework evaluation artifacts."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from frameworks.models import FrameworkEvaluation

if TYPE_CHECKING:
    from active_validation.models import ActiveValidationRun


def evaluation_to_dict(evaluation: FrameworkEvaluation) -> dict[str, Any]:
    """Return one evaluation as a stable JSON-compatible dictionary."""

    return _camelize(_normalize(asdict(evaluation)))


def write_analysis_json(
    evaluations: list[FrameworkEvaluation],
    output_path: str | Path,
    active_validation: "ActiveValidationRun | None" = None,
) -> Path:
    """Write framework evaluations as an analyzer sidecar artifact."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schemaVersion": "1.0",
        "frameworkEvaluations": [evaluation_to_dict(item) for item in evaluations],
    }
    if active_validation is not None:
        from active_validation.evidence import validate_evidence
        from active_validation.serialization import active_run_to_dict

        serialized_run = active_run_to_dict(active_validation)
        validate_evidence([serialized_run])
        document["activeValidation"] = serialized_run
    output.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    return output


def _normalize(value: Any) -> Any:
    """Normalize nested dataclass output and enums."""

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


def _camelize(value: Any) -> Any:
    """Convert Python model keys to the JSON contract's camelCase style."""

    if isinstance(value, dict):
        return {_camel_key(key): _camelize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_camelize(item) for item in value]
    return value


def _camel_key(value: str) -> str:
    """Convert one snake_case key to lower camelCase."""

    return re.sub(r"_([a-z])", lambda match: match.group(1).upper(), value)
