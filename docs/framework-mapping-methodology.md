# Framework mapping methodology

CSA rules are the primary technical assessment units. A framework mapping points
to a rule result and never copies the rule's collection or decision logic.

## Strength

- `DIRECT`: the rule directly measures a technical setting represented by the
  control. All applicable direct mappings must pass before a technical control
  can be `SATISFIED`.
- `SUPPORTING`: the rule supplies relevant but incomplete evidence. Supporting
  evidence alone never produces `SATISFIED`.
- `CONTEXTUAL`: the result is related context. It does not affect control status,
  confidence, or assessment coverage.

## Review state

- `VALIDATED`: a human reviewer, review date, source reference, rationale, and
  known limitations are present.
- `PROVISIONAL`: mapping is visible for traceability but excluded from formal
  evaluation. `CSA_ARCHITECT_REVIEW_PENDING` always means provisional.
- `DEPRECATED`: retained only for history and excluded from evaluation.

Release validation uses:

```text
python -m frameworks.validate --require-reviewed
```

It fails for provisional mappings, missing review provenance, unknown rules,
and rules that are disabled, deprecated, or superseded.

## Conservative status rules

Technical controls can be fully satisfied only by complete validated direct
evidence. Missing, errored, not-collected, or unsupported rule evidence becomes
`NOT_ASSESSABLE`, never pass. Procedural, organizational, and mixed controls
cannot be fully satisfied from endpoint evidence. `NOT_APPLICABLE` requires an
explicit applicability decision.

Pack generation and import never grants `VALIDATED` automatically.
