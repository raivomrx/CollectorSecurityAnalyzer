# Framework mapping human review

Technical compatibility is not human source validation. CSA never changes a
mapping to `VALIDATED` because tests pass, IDs exist, or evidence appears related.

## Lifecycle

```text
DRAFT
  -> REVIEW_REQUIRED
  -> Human source review
  -> VALIDATED mappings
  -> Strict validation
  -> Explicit ACTIVE release decision
```

Export candidates without modifying packs:

```text
python -m frameworks.cli review-candidates \
  --framework EITS \
  --status PROVISIONAL \
  --strength DIRECT \
  --format csv
```

The export includes framework/version, control/rule IDs, strength, status,
source reference, rationale, limitations, and pending reason. Table and JSON
formats are also supported.

## Applying decisions

The review CSV has exactly these fields:

```text
control_id,rule_id,decision,reviewer,reviewed_at,review_method,comment
```

Allowed decisions are `VALIDATE`, `KEEP_PROVISIONAL`, `REJECT`, and `DEPRECATE`.
The reviewer must be real, the date must be ISO-8601, and the method must be
`MANUAL_SOURCE_REVIEW` or `PEER_REVIEW`.

```text
python -m frameworks.cli apply-review \
  --input reviewed-mappings.csv \
  --framework EITS \
  --version 2026
```

The importer operates only on existing mappings. It validates every row before
writing, aborts the entire operation on any error, recomputes the canonical pack
digest, atomically replaces the pack, and writes `review-audit.json`. The audit
contains the review input digest and decisions, but never its absolute path.

`VALIDATE` additionally requires an existing source release, exact source
reference, and non-empty rationale. Applying review decisions does not promote a
pack to `ACTIVE`; release status and registry default remain explicit audited
changes.

## Release gate

```text
python -m frameworks.cli validate --all --strict-sources
python -m frameworks.validate --active-only --require-reviewed --strict-sources
```

The second command validates only active releases. With no active pack it exits
successfully and prints `No active framework packs`. Before promotion, reviewers
must also confirm that all mapped CSA rules exist, are enabled, and are neither
deprecated nor superseded.
