# Framework content packs

CSA framework packs are immutable, versioned JSON snapshots under `frameworks/`.
They provide traceability from existing CSA rules to external control identifiers;
they do not contain or reimplement technical checks.

## Pack lifecycle

- `DRAFT`: incomplete content or mappings awaiting review.
- `ACTIVE`: selectable as an operational pack. An active pack can still contain
  provisional mappings, which remain excluded from formal evaluation.
- `DEPRECATED`: retained for reproducibility but replaced by another version.
- `ARCHIVED`: historical and excluded from normal discovery.

`frameworks/registry.json` may define only one active default version for each
framework. Exact historical versions remain addressable as
`FRAMEWORK_ID:VERSION`. Every report records the selected version and the pack's
canonical SHA-256 digest.

## Commands

```text
python -m frameworks.cli list
python -m frameworks.cli show EITS:2026
python -m frameworks.cli validate --all
python -m frameworks.validate --require-reviewed
python -m frameworks.cli coverage EITS:2026
python -m frameworks.cli compare FRAMEWORK_ID OLD_VERSION NEW_VERSION
```

Analyzer selection accepts repeatable `--framework-pack FRAMEWORK_ID:VERSION`.
With no selection, all active defaults are evaluated. `--skip-framework-packs`
disables the layer. The analyzer writes both HTML and `.analysis.json` artifacts.

## Updating a pack

1. Add a new version directory; do not edit a released historical snapshot.
2. Preserve publisher release metadata exactly. Use `null` when unknown.
3. Add only identifiers confirmed from an authoritative or licensed source.
4. Keep new mappings `PROVISIONAL` until human review is recorded.
5. Recompute `contentHashSha256` from canonical JSON excluding that field.
6. Register the new version and explicitly change the active default.
7. Validate, compare with the previous pack, and run all tests.

Runtime evaluation performs no web scraping or remote framework lookup.
