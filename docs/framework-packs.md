# Framework content packs

CSA framework packs are immutable, versioned JSON snapshots under `frameworks/`.
They provide traceability from existing CSA rules to external control identifiers;
they do not contain or reimplement technical checks.

## Pack lifecycle

- `DRAFT`: incomplete content, unavailable source material, placeholders, or no
  assessable content. A draft may be empty.
- `REVIEW_REQUIRED`: structurally usable content with one or more mappings still
  awaiting auditable human source review.
- `ACTIVE`: a released pack containing at least one validated mapping and no
  provisional mappings. Every mapping has complete human review provenance.
- `DEPRECATED`: retained for reproducibility but replaced by another version.
- `ARCHIVED`: historical and excluded from normal discovery.

`frameworks/registry.json` may define only one active default version for each
framework. `latest` resolves only an `ACTIVE` default and fails clearly when no
such version exists. It never falls back to `REVIEW_REQUIRED` or `DRAFT`.
Exact historical versions remain addressable as
`FRAMEWORK_ID:VERSION`. Every report records the selected version and the pack's
canonical SHA-256 digest.

## Commands

```text
python -m frameworks.cli list
python -m frameworks.cli show EITS:2026
python -m frameworks.cli validate --all
python -m frameworks.validate --active-only --require-reviewed
python -m frameworks.cli validate --all --strict-sources
python -m frameworks.cli coverage EITS:2026
python -m frameworks.cli compare FRAMEWORK_ID OLD_VERSION NEW_VERSION
python -m frameworks.cli review-candidates --status PROVISIONAL --format csv
```

Analyzer selection accepts repeatable `--framework-pack FRAMEWORK_ID:VERSION`.
With no selection, all active defaults are evaluated. The current registry has
no active packs; the release validator reports `No active framework packs` and
exits successfully. An exact `REVIEW_REQUIRED` pack may be evaluated only with
`--allow-unreviewed-frameworks`, which produces traceability-only output.
`--skip-framework-packs` disables the layer. The analyzer writes both HTML and
`.analysis.json` artifacts.

## Updating a pack

1. Add a new version directory; do not edit a released historical snapshot.
2. Preserve publisher release metadata exactly. Use `null` when unknown.
3. Add only identifiers confirmed from an authoritative or licensed source.
4. Keep new mappings `PROVISIONAL` until human review is recorded.
5. Recompute `contentHashSha256` from canonical JSON excluding that field.
6. Export candidates and apply recorded human decisions; never auto-validate.
7. Run strict validation and explicitly approve the pack's release status.
8. Register the new version and explicitly change the active default.
9. Compare with the previous pack and run all tests.

Runtime evaluation performs no web scraping or remote framework lookup.
