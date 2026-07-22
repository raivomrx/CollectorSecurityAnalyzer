# Framework licensing and source handling

Framework publishers retain ownership of their source content. CSA stores only
the minimum material needed for versioned technical traceability: identifiers,
short CSA-authored titles, profiles, automation metadata, mappings, provenance,
and digests.

## CIS

The bundled CIS Windows 11 Enterprise 5.0.1 pack is intentionally an empty draft
seed. No licensed benchmark source is present in this repository, so CSA does not
redistribute benchmark prose or invent control identifiers. Use the bounded
CSV/JSON importer with a properly licensed mapping source:

```text
python -m frameworks.import_cis_mapping \
  --input licensed-mapping.csv \
  --framework CIS_WINDOWS_11_ENTERPRISE \
  --version 5.0.1 \
  --output frameworks/cis/windows-11-enterprise/5.0.1/pack.json
```

The importer records the input SHA-256 digest, accepts only whitelisted fields,
validates rule IDs and profile names, rejects duplicate controls and duplicate
JSON keys, and creates provisional mappings only. Provenance stores the source
format, record count, import time, digest, and optionally the basename. It never
stores a drive letter, absolute path, parent directory, UNC path, or user profile.
Use `--strict-privacy` to set `sourceFileName` to `null` while preserving the
digest.

## Microsoft guidance and E-ITS

Microsoft and RIA source URLs are provenance references, not embedded source
copies. An unknown upstream release is represented as `null`, never guessed.
The Microsoft pack is named `CSA_WINDOWS_11_MICROSOFT_GUIDANCE`. It contains
CSA-authored mappings to selected Microsoft guidance and is not an official or
complete Microsoft Security Baseline export. No source release is invented.

E-ITS entries use measure identifiers and 2026 source references. Until an exact
source review confirms each reference, the mappings remain provisional and
record an explicit limitation. The publisher is stored as UTF-8
`Riigi Infosüsteemi Amet`.

## NIS2

`NIS2_TECHNICAL_TRACEABILITY` is limited to high-level Article 21 technical
evidence traceability. Its assessment mode is `TRACEABILITY_ONLY`; CSA does not
provide legal advice or determine directive compliance.
