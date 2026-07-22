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
JSON keys, and creates provisional mappings only.

## Microsoft and E-ITS

Microsoft and RIA source URLs are provenance references, not embedded source
copies. An unknown upstream release is represented as `null`, never guessed.
E-ITS entries use confirmed measure identifiers rather than CSA-created module
aliases.

## NIS2

NIS2 content is limited to high-level Article 21 traceability. CSA does not
provide legal advice or determine directive compliance.
