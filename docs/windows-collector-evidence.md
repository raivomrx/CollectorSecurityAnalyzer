# Windows collector evidence contract

`collector/windows/evidence-manifest.json` is the only source of truth for expected
Windows evidence. Collector modules emit observations; they do not define expected
counts.

## Evidence units

Each manifest entry declares an `id`, `matchType`, `cardinality`, `evidenceUnitId`,
and `canonical` flag. A canonical entry and its aliases share one
`evidenceUnitId`, so aliases never increase coverage. Dynamic entries expand by
their declared cardinality. Firewall profiles use the Domain, Private, and Public
context; BitLocker volumes are discovered from trusted runtime metadata.

Mandatory evidence controls module completeness. Missing mandatory evidence makes
the module `PARTIAL` or `NOT_AVAILABLE`. Missing optional evidence lowers evidence
coverage and produces a warning, but does not by itself prevent `SUCCESS`.

## Coverage metrics

- `moduleInvocationCoveragePercent`: modules invoked divided by manifested modules.
- `successfulModulePercent`: modules with final status `SUCCESS` divided by manifested modules.
- `evidenceUnitCoveragePercent`: successfully collected canonical units divided by applicable units.
- `mandatoryEvidenceCoveragePercent`: successfully collected mandatory units divided by applicable mandatory units.

The legacy coverage fields remain compatibility aliases for Schema 2.0 consumers.

## Audit Policy locales

Audit Policy value parsing supports `en-US` and `et-EE`. English and Estonian
fixtures are stored in `tests/fixtures`. An unrecognized localized value is treated
as unavailable evidence; it is never interpreted as a disabled audit setting.
