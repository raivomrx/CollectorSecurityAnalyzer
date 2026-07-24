# Fleet Analysis

Fleet aggregation groups affected endpoint findings by stable rule ID.
Endpoint references are unique and sorted. One repeated rule becomes one
`FleetFinding` with affected count, assessed count, prevalence, systemic flag,
framework mappings, recommendation, confidence, and risk score.

A finding is systemic when at least two endpoints and at least 50% of the
assessed fleet are affected.

Risk uses severity weight and prevalence:

```text
finding risk = severity weight * (0.5 + affected percent / 200)
fleet risk = highest finding risk + 8% of remaining distinct finding risks
fleet risk is capped at 100
```

The same finding on 13 endpoints is therefore not scored as 13 independent
risks. Fleet evidence digest is calculated from sorted endpoint submission and
evidence-set digests.
