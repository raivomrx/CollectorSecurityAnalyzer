# Coverage Model

Coverage is capability-based and reported by:

```text
OS, PATCHING, SOFTWARE, ENDPOINT_PROTECTION, DISK_ENCRYPTION,
IDENTITY, NETWORK, SECURITY_POLICY, BROWSER, SERVICES,
CERTIFICATES, ACTIVE_VALIDATION
```

`COLLECTED` contributes 100%. `COLLECTED_PARTIAL` uses collected versus
expected evidence units, or 50% when cardinality is unavailable. Other terminal
states contribute zero and create a typed limitation.

Active Validation coverage remains zero in standard collection but is excluded
from the standard collection overall percentage because it is a separate
assessment depth.

Coverage and risk are intentionally separate:

```text
not verified != failed
access denied != vulnerable
privilege required != non-compliant
```

Rules must return `NOT_EVALUATED` when evidence is insufficient.
