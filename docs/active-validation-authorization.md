# Active Validation Authorization

Authorization is a signed-off operational input, not a CLI flag. CSA requires
schema version `1.0`, `authorized: true`, an unexpired timezone-aware validity
window, assessment ID, device scope, validator scope, operator, and purpose.

JSON parsing rejects duplicate keys, unknown fields, duplicate scope values, and
oversized input. The exact canonical document receives a SHA-256 digest, which is
included in results and metadata-only audit events. The document itself is not
copied into report artifacts.

The target hostname must exactly match `scope.deviceIdentifiers`, and every planned
validator must be present in `scope.validatorIds`. CSA never auto-elevates and does
not infer authorization from administrator privileges.

Use a short expiry and the smallest practical validator scope. The example file is
illustrative and must be replaced for each assessment.
