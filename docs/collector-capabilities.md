# Collector Capabilities

The formal registry is
`collector/windows/collection-capabilities.json`. The
`windows-standard-v1` profile selects 18 capabilities across OS, software,
services, encryption, endpoint protection, identity, network, patching,
browser posture, certificate metadata, and security policy.

Each definition contains:

```text
capabilityId, name, description, supportedOperatingSystems,
minimumPrivilege, collectionMethod, evidenceTypes, sensitivity,
timeoutSeconds, failureSemantics, frameworkMappings, coverageDomain, module
```

Every execution terminates as one of:

```text
COLLECTED
COLLECTED_PARTIAL
NOT_SUPPORTED
NOT_COLLECTED_PRIVILEGE_REQUIRED
NOT_COLLECTED_POLICY_BLOCKED
NOT_COLLECTED_TIMEOUT
NOT_COLLECTED_ACCESS_DENIED
NOT_COLLECTED_ERROR
```

An access or privilege limitation is collection evidence, not proof that a
security control failed.

Elevated-only capability definitions may remain in the standard profile so the
gap is explicit and measurable. They are not executed through elevation.

Browser collection is limited to installed versions and policy presence. It
does not read history, cookies, credentials, form data, or extensions in the
default profile. Certificate collection stores validity and cryptographic
metadata with privacy-preserving subject and issuer identifiers; private key
material is never opened or exported.
