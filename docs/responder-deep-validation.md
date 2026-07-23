# Responder Deep Validation

## Purpose and boundary

Safe observation correlates configuration and bounded local observations. Deep
validation answers a narrower runtime question: can the authorized endpoint be
induced, under the tested interface and policy conditions, to start NTLM
authentication to the assessment service after one controlled name-resolution
response?

Confirming that path does not require retaining authentication material, relaying
it, reusing it, or cracking it. Those operations are prohibited.

## Required authorization

The policy must enable every deep responder gate while real credential
observation, retention, relay, cracking, and external targets remain false.
Authorization must name the device, every dependency validator, interface, source
and target IP addresses, protocols, operation permissions, validity window, and a
non-privileged test identity backed by a secure runtime reference.

CSA answers only `CSA-RSP-<RUN-HASH>-<SUFFIX>`, only on the authorized interface,
and only for the authorized endpoint. The response and connection limits are one,
payload size is bounded, wildcard binds are rejected, and the observation window
is short. A mismatched marker, interface, address, or protocol is ignored and only
a mismatch count may be retained.

## Authentication evidence

The preferred path is a scoped SMB challenge, with scoped HTTP as the fallback.
The endpoint closes after the first matching event. Evidence contains protocol,
message-type labels, hashed identity/source linkage, and boolean safety fields.
Raw challenge-response bytes never enter worker JSON, stdout, stderr, audit, HTML,
or the analysis sidecar.

## Cleanup and failures

Temporary listeners and firewall rules use `CSA-VALIDATION-<runId>`, are
pre-registered for recovery, and are removed on every terminal path. A cleanup
failure becomes `ROLLBACK_FAILED` while the separate exposure evidence remains
visible, with manual cleanup required.

## Testing and limitations

Hosted CI uses the production protocol parser and a minimized controlled transport
signal through the real subprocess pipeline. Scope, authorization, redaction,
rollback, and aggregate outcomes are required gates. A real two-host network test
belongs in an explicitly authorized self-hosted Windows workflow because hosted
runner networking cannot provide a stable poisoning test.

No observed exposure applies only to the tested interface, protocol, policy,
identity, observation window, and network conditions. Policy precedence or an
unreliable listener produces `INCONCLUSIVE`, while direct runtime authentication
evidence may confirm the path despite incomplete passive policy precedence.
