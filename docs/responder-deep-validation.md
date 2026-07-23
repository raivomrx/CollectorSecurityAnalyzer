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

The self-hosted harness uses a scoped HTTP NTLM challenge. The endpoint closes
after the first matching event. Evidence contains protocol,
message-type labels, hashed identity/source linkage, and boolean safety fields.
Raw challenge-response bytes never enter worker JSON, stdout, stderr, audit, HTML,
or the analysis sidecar.

The harness listens only on the authorization-scoped IPv4 interface. LLMNR uses
UDP 5355 and NBT-NS uses UDP 137. A separate one-shot HTTP listener uses the
reviewed high port. Source IP, query marker, response count, connection count,
payload size, plan digest, authorization digest, and run ID are all checked.

The HTTP exchange parses real `NEGOTIATE` and `AUTHENTICATE` messages and creates
one ephemeral `CHALLENGE`. Type 3 response fields are not copied or serialized.
Only the normalized test identity hash is derived before the in-memory bytearray
is overwritten.

## Cleanup and failures

Temporary listeners and firewall rules use `CSA-VALIDATION-<runId>`, are
pre-registered for recovery, and are removed on every terminal path. A cleanup
failure becomes `ROLLBACK_FAILED` while the separate exposure evidence remains
visible, with manual cleanup required.

Firewall rules are limited to the packaged Python program, one local port, one
local IP, one remote IP, and one selected Windows profile. Both normal `finally`
cleanup and the fresh rollback worker remove the exact tracked names and verify
that they no longer exist.

## Self-hosted execution

Use an assessment runner labelled `self-hosted`, `Windows`, and
`csa-responder-lab`. The runner and target must be different authorized Windows
VMs, WinRM must be configured between them, and the runner service identity must
match the authorization test identity.

Preview and run with the same transport scope:

```powershell
python -m active_validation.cli plan `
  --profile deep-responder-validation `
  --policy deep-policy.json `
  --authorization deep-authorization.json `
  --device HOSTNAME-01 `
  --validator VAL-RESPONDER-DEEP-001 `
  --validator VAL-RESPONDER-EXPOSURE-001 `
  --live-responder-transport `
  --network-interface Ethernet `
  --listener-address 192.0.2.10 `
  --target-address 192.0.2.25 `
  --name-resolution-protocol LLMNR `
  --listener-port 8080 `
  --remote-computer HOSTNAME-01 `
  --firewall-profile Private
```

Pass the returned digest to `run` with `--require-plan-digest`. The transport
scope is part of that digest.

## Testing and limitations

GitHub hosted runners validate production protocol parsers, contracts,
authorization flow, isolation, cleanup, and aggregate classification using a
controlled transport test double. Test-double output cannot produce a live
network confirmation. The repository includes a manually dispatched two-Windows-
VM workflow for the real harness because hosted runner networking cannot provide
a stable authorized name-resolution test.

No observed exposure applies only to the tested interface, protocol, policy,
identity, observation window, and network conditions. Policy precedence or an
unreliable listener produces `INCONCLUSIVE`, while direct runtime authentication
evidence may confirm the path despite incomplete passive policy precedence.
