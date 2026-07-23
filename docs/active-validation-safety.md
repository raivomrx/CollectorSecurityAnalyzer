# Active Validation Safety

The default policy is disabled and permits only `SAFE_READ_ONLY` definitions.
`RESTRICTED` and `PROHIBITED` validators cannot run in Sprint 4.1. Temporary
changes, listeners, outbound tests, and loopback tests each have separate policy
gates.

The engine does not retain passwords, hashes, authentication responses, tokens,
tickets, process memory, credential stores, or raw packet captures. It does not
read LSASS, SAM, SECURITY, or directory databases. Relay, cracking, credential
reuse, persistence, and testing outside authorization scope remain prohibited.

`deep-responder-validation` is a separate fail-closed profile. It may issue one
exact-marker LLMNR or NBT-NS response and one scoped SMB or HTTP authentication
challenge only when every deep policy flag and authorization permission is
explicit. It derives boolean protocol facts in memory and discards credential
material without writing, reporting, relaying, or cracking it.

Evidence is bounded and recursively scanned before it crosses the worker boundary.
Credential-like strings, private-key material, authorization headers, token
assignments, digest-like values, and local user-profile paths are blocked. The
scanner reports only the blocked category.

The audit is a tamper-evident hash-chain rather than a digital signature. Its
verified terminal hash and entry count are bound into the analysis result.
