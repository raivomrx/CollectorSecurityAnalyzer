# Active Validation Safety

The default policy is disabled and permits only `SAFE_READ_ONLY` definitions.
`RESTRICTED` and `PROHIBITED` validators cannot run in Sprint 4.1. Temporary
changes, listeners, outbound tests, and loopback tests each have separate policy
gates.

The engine does not collect passwords, hashes, authentication responses, tokens,
tickets, process memory, credential stores, or raw packet captures. It does not
read LSASS, SAM, SECURITY, or directory databases. It does not run exploits,
credential dumping, relay, spoofing, rogue servers, or authentication challenges.

Evidence is bounded and recursively scanned before it crosses the worker boundary.
Credential-like strings, private-key material, authorization headers, token
assignments, digest-like values, and local user-profile paths are blocked. The
scanner reports only the blocked category.

Network-impact validators are `REVIEW_REQUIRED` until their Windows CI behavior is
stable. The Responder aggregate consumes typed observations only and performs no
network activity.
