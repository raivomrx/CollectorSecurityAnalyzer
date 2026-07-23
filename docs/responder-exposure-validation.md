# Responder Exposure Validation

The Responder Exposure domain correlates independent observations for legacy name
resolution, integrated-authentication policy, SMB signing, WPAD policy, outbound
path availability, and missing evidence. It reports prerequisites, observed attack
paths, mitigating controls, confidence, and limitations.

Runtime LLMNR, NBT-NS, mDNS, outbound SMB, HTTP policy, and fallback-order
validators remain `REVIEW_REQUIRED` until a stable no-response Windows CI contract
exists. WPAD, local authentication policy, and signing checks are read-only.
Local policy alone is not labeled as domain-effective denial.

Risk is conservative. High requires an observed legacy query, permitted
authentication, an available outbound path, and no confirmed signing mitigation.
Configuration-only evidence can produce `EXPOSURE_LIKELY`, never a confirmed
runtime observation. Unknown effective policy or missing path evidence produces
`INCONCLUSIVE`.

The implementation sends no LLMNR or NBT-NS response, starts no rogue WPAD server,
issues no SMB or HTTP authentication challenge, generates or captures no
credential material, and retains no packet capture.
