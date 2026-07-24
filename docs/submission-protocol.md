# Submission Protocol

## Online Flow

1. Collector sends its short-lived enrollment token and submission ID to
   `POST /api/v1/nonce`.
2. Console validates session state, expiration, source scope, token hash, and
   use limits.
3. Console returns a one-use, source-bound nonce.
4. Collector creates the evidence package and HMAC-binds session ID,
   submission ID, nonce, package digest, and payload file digests.
5. Collector uploads to `POST /api/v1/submissions/<submission-id>`.
6. Console consumes the nonce before validation, applies archive limits,
   validates all digests, schema, privacy, profile, and trusted build, then
   moves the package from quarantine to accepted storage.
7. Console returns an RSA-PSS-SHA256 signed receipt.

Nonce or package replay is rejected. Token plaintext exists in the Collector
package, as permitted for submission-only enrollment, but the server persists
only its SHA-256 verifier.

## TLS

The session certificate contains the selected IP or DNS SAN, has short
validity, and is fingerprint-pinned in the Collector package. There is no
silent certificate bypass, unknown-certificate trust, or HTTP fallback.

## Archive Safety

The Console rejects absolute paths, `..`, backslashes, duplicate paths,
symlinks, directories, unexpected files, excess file count, compressed and
uncompressed size excess, and unsafe compression ratios. It reads allowlisted
members in memory and does not recursively extract nested archives.
