# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Assay, please report it
responsibly. Do **not** open a public GitHub issue.

**Email:** tim2208@gmail.com
**Subject line:** `[SECURITY] <brief description>`

You will receive an acknowledgment within 48 hours and a substantive
response within 5 business days.

## Scope

Assay is a cryptographic evidence tool. Security issues in the following
areas are especially important:

- Ed25519 signing or verification logic
- SHA-256 hashing or manifest integrity checks
- JCS (RFC 8785) canonicalization
- Key storage, rotation, or access control
- Receipt emission that leaks sensitive content unexpectedly
- MCP Notary Proxy message handling
- Any path where tampered evidence could pass verification

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.17.x  | Yes       |
| < 1.17  | No        |

We recommend always using the latest release from PyPI.

## Disclosure Timeline

- **Day 0:** Report received, acknowledgment sent
- **Day 5:** Initial assessment shared with reporter
- **Day 30:** Target for fix release (may vary by severity)
- **Day 90:** Public disclosure (coordinated with reporter)

## Dependencies

Assay delegates cryptographic operations to PyNaCl (libsodium). Signing
key material is stored in `~/.assay/keys/` with 0o600 permissions. No
secrets are transmitted to external services unless the user explicitly
configures external timestamping or transparency log anchoring.
