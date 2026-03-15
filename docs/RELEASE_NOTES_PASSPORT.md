# Passport + Governance: Release Notes

Assay now includes a portable passport and governance flow with signed artifacts, verified lifecycle receipts, and a reproducible seeded referee gallery.

## New Commands

| Command | Description |
|---------|-------------|
| `assay passport mint` | Build an unsigned passport draft from a proof pack |
| `assay passport sign` | Ed25519-sign a passport (content-addressed ID computed at signing) |
| `assay passport verify` | Check structural validity: signature, content hash, lifecycle state |
| `assay passport status` | Derive reliance posture under a policy mode (PASS / WARN / FAIL) |
| `assay passport show` | Rich terminal summary of a passport |
| `assay passport render` | Self-contained HTML output |
| `assay passport xray` | Structural diagnostic with grade (A-F) and improvement path |
| `assay passport challenge` | Issue a signed challenge receipt against a passport |
| `assay passport supersede` | Link an old passport to a new one with a signed supersession receipt |
| `assay passport revoke` | Permanently revoke a passport with a signed revocation receipt |
| `assay passport diff` | Compare two passport files and flag regressions |
| `assay passport demo` | Full 10-step lifecycle walkthrough |

## Architecture

- Signed passports are immutable after signing. Governance truth lives in signed lifecycle receipts, not passport mutation.
- `verify` (object integrity) and `status` (reliance posture) are explicitly separated by contract. They answer different questions.
- All governance events -- challenge, supersession, revocation -- are Ed25519-signed with content-addressed identity.
- Lifecycle receipts are co-located with the passport and ingested at verification time. No external service required.
- Unsigned demo receipts exist for backward compatibility and local experimentation. They are quarantined from production verification paths.

## Worked Example

`docs/passport/gallery/` contains a 7-artifact deterministic reference set:

| Artifact | Purpose |
|----------|---------|
| `passport_v1.json` | Signed passport (AcmeSaaS) |
| `passport_v1.html` | Self-contained HTML render with verification status |
| `xray_v1.html` | X-Ray diagnostic report: grade, findings, improvement path |
| `challenge_*.json` | Signed challenge receipt (coverage gap) |
| `passport_v2.json` | Signed passport v2 (adds admin override coverage claim) |
| `supersession_*.json` | Signed supersession receipt linking v1 to v2 |
| `trust_diff.html` | Diff report showing v1 to v2 changes |

The gallery demonstrates a full lifecycle:

```
mint v1 -> sign -> render -> xray -> challenge -> verify (CHALLENGED)
  -> mint v2 (address gap) -> sign -> supersede v1->v2 -> diff
```

Regenerate with: `python3 docs/passport/generate_gallery.py --output-dir docs/passport/gallery`

All artifacts are seeded, deterministic, and inspectable. The gallery is a worked example on controlled inputs, not a scan of external systems.

## What This Does Not Include

- Arbitrary URL or PDF scanning
- External document ingestion
- Enterprise diff workflows or fleet management
- Delegated authority beyond issuer fingerprint
- Real-time monitoring or continuous scanning
