# Assay for Compliance Teams

Prefer the styled public page: [for-compliance.html](for-compliance.html).

When someone asks "show me evidence of what your AI system did," Assay produces a portable, independently verifiable evidence bundle. No server access required.

## What Assay Produces

A **proof pack** is a self-contained evidence bundle for a single AI system run.
Five files. One Ed25519 signature. Independently verifiable.

| File | What it contains |
|------|-----------------|
| `receipt_pack.jsonl` | Structured evidence records |
| `pack_manifest.json` | SHA-256 hashes of every file in the pack |
| `pack_signature.sig` | Ed25519 signature over the manifest |
| `verify_report.json` | Machine-readable verification results |
| `verify_transcript.md` | Human-readable verification narrative |

## What Verification Checks

Running `assay verify-pack ./proof_pack_*/` answers two questions:

1. **Integrity** — were these files tampered with after creation?
2. **Claims** — does the evidence satisfy the declared governance checks?

## What Assay Proves

- Evidence files have not been modified since signing
- Declared call sites emitted receipts under a completeness contract
- Declared governance checks passed or failed against authentic evidence

## What Assay Does Not Prove

- That receipts perfectly represent runtime reality if the operator fabricates a run
- That every action was captured outside the instrumented or contracted surface
- That timestamps correspond to real-world time without an external anchor
