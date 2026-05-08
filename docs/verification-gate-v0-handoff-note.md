# Verification Gate v0 Handoff Note

Assay Verification Gate v0 is a signed verification judgment for one evidence
pack. The committed sample lets you verify the judgment locally without relying
on a dashboard or on the original GitHub Actions artifact still being retained.
The purpose of this check is to confirm what the artifact proves and what it
does not prove.

## Verify The Sample

If you are new to the packet, start here:

```text
docs/examples/verification-gate-v0/START-HERE.md
```

From the repository root:

```bash
bash scripts/verify_verification_gate_sample.sh
```

Expected result:

```text
Result: VERIFIED OK
```

## Files Involved

```text
docs/examples/verification-gate-v0/
  proof-pack/
    pack_manifest.json
    pack_signature.sig
    receipt_pack.jsonl
    verify_report.json
    verify_transcript.md
  signed-report/
    verify.stdout.json
    verify_report.json
    verify_report.sigstore.json
```

- `proof-pack/pack_manifest.json` is the evidence object manifest.
- `signed-report/verify_report.json` is the public verification judgment.
- `signed-report/verify_report.sigstore.json` is the provenance bundle for
  the judgment signature.

## What This Proves

- The signed public report and proof-pack manifest bind to the same
  `pack_root_sha256`.
- The proof-pack directory contains every file named by its manifest.
- The public report signature verifies against the expected GitHub Actions
  workflow identity for PR `#116`.
- The required integrity channel passed.

## What This Does Not Prove

- It does not prove production authorization.
- It does not prove legal compliance.
- It does not prove ledger acceptance or scorecard interpretation.
- It does not prove full claim, replay, or trust-policy evaluation.
- It does not prove upstream data authenticity beyond the included evidence.

## Questions To Answer Back

1. What is the Evidence Box?
2. What is the Inspection Note / Verification Report?
3. What is the Signature Proof?
4. Which channel passed?
5. Which channels were not evaluated?
6. What should not be inferred from this sample?
