# Public Verification Ritual

Verify the Assay passport surface from a clean environment with no repo context.

## Quick check

```bash
python3 -m venv /tmp/assay-verify
source /tmp/assay-verify/bin/activate
pip install --upgrade pip
pip install assay-ai==1.17.0
assay passport demo --output-dir /tmp/assay-verify-demo
```

## What success looks like

The demo produces 6 artifacts in the output directory:

```
/tmp/assay-verify-demo/
  passport_v1.json                    # Signed passport (Ed25519 + content-addressed ID)
  passport_v1.html                    # Self-contained HTML render (~28KB)
  passport_v2.json                    # Signed v2 with added coverage claim
  challenge_<ts>_<hash>.json          # Signed challenge receipt
  supersession_<ts>_<hash>.json       # Signed supersession receipt (v1 → v2)
  trust_diff.html                     # Diff report showing v1 → v2 changes
```

The 10 steps should complete with no errors:

| Step | What happens |
|------|-------------|
| 1 | Mint unsigned passport draft |
| 2 | Sign with Ed25519 (passport_id = SHA-256 of JCS body) |
| 3 | Render self-contained HTML |
| 4 | X-Ray diagnostic (expect Grade D — no proof pack backing) |
| 5 | Challenge (signed receipt created, coverage gap reason) |
| 6 | Verify (governance status: challenged, event integrity: all_valid) |
| 7 | Mint v2 (adds admin override coverage claim) |
| 8 | Sign v2 (different passport_id from v1) |
| 9 | Supersede v1 with v2 (signed supersession receipt) |
| 10 | Trust Diff (no regression — v2 adds coverage v1 lacked) |

## What to check

- `passport_v1.json` has `"signature"` and `"passport_id"` fields
- `passport_v1.json` and `passport_v2.json` have different `passport_id` values
- Challenge receipt has `"signature"` and `"event_id"` fields
- Supersession receipt links v1 → v2 via `target_passport_id` and `new_passport_id`

## v1.17.0 promotion receipt

| Field | Value |
|-------|-------|
| Release tag | `v1.17.0` |
| Commit | `7a5dc8a` |
| Workflow run | `23103540700` |
| PyPI | `assay-ai==1.17.0` |
| Publish method | OIDC trusted publisher + build provenance attestation |
| External proof | PyPI install → `assay passport demo` → 10/10 steps |
