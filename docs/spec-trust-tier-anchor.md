# Trust Tier Anchor Spec

**Status**: Implementation spec
**Feature**: `assay anchor` -- external witnessing via Sigstore/Rekor
**Prerequisite**: Gate policy hardening (spec-gate-policy.md)
**Blocked by**: Nothing (can start after gate work)

---

## Problem

Assay proof packs are self-signed (T0). The operator controls the key.
A determined adversary can fabricate a run, sign it, and present it as
genuine. The strongest technical objection to Assay is "self-signed
operator evidence."

External witnessing (T1/T2) makes fabrication detectable by recording
pack hashes in a public, append-only transparency log that the operator
does not control.

## Trust tier model

| Tier | What | How | Who controls |
|------|------|-----|-------------|
| T0 | Self-signed | Ed25519 keypair, local signing | Operator |
| T1 | Time-anchored | RFC 3161 TSA or Sigstore timestamp | Operator + TSA |
| T2 | Independent witness | Rekor transparency log entry | Operator + public log |
| T3 | Runtime attestation | TEE/TPM-backed signing | Hardware |

This spec implements T1 + T2 via Sigstore (which provides both
timestamping and transparency log in one integration).

---

## What ships

### Package

```bash
pip install assay-ai[witness]
```

Optional dependency: `sigstore>=3.0.0`.

**pyproject.toml addition:**
```toml
[project.optional-dependencies]
witness = ["sigstore>=3.0.0"]
```

### New CLI command: `assay anchor`

```bash
# Anchor a proof pack to Sigstore's Rekor transparency log
assay anchor ./proof_pack_*/

# Verify a pack was anchored
assay verify-pack ./proof_pack_*/ --require-anchor

# Show anchor status
assay anchor --status ./proof_pack_*/
```

### New files

```
src/assay/anchor.py              # Sigstore/Rekor integration
tests/assay/test_anchor.py       # Tests (with mock Rekor)
```

---

## Anchor flow

### 1. `assay anchor <pack_dir>`

```
Read pack_manifest.json
    |
    v
Extract pack_root_sha256 (the signed root hash)
    |
    v
Sign with Sigstore (keyless OIDC flow OR local key)
    |
    v
Submit to Rekor transparency log
    |
    v
Receive: log_index, entry_uuid, inclusion_proof, signed_entry_timestamp
    |
    v
Write anchor_receipt.json into pack directory
```

### 2. `anchor_receipt.json`

New file added to pack directory after anchoring:

```json
{
    "anchor_version": "1",
    "pack_id": "pack_abc123",
    "pack_root_sha256": "sha256:abcdef...",
    "anchor_timestamp": "2026-03-15T12:00:00.000Z",

    "transparency_log": "rekor",
    "log_url": "https://rekor.sigstore.dev",
    "log_index": 123456789,
    "entry_uuid": "24296fb24b8ad77a...",

    "inclusion_proof": {
        "checkpoint": "rekor.sigstore.dev - ...",
        "hashes": ["sha256:...", "sha256:..."],
        "log_index": 123456789,
        "root_hash": "sha256:...",
        "tree_size": 987654321
    },

    "signed_entry_timestamp": "base64:...",

    "signer_identity": "tim2208@gmail.com",
    "signer_issuer": "https://accounts.google.com",

    "assay_version": "1.5.0"
}
```

**This file is NOT included in the pack manifest signature** (it's added
after signing). It's a sidecar proof that the pack hash was recorded in
a public log at a specific time.

### 3. `assay verify-pack --require-anchor`

When `--require-anchor` is set:

1. Run normal verification (integrity + claims)
2. Check for `anchor_receipt.json` in pack directory
3. If missing: exit 3 (bad input -- anchor required but not present)
4. Verify `pack_root_sha256` in receipt matches `pack_manifest.json`
5. Verify inclusion proof against Rekor (online check)
6. If Rekor verification fails: exit 2 (integrity -- anchor doesn't match)
7. Report anchor metadata in verify_report.json and verify_transcript.md

**Offline mode:** If `--require-anchor` is set but network is unavailable,
verify the inclusion proof structure and checkpoint signature locally
(Sigstore bundles contain enough data for offline verification of the
Merkle inclusion proof).

### 3a. Outage and fallback behavior

Rekor/Sigstore may be unavailable. Behavior must be explicit and
predictable.

**`assay anchor` (write path):**

| Scenario | Behavior | Exit code |
|----------|----------|-----------|
| Rekor available, submission succeeds | Write `anchor_receipt.json` | 0 |
| Rekor unavailable (network error) | Print error, do NOT write receipt | 1 |
| Rekor available, submission rejected | Print error with rejection reason | 1 |
| `--dry-run` | Print what would be submitted | 0 |

Anchoring never silently succeeds. If `anchor_receipt.json` exists,
it means Rekor accepted the submission. No partial/optimistic writes.

**`assay verify-pack --require-anchor` (read path):**

| Scenario | Behavior | Exit code |
|----------|----------|-----------|
| Anchor present, Rekor verifies | PASS | 0 (or 1 if claims fail) |
| Anchor present, Rekor unavailable | See modes below | |
| Anchor present, Rekor rejects proof | FAIL (integrity) | 2 |
| Anchor absent, `--require-anchor` set | BAD INPUT | 3 |
| Anchor absent, no `--require-anchor` | Skip anchor check | unchanged |

**Two modes for Rekor unavailability during verification:**

```
--require-anchor                  # Default: offline-verify inclusion proof
                                  # (verify checkpoint signature + Merkle path locally)
                                  # Exit 0 if local proof checks pass

--require-anchor --anchor-online  # Strict: must contact Rekor
                                  # Exit 2 if Rekor unreachable
```

The default (`--require-anchor` without `--anchor-online`) is
**offline-safe**: it verifies the inclusion proof cryptographically
without contacting Rekor. This is correct because the inclusion proof
in `anchor_receipt.json` is self-contained -- it includes the Rekor
checkpoint signature and Merkle path, which can be verified against
Sigstore's root of trust (bundled in the `sigstore` Python package).

The strict mode (`--anchor-online`) additionally queries Rekor to
confirm the entry still exists and hasn't been removed. This is for
high-assurance scenarios where log consistency matters.

**verify_report.json anchor fields:**
```json
{
    "anchor": {
        "present": true,
        "verified": true,
        "verification_mode": "offline|online",
        "log_index": 123456789,
        "anchor_timestamp": "2026-03-15T12:00:00Z",
        "rekor_reachable": true,
        "warnings": []
    }
}
```

### 4. Manifest metadata extension

After anchoring, the verify_transcript.md gains an "Anchor" section:

```markdown
## Anchor

| Field | Value |
|-------|-------|
| Trust tier | T2 (independent witness) |
| Transparency log | Rekor (rekor.sigstore.dev) |
| Log index | 123456789 |
| Anchored at | 2026-03-15T12:00:00Z |
| Signer identity | tim2208@gmail.com |
```

---

## CLI interface

```
assay anchor <pack_dir>
    --keyless              Use Sigstore OIDC keyless signing (default)
    --key <path>           Use local key for Sigstore signing
    --rekor-url <url>      Custom Rekor instance (default: public)
    --dry-run              Show what would be submitted, don't submit

assay anchor --status <pack_dir>
    Print anchor status: anchored/not-anchored, log index, timestamp

assay verify-pack <pack_dir>
    --require-anchor       Fail if pack is not anchored
    --anchor-offline       Verify inclusion proof without contacting Rekor
```

---

## Implementation notes

### Sigstore Python SDK

The `sigstore` Python package provides:

```python
from sigstore.sign import SigningContext
from sigstore.verify import Verifier

# Keyless signing (OIDC browser flow)
with SigningContext.production() as ctx:
    result = ctx.signer().sign(artifact=pack_root_bytes)
    bundle = result.bundle

# Verify
verifier = Verifier.production()
verifier.verify(bundle, artifact=pack_root_bytes)
```

The bundle contains the Rekor entry, inclusion proof, and signed
timestamp. We extract these into `anchor_receipt.json`.

### Key modes

| Mode | Flag | How |
|------|------|-----|
| Keyless (default) | `--keyless` | OIDC browser flow, identity = email |
| Local key | `--key path` | Ed25519 key from Assay keystore |
| CI key | env `ASSAY_ANCHOR_KEY` | For automated CI workflows |

Keyless is default because it provides the strongest identity binding
(email from identity provider). Local key is for air-gapped or
automated environments.

### What goes to Rekor

Only the `pack_root_sha256` hash. Not the pack contents, not the
receipts, not any PII. Rekor records:
- The hash
- The signer's identity
- The timestamp
- The inclusion proof

This is safe for any sensitivity level. No data leaves the machine
except a 32-byte hash.

---

## Lockfile integration

If the project uses `assay.lock`, add an optional field:

```yaml
# In assay.lock
require_anchor: true        # Verify-pack fails without anchor
anchor_log: "rekor"          # Expected transparency log
```

This makes anchor requirements enforceable in CI without remembering
the `--require-anchor` flag.

---

## Exit criteria

- [ ] `assay anchor ./proof_pack_*/` submits to Rekor and writes `anchor_receipt.json`
- [ ] `assay verify-pack --require-anchor` checks inclusion proof
- [ ] Offline verification works with `--anchor-offline`
- [ ] `assay anchor --status` shows anchor metadata
- [ ] verify_transcript.md shows anchor section when present
- [ ] verify_report.json includes anchor metadata when present
- [ ] Keyless OIDC flow works interactively
- [ ] CI key flow works non-interactively
- [ ] `assay.lock` supports `require_anchor` field
- [ ] No `sigstore` dependency for core assay-ai install
- [ ] Tests with mock Rekor (no network needed)
- [ ] 15+ tests for anchor lifecycle

---

## What this does NOT include (deferred)

- RFC 3161 TSA support (Sigstore provides timestamps, sufficient for now)
- Multiple anchors per pack (one anchor is enough for T2)
- Anchor revocation
- TPM/SGX attestation (T3 -- future)
- Post-quantum migration (academic, not practical yet)
- Anchor for individual receipts (pack-level is sufficient)
