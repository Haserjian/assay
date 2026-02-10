# Assay: Owner's Manual

Everything you need to understand about what you built, how it works,
and how to prove it works. Written for you, not for users.

---

## Part 1: What You Built (The Primitive)

Assay is a **receipt-to-proof-pack pipeline**. That's the whole thing.

Your AI system does work. During that work, structured evidence events
("receipts") get emitted. After the work is done, those receipts get
packaged into a cryptographically signed bundle ("Proof Pack") that
anyone can verify independently.

The key architectural decision -- the thing that makes this different
from logging -- is the **integrity/claims split**:

- **Integrity** answers: "Were these bytes tampered with after creation?"
- **Claims** answer: "Does this evidence satisfy declared behavioral checks?"

These are deliberately independent. That creates four possible outcomes:

| Integrity | Claims | Exit | What it means |
|-----------|--------|------|---------------|
| PASS | PASS | 0 | Evidence authentic, behavior meets standards |
| PASS | FAIL | 1 | Evidence authentic, behavior violated standards |
| FAIL | -- | 2 | Evidence has been tampered with |
| PASS | SKIP | 0 | Evidence authentic, no behavioral checks declared |

**Exit code 1 is the important one.** It's called "honest failure" --
authentic, signed evidence proving your system violated its own declared
standards. This is more trustworthy than systems that always claim to pass,
because it proves the system reports truthfully even when the news is bad.

### What it does NOT prove

This is critical. Say this in every public post:

1. **Completeness**: Assay verifies receipts that exist. It cannot prove
   receipts that *should* exist but were never emitted. If your code
   makes 10 API calls but only instruments 3, the pack shows 3.

2. **Source honesty**: Receipts are self-attested. The signing proves
   the bytes weren't changed *after creation*, not that they were
   truthfully created in the first place.

3. **Timestamp anchoring**: Timestamps come from the local clock.
   Without an external time authority, they can be fabricated.

4. **Freshness**: A valid pack can be replayed. No challenge-nonce
   is enforced.

5. **Trust root**: The embedded public key allows self-signed truth.
   No external trust anchor exists yet (no CA, no witness network).

These aren't bugs. They're the boundary of what self-attested evidence
can prove. Over-claiming destroys trust faster than bugs.

---

## Part 2: How Data Flows (End to End)

Here's what happens when someone runs:
```
assay run -c receipt_completeness -c guardian_enforcement -- python app.py
```

### Step 1: Trace setup

`commands.py` generates a trace ID like `trace_20260209T120000_a1b2c3d4`.
This creates a JSONL file at `~/.loom/assay/2026-02-09/trace_20260209T120000_a1b2c3d4.jsonl`.

### Step 2: Subprocess launch

The child process (`python app.py`) is launched with `ASSAY_TRACE_ID`
set in its environment. This is the bridge -- the child doesn't need
to know about the parent.

### Step 3: Receipt emission

Inside the child process, receipts get written. Two ways this happens:

**Auto-patch (one line in user code):**
```python
from assay.integrations.openai import patch; patch()
```
This monkey-patches `openai.resources.chat.completions.Completions.create`.
Every API call now emits a `model_call` receipt automatically. The patch:
- Times the call (latency_ms)
- Captures token counts from response.usage
- SHA-256 hashes inputs/outputs (privacy-preserving, 16 chars truncated)
- Writes the receipt in a `finally` block (even errors get recorded)

**Manual:**
```python
from assay import emit_receipt
emit_receipt("model_call", {"provider": "openai", "model_id": "gpt-4", ...})
emit_receipt("guardian_verdict", {"verdict": "allow"})
```

Both paths call the same function: `store.emit_receipt()`. This function:
1. Reads `ASSAY_TRACE_ID` from the environment
2. Opens (or creates) the JSONL trace file
3. Assigns a monotonically increasing sequence number (`seq`)
4. Generates a receipt ID (`r_<12 hex chars>`)
5. Adds timestamp (ISO 8601 UTC) and `schema_version: "3.0"`
6. Appends one JSON line to the trace file

### Step 4: Pack building

After the child exits, the parent reads the JSONL trace file and builds
a Proof Pack. Here's exactly what `ProofPack.build()` does:

**4a. Sort receipts deterministically.**
By (run_id, seq, receipt_id). Same receipts always produce same order.

**4b. Write `receipt_pack.jsonl`.**
Each receipt is JCS-canonicalized (RFC 8785 -- deterministic JSON
serialization with sorted keys, no whitespace, IEEE 754 floats).
One canonical JSON object per line.

**4c. Verify receipt integrity.**
`verify_receipt_pack()` checks each receipt:
- Required fields present (receipt_id, type, timestamp)
- Timestamps parse as valid ISO 8601
- JCS round-trip stability (serialize -> parse -> serialize = identical bytes)
- No duplicate receipt IDs

Computes `head_hash` = SHA-256 of the JCS-canonical last receipt.

**4d. Verify claims.**
For each RunCard specified with `-c`:
- `receipt_completeness` has 2 claims: at least 1 receipt total + at least 1 model_call
- `guardian_enforcement` has 1 claim: at least 1 guardian_verdict receipt

Each claim calls a check function against the receipt list. 5 built-in checks:
- `receipt_type_present` -- does type X exist?
- `no_receipt_type` -- does type X NOT exist?
- `receipt_count_ge` -- are there >= N receipts?
- `timestamps_monotonic` -- are timestamps non-decreasing?
- `field_value_matches` -- do all receipts of type X have field Y = Z?

Result: ClaimSetResult with per-claim PASS/FAIL and a `discrepancy_fingerprint`
(SHA-256 of the canonical claim results -- unique to this exact outcome).

**4e. Write `verify_report.json`.**
Machine-readable: integrity result, claim results, receipt count, head hash.

**4f. Build the attestation.**
This is the core identity object:
```json
{
  "pack_format_version": "0.1.0",
  "receipt_integrity": "PASS",
  "claim_check": "PASS",
  "head_hash": "<sha256 of last receipt>",
  "n_receipts": 5,
  "timestamp_start": "...",
  "timestamp_end": "...",
  "canon_version": "jcs-rfc8785",
  "time_authority": "local_clock",
  "assurance_level": "L0",
  "proof_tier": "signed-pack",
  "mode": "shadow",
  ...
}
```

The attestation is JCS-canonicalized and SHA-256'd to produce
`attestation_sha256`. This hash is the pack's immutable identity.

**4g. Write `verify_transcript.md`.**
Human-readable markdown summary.

**4h. Build the unsigned manifest.**
Contains:
- SHA-256 hash and byte count of every file (receipt_pack.jsonl,
  verify_report.json, verify_transcript.md)
- The attestation object
- `attestation_sha256`
- `receipt_count_expected`
- `signer_id`, `signer_pubkey` (base64 Ed25519 public key),
  `signer_pubkey_sha256` (fingerprint)
- `claim_set_hash` (SHA-256 of the JCS-canonical claim specs)

**4i. Sign.**
The unsigned manifest is JCS-canonicalized. The canonical bytes are
signed with Ed25519 using the signer's private key
(default: `~/.loom/assay/keys/assay-local.key`).

**4j. Write `pack_manifest.json`.**
The signed manifest = unsigned manifest + `signature` (base64) +
`pack_root_sha256` (= attestation_sha256, the D12 invariant).

**4k. Write `pack_signature.sig`.**
Raw 64-byte Ed25519 signature, same bytes as in the manifest.
Exists as a separate file for offline verification tools.

**4l. Write `PACK_SUMMARY.md`.**
Plain-English explanation via `explain.py`. Not part of the 5-file
verification kernel -- a presentation extra. Wrapped in try/except
so it never fails a pack build.

### Step 5: Output

The user sees a Rich panel:
```
Proof Pack Built
  Pack ID:    pack_20260209T120000_a1b2c3d4
  Integrity:  PASS
  Claims:     PASS
  Receipts:   5
  Output:     ./proof_pack_20260209T120000_a1b2c3d4/
```

### The 5-file kernel

```
proof_pack_<id>/
  receipt_pack.jsonl      # Evidence (the receipts, JCS-canonical)
  pack_manifest.json      # File hashes + signature + attestation
  pack_signature.sig      # Detached Ed25519 signature (same bytes)
  verify_report.json      # Machine-readable verification verdict
  verify_transcript.md    # Human-readable summary
  PACK_SUMMARY.md         # (bonus) Plain-English explanation
```

---

## Part 3: How Verification Works

When someone runs `assay verify-pack ./proof_pack_*/`, here's what happens:

### Check 1: File hashes

For each file listed in `pack_manifest.json`, read the file from disk,
compute SHA-256, compare against the hash in the manifest. If any hash
doesn't match: `E_MANIFEST_TAMPER`, exit 2.

### Check 2: Receipt re-verification

Parse `receipt_pack.jsonl` from disk. Count lines -- must match
`receipt_count_expected` in the manifest. Run `verify_receipt_pack()`
on the parsed receipts. Compare the result (PASS/FAIL) against what
the attestation claims for `receipt_integrity`. Compare the recomputed
`head_hash` against the attestation's `head_hash`. Any mismatch:
`E_MANIFEST_TAMPER` or `E_PACK_OMISSION_DETECTED`.

### Check 3: Attestation hash

Recompute `sha256(JCS(attestation))`. Compare against
`manifest["attestation_sha256"]`. Mismatch = `E_MANIFEST_TAMPER`.

### Check 4: Signature

Strip `signature` and `pack_root_sha256` from the manifest to
reconstruct the unsigned version. JCS-canonicalize it. Verify the
Ed25519 signature against the embedded `signer_pubkey`.

Also check: raw bytes in `pack_signature.sig` must match the
base64-decoded signature in the manifest. Mismatch =
`E_PACK_SIG_INVALID`.

Also check: `pack_root_sha256` must equal `attestation_sha256`
(the D12 invariant). Mismatch = `E_MANIFEST_TAMPER`.

### Check 5: Lockfile (if --lock provided)

- Pack format version must match lockfile
- `claim_set_hash` must match (claims haven't been weakened)
- Signer fingerprint must be in the allowlist (if mode=allowlist)
- Assay version must be >= lockfile minimum

### Why this is hard to defeat

To produce a forged pack that passes verification, an attacker would
need to:

1. Modify the receipt file AND recompute its SHA-256 hash AND update
   the manifest AND re-sign the manifest with the private key.

Without the private key, step 4 fails. The signature covers the
entire canonical manifest, which contains the file hashes, which
contain the receipt hashes. Change any byte anywhere, and either
the hash chain breaks or the signature breaks.

The embedded public key means you can verify without access to the
signer's infrastructure. The lockfile means you can detect if someone
quietly changed which claims are being checked.

---

## Part 4: The Lockfile (Why It Matters More Than You Think)

Without a lockfile, verification is honest but **driftable**. You can
quietly drop the `guardian_enforcement` card between runs and nobody
notices -- the pack still says "claims PASS" because fewer claims
were checked.

The lockfile pins:
- Exactly which cards are active (by hash)
- The composite hash of all claim specs
- The flat `claim_set_hash` (matches what ProofPack computes)
- Allowed signer fingerprints
- Minimum Assay version
- Exit code contract (0/1/2 semantics)

Two hashes, different things:
- `run_cards_composite_hash`: hash of the per-card hashes (detects per-card drift)
- `claim_set_hash`: hash of all flattened claim specs (matches the pack manifest)

When `verify-pack --lock assay.lock` runs, it checks the pack's
`claim_set_hash` against the lockfile's. If they differ, exit 2.
This means you can't weaken your checks without the lockfile catching it.

---

## Part 5: The Conformance Corpus

This is how you **prove** the verifier works. It lives in `conformance/`.

### What it is

6 pre-built packs generated with a deterministic Ed25519 key (derived
from `SHA-256("assay-corpus-v1-signer-key-seed")`). Byte-reproducible
across environments.

### The 6 packs

| Pack | What it tests | Expected exit |
|------|---------------|---------------|
| `good_01` | 1 model_call + 1 guardian_verdict, full claims | 0 |
| `good_02` | 4 model_calls + 1 guardian_verdict | 0 |
| `good_03` | 2 model_calls, receipt_completeness only | 0 |
| `claimfail_01` | 1 model_call, no guardian (honest failure) | 1 |
| `tampered_01` | Field injected after packing (hash mismatch) | 2 |
| `tampered_02` | Receipt deleted after packing (omission) | 2 |

### How to run it

```bash
cd ~/assay
source .venv/bin/activate
python conformance/run_corpus.py
```

If this exits 0, every pack produced the expected exit code.
The tampered packs were tampered correctly and caught correctly.

### Why this matters

The conformance corpus is your strongest evidence that Assay works.
It tests the three possible outcomes (pass, honest failure, tamper
detection) against known-good data with a deterministic key. If
someone asks "how do you know the verifier works?", point them here.

---

## Part 6: How to Demonstrate It Works (Live)

### Demo 1: The 30-second pitch (no setup)

```bash
pip install assay-ai
assay demo-incident
```

Shows two acts with synthetic data:
- Act 1: gpt-4 with guardian -> PASS/PASS
- Act 2: gpt-3.5-turbo, no guardian -> PASS/FAIL (honest failure)

Same tool, different evidence, different verdict. The point: the tool
reports truthfully even when the run violates standards.

### Demo 2: Tamper detection (no trust required)

```bash
assay demo-challenge
assay verify-pack challenge_pack/good/
assay verify-pack challenge_pack/tampered/
```

Good pack: PASS. Tampered pack: `E_MANIFEST_TAMPER` (one byte was
changed, hash caught it). This proves the crypto works.

### Demo 3: Full build-verify cycle

```bash
assay demo-pack
```

Builds two packs from the same 5 synthetic receipts:
- Pack A: 4 reasonable claims -> PASS/PASS
- Pack B: unreasonable claim (need 100 receipts) -> PASS/FAIL

Same evidence, different claims, different outcomes. Proves integrity
and claims are independent axes.

### Demo 4: Explain what a pack says

```bash
assay explain ./proof_pack_*/ --format md
```

Produces a structured summary: what happened, integrity status,
claim results, what it proves, what it does NOT prove. This is
the artifact people paste into security questionnaires.

### Demo 5: The conformance corpus

```bash
python conformance/run_corpus.py
```

6 packs, 3 expected outcomes, deterministic key. If this passes,
the verifier is correct.

### Demo 6: End-to-end with real code

```bash
# Write a tiny script that uses the OpenAI integration
cat > /tmp/test_app.py << 'EOF'
from assay.integrations.openai import patch; patch()
from unittest.mock import MagicMock
import openai

# Mock the API (no key needed)
client = openai.OpenAI(api_key="fake")
mock_response = MagicMock()
mock_response.usage.prompt_tokens = 100
mock_response.usage.completion_tokens = 50
mock_response.choices = [MagicMock()]
mock_response.choices[0].finish_reason = "stop"
mock_response.choices[0].message.content = "Hello"

import openai.resources.chat.completions as comp
original = comp.Completions.create.__wrapped__ if hasattr(comp.Completions.create, '__wrapped__') else None
# This won't work as-is because the mock needs to be deeper.
# Use demo-pack or demo-incident instead for live demos.
EOF

# Better: just use the demos
assay demo-pack
assay verify-pack ./proof_pack_*/
assay explain ./proof_pack_*/ --format md
```

For a real end-to-end demo with actual API calls, you'd need an
OpenAI or Anthropic API key. The demos use synthetic data to avoid
this requirement.

---

## Part 7: The Trust Chain (What Proves What)

Here's the chain of evidence, from bottom to top:

```
Receipt bytes
    |
    v  SHA-256 hash
head_hash (last receipt's canonical hash)
    |
    v  embedded in attestation
attestation_sha256 (hash of canonical attestation)
    |
    v  embedded in manifest, bound by D12 invariant
pack_root_sha256 == attestation_sha256
    |
    v  manifest contains file hashes
file hashes (SHA-256 of each file on disk)
    |
    v  unsigned manifest is JCS-canonicalized
canonical_bytes
    |
    v  Ed25519 signature
signature (64 bytes, covers the entire canonical manifest)
    |
    v  embedded public key
signer_pubkey (allows verification without infrastructure access)
    |
    v  lockfile pins claim_set_hash + signer fingerprint
lockfile (prevents silent weakening of checks)
```

Break any link and verification fails. The signature covers the
manifest, which covers the file hashes, which cover the receipt bytes.

### Why JCS (RFC 8785)?

JSON is not deterministic. `{"a":1,"b":2}` and `{"b":2,"a":1}` are
semantically identical but different bytes. If you hash or sign JSON,
you need canonical serialization or the same data produces different
hashes on different machines.

JCS defines: sorted keys (UTF-16BE order), no whitespace, IEEE 754
float encoding, minimal string escaping. Two implementations that
agree on the data will produce identical bytes.

Assay uses JCS everywhere: receipt canonicalization, attestation
hashing, manifest signing, claim spec hashing for lockfiles. It's
the foundation that makes cross-platform verification possible.

The implementation is in `src/assay/_receipts/jcs.py` -- pure Python,
~100 lines. There's a locked test vector in the test suite that pins
the exact output to prevent regression.

---

## Part 8: File Map

### Source code (`src/assay/`)

| File | What it does | Lines |
|------|-------------|-------|
| `cli.py` | Entrypoint (`assay` command) | ~10 |
| `commands.py` | All CLI commands (Typer) | ~3300 |
| `store.py` | Receipt emission + JSONL storage | ~250 |
| `proof_pack.py` | 5-file pack builder + signing | ~400 |
| `integrity.py` | Structural verification (<500 LOC budget) | ~450 |
| `claim_verifier.py` | Semantic claim checking | ~200 |
| `run_cards.py` | 5 built-in RunCard definitions | ~150 |
| `keystore.py` | Ed25519 key management (PyNaCl) | ~150 |
| `scanner.py` | AST-based LLM call site detection | ~450 |
| `doctor.py` | Preflight checks (13 checks, 4 profiles) | ~400 |
| `lockfile.py` | Governance lockfile read/write/validate | ~300 |
| `explain.py` | Plain-English pack summaries | ~200 |
| `integrations/openai.py` | OpenAI monkey-patch | ~200 |
| `integrations/anthropic.py` | Anthropic monkey-patch | ~200 |
| `integrations/langchain.py` | LangChain callback handler | ~200 |
| `_receipts/` | Vendored: JCS, Merkle, Pydantic compat | ~600 |
| `schemas/` | JSON Schema for manifest + attestation | 2 files |

### Tests (`tests/assay/`)

| File | What it tests | Tests |
|------|-------------|-------|
| `test_proof_pack.py` | Full pack lifecycle, tamper detection, orthogonal axes | ~160 |
| `test_integrity_mutants.py` | 12 mutation scenarios + LOC budget | ~15 |
| `test_scanner.py` | AST scanning, confidence tiers, excludes | ~73 |
| `test_lockfile.py` | Lockfile write/validate/check + conformance | ~25 |
| `test_integrations.py` | SDK patching, privacy, pack compatibility | ~40 |
| `test_doctor.py` | Preflight check engine | ~40 |
| `test_onboard_ci.py` | Onboard + CI workflow generation | ~5 |
| Others | Health, guardian, store, bridge, etc. | ~55 |
| **Total** | | **413** |

### Key invariants enforced by tests

- `integrity.py` stays under 500 lines (structural budget test)
- JCS test vector is pinned (cross-implementation stability)
- Tamper detection catches: field injection, receipt deletion,
  manifest modification, signature corruption, hash mismatch,
  receipt count mismatch, attestation lie, head hash mismatch
- Integrity PASS + Claims FAIL produces exit code 1 (honest failure)
- Same receipts + different claims = same integrity, different claims
  (orthogonal axes proof)
- Conformance corpus: 6 packs, 3 expected exit codes

---

## Part 9: The Commands (What Users See)

### Visible in `assay --help` (13 commands)

**The golden path:**
| Command | What it does |
|---------|-------------|
| `run` | Wrap a command, collect receipts, build signed pack |
| `verify-pack` | Verify integrity + claims of a pack |
| `explain` | Plain-English pack summary (text/md/json) |
| `scan` | Find uninstrumented LLM call sites (AST-based) |
| `doctor` | Preflight checks, always gives one next command |
| `onboard` | Guided setup: doctor -> scan -> patch suggestion |

**Demos (no config needed):**
| Command | What it shows |
|---------|--------------|
| `demo-incident` | Two-act honest failure scenario |
| `demo-challenge` | CTF: good pack vs tampered pack |
| `demo-pack` | Build + verify from scratch |

**Governance:**
| Command | What it does |
|---------|-------------|
| `lock write` | Freeze verification contract to `assay.lock` |
| `lock check` | Validate lockfile integrity |
| `ci init github` | Generate GitHub Actions workflow |

**Utility:**
| Command | What it does |
|---------|-------------|
| `proof-pack` | Build pack from an existing trace (advanced) |
| `version` | Show version info |

### Hidden but functional (9 legacy commands)

`validate`, `health`, `demo`, `show`, `list`, `verify`, `diff`,
`pack`, `launch-check`. These are from the pre-Proof-Pack era.
They still work (`assay validate --help` exits 0) but don't
show in `--help` to keep the golden path clean.

---

## Part 10: What's Deployed Where

### PyPI: `assay-ai`

```bash
pip install assay-ai           # latest (currently 1.2.2)
pip install assay-ai==1.2.2    # pinned
```

Version history:
- 1.0.0: Initial (receipts, proof packs, verification, SDK patches)
- 1.1.0: Scanner, doctor
- 1.2.0: Partial upload (explain, demos), filename claimed
- 1.2.1: + onboard, ci init, scanner next-steps
- 1.2.2: + clean help surface, scanner excludes, compat CI (current)

### GitHub: `Haserjian/assay`

https://github.com/Haserjian/assay

Branch: `main`. Tags: `v1.0.0` through `v1.2.2`.
Releases: https://github.com/Haserjian/assay/releases

### Related repos

| Repo | What it is |
|------|-----------|
| `Haserjian/assay` | Core CLI + SDK + conformance corpus |
| `Haserjian/assay-verify-action` | GitHub Action for CI (composite) |
| `Haserjian/assay-ledger` | Public transparency ledger (GitHub Pages) |

### CI

- `.github/workflows/compat.yml`: SDK compatibility matrix (weekly +
  push on integration changes). 6 jobs: min+latest for OpenAI,
  Anthropic, LangChain.

---

## Part 11: The Scan Study

You scanned 30 open-source AI repos and found 202 high-confidence
SDK call sites, 0 instrumented. The report is at
`scripts/scan_study/results/report.md`.

Post drafts are ready at:
- `scripts/scan_study/posts/hn.md` -- HN (tightened, one-liner first)
- `scripts/scan_study/posts/reddit.md` -- Reddit (+ pilot CTA)
- `scripts/scan_study/posts/discord.md` -- Discord (short)
- `scripts/scan_study/posts/comment_replies.md` -- 8 pre-written objection responses

Permalinks point to commit `9641c7c`.

---

## Part 12: Quick Reference

### How to run everything

```bash
cd ~/assay
source .venv/bin/activate

# Tests (413, ~2 seconds)
pytest tests/assay/ -q

# Conformance corpus
python conformance/run_corpus.py

# Full demo cycle
assay demo-incident
assay demo-challenge
assay verify-pack challenge_pack/good/
assay verify-pack challenge_pack/tampered/
assay demo-pack
assay explain ./proof_pack_*/ --format md

# Scanner
assay scan ~/some-project

# Doctor
assay doctor

# Onboard
assay onboard ~/some-project

# Lock
assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
assay lock check assay.lock

# CI workflow generation
assay ci init github --run-command "python app.py"
```

### Where data lives at runtime

```
~/.loom/assay/
  keys/
    assay-local.key    # Ed25519 private key (32 bytes)
    assay-local.pub    # Ed25519 public key (32 bytes)
  2026-02-09/
    trace_20260209T120000_a1b2c3d4.jsonl   # receipts
```

### The receipt format

```json
{
  "receipt_id": "r_a1b2c3d4e5f6",
  "type": "model_call",
  "timestamp": "2026-02-09T12:00:00.000000+00:00",
  "schema_version": "3.0",
  "seq": 0,
  "provider": "openai",
  "model_id": "gpt-4",
  "input_tokens": 100,
  "output_tokens": 50,
  "total_tokens": 150,
  "latency_ms": 1200,
  "input_hash": "a1b2c3d4e5f6g7h8",
  "output_hash": "i9j0k1l2m3n4o5p6",
  "integration_source": "assay.integrations.openai"
}
```

Required fields: `receipt_id`, `type`, `timestamp`.
Everything else is type-specific payload.

### The 5 built-in RunCards

| Card | Claims | What passes |
|------|--------|-------------|
| `receipt_completeness` | min 1 receipt + 1 model_call | Any run with an LLM call |
| `guardian_enforcement` | 1 guardian_verdict exists | Runs with guardian checks |
| `no_breakglass` | 0 breakglass receipts | Runs without overrides |
| `timestamp_ordering` | timestamps non-decreasing | Normal execution order |
| `schema_consistency` | all model_calls use schema 3.0 | Modern receipt format (warning, not critical) |

### Exit codes

```
0 = integrity PASS, claims PASS (or no claims)
1 = integrity PASS, claims FAIL (honest failure)
2 = integrity FAIL (tampering or lock mismatch)
```

---

## Part 13: What to Say When Someone Asks Hard Questions

**"How is this different from logging?"**

Logs are mutable narrative under your control. You can edit them,
delete them, selectively present them. A Proof Pack is a signed
evidence bundle with hash-chained integrity -- change one byte and
verification fails. You can hand the folder to someone who doesn't
trust you and they can verify it independently.

**"Can't you just fake the receipts?"**

Yes. Receipts are self-attested. Assay proves evidence hasn't been
*tampered with after creation*, not that it was honestly created.
This is stated explicitly in every explanation output. The value
is tamper-evidence and portability, not omniscient truth.

**"What about the signing key?"**

The key is local by default (`~/.loom/assay/keys/assay-local.key`).
This allows self-signed truth. The lockfile's signer policy can
restrict which key fingerprints are accepted. A future witness
network could provide external trust anchoring, but that's not
built yet.

**"Why not just use a blockchain?"**

Because nobody needs a blockchain for this. The signing is Ed25519,
the hashing is SHA-256, the serialization is JCS. The pack is 5
files in a folder. No consensus mechanism, no gas fees, no network
dependency. A Proof Pack works offline.

**"What happens if the OpenAI SDK changes?"**

The monkey-patches target specific methods (`Completions.create`,
`AsyncCompletions.create`). If OpenAI moves these, the patch breaks.
The compat CI workflow (`compat.yml`) tests against latest SDK
versions weekly and catches this before users do. The LangChain
integration uses their callback handler pattern (more stable).

**"Why JCS instead of just sorting keys?"**

JCS (RFC 8785) handles edge cases that naive sorting doesn't:
UTF-16BE key ordering, IEEE 754 float encoding, NaN rejection.
Two implementations that follow the RFC will produce identical
bytes for the same data. This matters because the signature
covers canonical bytes -- if canonicalization differs between
the signer and verifier, the signature check fails even though
the data is the same.
