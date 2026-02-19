# Order of Operations

How to use Assay, by use case. Each RunCard is a self-contained workflow
with inputs, steps, artifacts, and a clear "next" pointer.

## Decision tree

| Goal | Start here |
|------|-----------|
| "Show me tamper detection works" | RunCard A |
| "Instrument my app" | RunCard B |
| "Gate my CI" | RunCard C (after B) |
| "Track behavior changes" | RunCard D (after C) |
| "Hand evidence to an auditor" | RunCard E |
| "Audit MCP tool calls" | RunCard F |
| "Weekly ops cadence" | RunCard G |

The default spine: **scan -> patch -> run -> verify-pack -> lock -> CI gate**.

---

## RunCard A: Demo Tamper Detection (5 min)

**Goal:** See that tampering shows up as exit 2.

```bash
pip install assay-ai
assay quickstart .
assay verify-pack ./challenge_pack/good/       # exit 0 (pass)
assay verify-pack ./challenge_pack/tampered/    # exit 2 (tampered)
```

**Artifact:** `challenge_pack/` (good + tampered packs)

**Next:** Instrument your code (RunCard B)

---

## RunCard B: Instrument and Capture (15 min)

**Goal:** Your app produces signed evidence packs.

```bash
# 1. Find LLM call sites
assay scan .

# 2. Auto-patch (or add manually: from assay.integrations.openai import patch; patch())
assay patch .

# 3. Run your app -- receipts collected, pack built automatically
assay run -- python your_app.py

# 4. Verify the pack
assay verify-pack ./proof_pack_*/

# 5. Read what happened
assay explain ./proof_pack_*/
```

**How it works:** `assay run` sets `ASSAY_TRACE_ID` in the environment, spawns
your command as a subprocess. SDK integrations detect the env var and route
receipts to `~/.assay/<date>/<trace_id>.jsonl`. After the subprocess exits,
`assay run` reads the trace and builds a 5-file proof pack (receipts, manifest,
signature, verify report, transcript).

**Artifact:** `proof_pack_<trace_id>/`

**Next:** Lock the contract (RunCard C)

---

## RunCard C: Lock the Contract (10 min)

**Goal:** Completeness and policy become enforceable.

```bash
# 1. Create a lockfile with sane defaults
assay lock init

# 2. Verify against the lock
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
```

The lockfile freezes which verification cards run, the pack format version,
and the signer policy. Config drift between environments now fails verification.

**Artifact:** `assay.lock`

**Next:** Gate CI (RunCard D)

---

## RunCard D: CI Gate (30 min)

**Goal:** PRs cannot merge without evidence checks.

```bash
# 1. Generate a GitHub Actions workflow
assay ci init github --run-command "python your_app.py"

# 2. Commit the lockfile
git add assay.lock .github/workflows/assay-verify.yml
git commit -m "Add Assay CI evidence gate"
```

The CI workflow runs three checks:
1. `assay run -c receipt_completeness -- <cmd>` (collect evidence)
2. `assay verify-pack ... --lock assay.lock --require-claim-pass` (integrity + policy)
3. `assay diff ... --gate-cost-pct 25 --gate-errors 0` (regression budget)

Optional: add the [assay-verify-action](https://github.com/Haserjian/assay-verify-action)
for PR comments with verification summaries.

**Artifact:** CI workflow YAML + enforced gate

**Next:** Track changes (RunCard E)

---

## RunCard E: Track Changes Over Time

**Goal:** Behavior changes become visible and gateable.

```bash
# Compare two packs
assay diff ./pack_baseline/ ./pack_new/

# Auto-discover previous pack (mtime-based)
assay diff ./pack_new/ --against-previous

# Causal chain for regressions
assay diff ./pack_new/ --against-previous --why

# HTML/JSON report for CI artifacts
assay diff ./pack_new/ --against-previous --report

# Historical cost/latency analysis from local traces
assay analyze --history --days 30
```

**Artifact:** Diff report (HTML/JSON)

**Next:** Auditor handoff (RunCard F) or weekly ops (RunCard G)

---

## RunCard F: Auditor Handoff (offline)

**Goal:** A third party verifies your evidence on their machine, without trusting you.

```bash
# Auditor receives the pack directory and runs:
assay verify-pack ./proof_pack_*/                 # offline, no API needed
assay explain ./proof_pack_*/ --format json       # machine-readable summary
```

The auditor checks:
- Exit 0 = evidence checks out (integrity PASS, claims PASS)
- Exit 1 = honest failure (authentic evidence of a control violation)
- Exit 2 = tampered evidence

Signer identity verification by trust tier:
- **T0:** Compare `signer_pubkey_sha256` from manifest to out-of-band fingerprint
- **T1:** Compare fingerprint to repo-committed key in `.assay/keys/<signer_id>.pub`
- **T2:** Look up fingerprint in assay-ledger or Rekor transparency log

**Artifact:** Verified pack + explanation report

---

## RunCard G: MCP Tool Audit

**Goal:** Audit trail for MCP tool calls (observe mode, not enforcement).

```bash
# 1. Generate a policy file
assay mcp policy init

# 2. Run your MCP server through the proxy
assay mcp-proxy -- python my_mcp_server.py

# 3. Pack auto-built on clean exit; verify it
assay verify-pack .assay/mcp/packs/proof_pack_*/
```

The proxy sits between client and server, intercepts `tools/call` JSON-RPC
messages, and emits `mcp_tool_call` receipts. Arguments are hashed by default
(privacy-preserving); use `--store-args` to capture cleartext.

MCP receipts go to `.assay/mcp/receipts/session_<timestamp>.jsonl`.
Regular SDK receipts go to `~/.assay/<date>/<trace_id>.jsonl`.

**Artifact:** MCP proof pack

---

## RunCard H: Weekly Ops Cadence

**Goal:** Ongoing governance hygiene.

```bash
# 1. Cost/latency/error trends
assay analyze --history --days 7

# 2. Evidence readiness
assay score .

# 3. Environment health
assay doctor

# 4. Review CI diff gate failures from the week

# 5. Key rotation (when key lifecycle hardening ships)
assay key rotate --lock assay.lock
```

---

## The six-command spine

Every workflow above is a subset of this default path:

```
scan -> patch -> run -> verify-pack -> lock -> CI gate
```

If you remember nothing else, remember the spine.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Pass (integrity OK, claims OK) |
| 1 | Honest failure (integrity OK, claims FAIL -- authentic evidence of a violation) |
| 2 | Tampered (integrity FAIL) |
| 3 | Bad input (missing files, invalid arguments) |

Exit 1 is audit gold: authentic evidence that a control failed, retained permanently.

---

## Pack anatomy (5 files)

| File | Purpose |
|------|---------|
| `receipt_pack.jsonl` | All receipts, JCS-canonicalized, deterministic order |
| `pack_manifest.json` | Metadata, SHA-256 hashes, signer public key, Ed25519 signature |
| `pack_signature.sig` | Detached Ed25519 signature (raw bytes) |
| `verify_report.json` | Machine-readable verification result |
| `verify_transcript.md` | Human-readable verification narrative |

Change any byte in any receipt, the hash changes, the manifest doesn't match,
verification fails. The signature covers the manifest. Tamper-evidence is
structural, not trust-based.
