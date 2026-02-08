# Assay Quickstart

Receipt-native AI safety toolkit. Build, sign, and verify Proof Packs
that prove what your AI system actually did.

## Install

```bash
pip install assay-ai
```

Verify:

```bash
assay --help
```

## 60-Second Demo

```bash
assay demo-pack
```

This creates 5 synthetic receipts, builds two signed Proof Packs with
different claims against the same evidence, and verifies them. One pack
passes all claims. The other fails -- on purpose -- to demonstrate the
core invariant: **integrity PASS + claim FAIL = honest failure report.**

No API key, no configuration, no git clone required.

## Emit Receipts from Your Code

```python
from assay import emit_receipt

emit_receipt("model_call", {"model": "claude-sonnet-4-20250514", "tokens": 1200})
emit_receipt("guardian_verdict", {"verdict": "allow", "tool": "web_search"})
emit_receipt("capability_use", {"capability": "file_write", "target": "/tmp/out.txt"})
```

`emit_receipt` auto-populates `receipt_id`, `timestamp`, and `schema_version`.
When called inside `assay run`, it picks up `ASSAY_TRACE_ID` from the
environment automatically.

## Wrap a Command

```bash
assay run -- python my_agent.py
assay run -c guardian_enforcement -- pytest tests/
```

This runs the command, collects emitted receipts, builds a signed Proof
Pack, and prints the verdict. Use `--allow-empty` if your command doesn't
emit receipts yet.

## Verify a Pack

```bash
assay verify-pack ./proof_pack_<id>/
```

## CI Gating

```bash
assay verify-pack ./proof_pack_<id>/ --require-claim-pass
```

Exit codes:
- **0** -- integrity PASS and claim_check PASS
- **1** -- integrity PASS but claim_check FAIL (claim gate)
- **2** -- integrity FAIL (structural problem)

## Lock Verification Semantics

Freeze your verification contract so CI, local runs, and external verifiers
use the same claim set and signer policy:

```bash
assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
assay lock check assay.lock
assay verify-pack ./proof_pack_<id>/ --lock assay.lock --require-claim-pass
```

Lock mismatch exits with code **2**.

## Scan for Uninstrumented LLM Calls

Find every LLM call site in your project and check if it has receipt emission:

```bash
assay scan .
assay scan . --json
assay scan . --ci --fail-on high
assay scan src/ --exclude "tests/**"
```

Confidence levels:
- **high** -- direct SDK calls (OpenAI `chat.completions.create`, Anthropic `messages.create`)
- **medium** -- framework wrappers (LangChain `invoke`, LiteLLM `completion`)
- **low** -- heuristic name matches (`call_llm`, `query_model`, etc.)

Each finding includes a per-framework fix suggestion. In CI mode (`--ci`),
exits with code **1** if uninstrumented sites exceed the `--fail-on` threshold.

## Preflight Check

Verify your environment is ready before running Assay:

```bash
assay doctor                          # local dev (default)
assay doctor --profile ci             # CI environment
assay doctor --profile ledger         # ledger submission readiness
assay doctor --profile ledger --strict  # prod: treat warnings as failures
```

Doctor checks install, keys, run cards, lockfile, pack integrity, and CI
integration. It prints the single next command to become "green."

Use `--json` for CI automation, `--fix` to auto-generate missing keys and lockfiles.

## Conformance Corpus (Verifier ABI Check)

Assay ships a conformance corpus with known expected outcomes:

```bash
python conformance/generate_corpus.py
python conformance/run_corpus.py
```

Expected behavior in corpus:
- good packs -> exit `0`
- claim-fail packs -> exit `1`
- tampered packs -> exit `2`

See `conformance/corpus_v1/expected_outcomes.json`.

## What This Does NOT Prove

Assay produces **self-attested evidence**. The integrity verifier proves
evidence hasn't been tampered with *after creation*. It does not prove
evidence was honestly created in the first place. Specifically:

- **Completeness**: Assay verifies receipts that exist. It cannot prove
  receipts that should exist but were never emitted.
- **Freshness**: A valid pack can be replayed. No challenge-nonce or
  freshness window is enforced in v1.
- **Trust root**: Embedded pubkeys allow self-signed truth. No external
  trust anchor or witness protocol exists yet.
- **Timestamp honesty**: Timestamps come from the local clock. Without a
  time authority (RFC 3161), they can be fabricated.
- **Confidentiality**: Receipt hashes of low-entropy fields can be
  brute-forced. No keyed commitments in v1.

Independent attestation (external timestamps, third-party witnesses,
environment-constrained receipt emission) is a planned upgrade path.

## Command Reference

| Command | Purpose |
|---------|---------|
| `assay demo-pack` | Generate demo packs (no config needed) |
| `assay run` | Wrap command execution, collect receipts, build pack |
| `assay verify-pack` | Verify a Proof Pack (integrity + claims) |
| `assay lock write` | Write a lockfile freezing verification contract |
| `assay lock check` | Validate a lockfile against current card definitions |
| `assay scan` | Find uninstrumented LLM call sites |
| `assay doctor` | Preflight check: is Assay ready here? |

## Read Next

- `ASSAY_DEEP_DIVE_2026Q1.md`
- `assay_master_plan.md`
- `ASSAY_DECISION_LOG.md`

## Glossary

| Term | Meaning |
|------|---------|
| **receipt** | Structured record of one action (model call, guardian verdict, etc.) |
| **receipt_integrity** | Structural truth: hashes match, signatures verify, files present |
| **claim_check** | Semantic truth: claims about behavior pass or fail against evidence |
| **Proof Pack** | 5-file signed kernel: `receipt_pack.jsonl`, `verify_report.json`, `verify_transcript.md`, `pack_manifest.json`, `pack_signature.sig` |
| **pack_root_sha256** | SHA-256 of the attestation -- the single immutable pack identifier |
| **discrepancy_fingerprint** | Hash of claim results; same receipts + different claims = different fingerprints |
| **RunCard** | Named collection of claims (e.g., `guardian_enforcement`, `no_breakglass`) |
| **mode** | `shadow` (observe), `enforced` (block on failure), `breakglass` (override with receipt) |
| **signer_id** | Ed25519 key identity used to sign the pack manifest |
| **claim severity** | `critical` (fails the pack) or `warning` (noted but doesn't fail) |

## Built-in RunCards

| Card ID | What it checks |
|---------|----------------|
| `guardian_enforcement` | At least one guardian_verdict receipt exists |
| `receipt_completeness` | At least 1 receipt + at least 1 model_call |
| `no_breakglass` | No breakglass override receipts |
| `timestamp_ordering` | Timestamps are monotonically non-decreasing |
| `schema_consistency` | All model_call receipts use schema_version 3.0 |
