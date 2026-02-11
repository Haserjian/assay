# Assay Quickstart

When someone asks "prove what your AI did," you need more than logs.
Logs live on your infrastructure, under your control. They can be edited,
deleted, or selectively presented. Assay produces **signed evidence bundles**
that anyone can verify independently -- no access to your systems required.

If you're currently filling out spreadsheets to document AI system behavior
for compliance reviews, Assay replaces that process with one CI step.

## Install

```bash
pip install assay-ai
```

## See It Work (No API Key Required)

```bash
assay demo-pack           # build + verify a signed proof pack
assay demo-incident       # see what an honest failure looks like
assay demo-challenge      # spot the tampered pack (CTF-style)
```

`demo-pack` creates synthetic receipts, builds two signed Proof Packs with
different claims, and verifies them. One passes. One fails on purpose --
demonstrating that **integrity PASS + claim FAIL = honest failure**.

`demo-incident` runs a two-act scenario: Act 1 uses gpt-4 with a guardian
(PASS/PASS). Act 2 swaps to gpt-3.5-turbo and drops the guardian
(PASS/FAIL). Same tool, different evidence, different verdict.

`demo-challenge` generates a good pack and a tampered pack side by side.
Run `assay verify-pack` on each -- your machine decides which is authentic.

## Core Concepts

### Receipts

A receipt is a single evidence event: "this action happened."

```python
from assay import emit_receipt

emit_receipt("model_call", {"model": "claude-sonnet-4-20250514", "tokens": 1200})
emit_receipt("guardian_verdict", {"verdict": "allow", "tool": "web_search"})
```

Receipts are not logs. Logs are mutable narrative under your control.
Receipts are structured evidence bytes designed to be portable inputs
to independent verification.

### Proof Packs

A Proof Pack is a 5-file signed evidence bundle:

| File | Purpose |
|------|---------|
| `receipt_pack.jsonl` | All receipts from the run (append-only) |
| `pack_manifest.json` | SHA-256 hashes of all files + Ed25519 signature |
| `pack_signature.sig` | Detached signature for offline verification |
| `verify_report.json` | Machine-readable verification verdict |
| `verify_transcript.md` | Human-readable summary |

You can hand this folder to someone who doesn't trust you or your
infrastructure. They run `assay verify-pack` and get a verdict.

### Integrity vs Claims

This is the core architectural split.

**Integrity** answers: "Were these bytes tampered with after creation?"
- Checks file hashes, Ed25519 signature, required files, schema

**Claims** answer: "Does this evidence satisfy the declared behavioral checks?"
- Checks receipt types, counts, field values, ordering

These are deliberately independent. Four outcomes:

| Integrity | Claims | Exit Code | Meaning |
|-----------|--------|-----------|---------|
| PASS | PASS | 0 | Evidence checks out, behavior meets standards |
| PASS | FAIL | 1 | **Honest failure**: authentic evidence proving the run violated standards |
| FAIL | -- | 2 | Evidence has been tampered with |
| PASS | SKIPPED | 0 | Evidence is authentic, no behavioral checks declared |

**Honest failure** (exit 1) is the most important outcome. It proves the
system is reporting truthfully even when the news is bad. That's the
difference between compliance theater and actual accountability.

### Lockfile

The lockfile is a machine-readable governance contract. It pins:

- Which claims exist and their exact semantics (hashes)
- Required checks and exit behavior
- Allowed signers and minimum versions
- Fail-closed rules

Without a lockfile, you can quietly weaken your verification criteria
between runs and nobody would notice. With a lockfile, drift is detectable.
Lock mismatch exits with code 2.

## The Golden Path

### 0. Guided onboarding (recommended)

```bash
assay onboard .
```

### 1. Scan for uninstrumented LLM calls

```bash
assay scan .
```

Finds every LLM call site and checks for evidence emission. Confidence levels:
- **high** -- direct SDK calls (`chat.completions.create`, `messages.create`)
- **medium** -- framework wrappers (LangChain `.invoke()`, LiteLLM)
- **low** -- heuristic name matches (`call_llm`, `query_model`)

Each finding includes a fix suggestion and the next command to run.

### 2. Instrument your code (one line)

```python
# OpenAI
from assay.integrations.openai import patch; patch()

# Anthropic
from assay.integrations.anthropic import patch; patch()

# LangChain
from assay.integrations.langchain import patch; patch()

# Manual (any framework)
from assay import emit_receipt
emit_receipt("model_call", {"provider": "...", "model_id": "..."})
```

### 3. Run through Assay

```bash
assay run -c receipt_completeness -c guardian_enforcement -- python my_agent.py
```

This runs your command, collects emitted receipts, builds a signed Proof
Pack, and prints the verdict. Use `--allow-empty` if your command doesn't
emit receipts yet.

### 4. Verify the pack

```bash
assay verify-pack ./proof_pack_*/
```

### 5. Read the explanation

```bash
assay explain ./proof_pack_*/
```

Plain-English summary: what happened, integrity status, claim results,
what the pack proves, and what it does NOT prove.

### 6. Lock your verification contract

```bash
assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
assay lock check assay.lock
```

### 7. Gate in CI

```bash
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
```

Exit code 0 = pass the build. Exit code 1 = fail the build (honest
failure). Exit code 2 = fail the build (tampering or lock drift).

## Preflight Check

```bash
assay doctor                            # local dev (default)
assay doctor --profile ci               # CI environment
assay doctor --profile ledger --strict   # prod: treat warnings as failures
```

Doctor checks install, keys, run cards, lockfile, and pack integrity.
It prints the single next command to become "green." Use `--fix` to
auto-generate missing keys and lockfiles.

## What This Does NOT Prove

Assay produces **self-attested evidence**. Integrity verification proves
evidence hasn't been tampered with *after creation*. It does not prove
evidence was honestly created in the first place. Specifically:

- **Completeness**: Assay verifies receipts that exist. It cannot prove
  receipts that should exist but were never emitted.
- **Freshness**: A valid pack can be replayed. No challenge-nonce or
  freshness window is enforced.
- **Trust root**: Embedded pubkeys allow self-signed truth. No external
  trust anchor exists yet.
- **Timestamp honesty**: Timestamps come from the local clock. Without a
  time authority, they can be fabricated.
- **Confidentiality**: Receipt hashes of low-entropy fields can be
  brute-forced.

These are stated limitations, not hidden ones. Over-claiming destroys
trust faster than bugs.

## Command Reference

| Command | Purpose |
|---------|---------|
| `assay demo-pack` | Generate demo packs (no config needed) |
| `assay demo-incident` | Two-act scenario: passing run vs failing run |
| `assay demo-challenge` | CTF-style good + tampered pack pair |
| `assay onboard` | Guided setup: doctor -> scan -> first run plan |
| `assay scan` | Find uninstrumented LLM call sites |
| `assay run` | Wrap command, collect receipts, build signed pack |
| `assay verify-pack` | Verify a Proof Pack (integrity + claims) |
| `assay explain` | Plain-English summary of a proof pack |
| `assay ci init github` | Generate a GitHub Actions workflow |
| `assay lock write` | Freeze verification contract to lockfile |
| `assay lock check` | Validate lockfile against current card definitions |
| `assay doctor` | Preflight check: is Assay ready here? |

## Built-in RunCards

| Card ID | What it checks |
|---------|----------------|
| `guardian_enforcement` | At least one `guardian_verdict` receipt exists |
| `receipt_completeness` | At least 1 receipt + at least 1 `model_call` |
| `no_breakglass` | No breakglass override receipts |
| `timestamp_ordering` | Timestamps are monotonically non-decreasing |
| `schema_consistency` | All `model_call` receipts use schema_version 3.0 |

## Glossary

| Term | Meaning |
|------|---------|
| **receipt** | Structured evidence event (model call, guardian verdict, etc.) |
| **Proof Pack** | 5-file signed evidence bundle, independently verifiable |
| **integrity** | Structural truth: hashes match, signature verifies, files present |
| **claim check** | Semantic truth: behavioral claims pass or fail against evidence |
| **honest failure** | Integrity PASS + claims FAIL: authentic evidence proving standards were violated |
| **lockfile** | Machine-readable governance contract pinning verification semantics |
| **RunCard** | Named collection of claims (e.g., `guardian_enforcement`) |
| **pack_root_sha256** | SHA-256 of the attestation -- the immutable pack identifier |
| **signer_id** | Ed25519 key identity used to sign the pack manifest |

## Read Next

- [Repo Map](REPO_MAP.md) -- what lives where across the Assay ecosystem
- [Pilot Program](PILOT_PROGRAM.md) -- early adopter program details
