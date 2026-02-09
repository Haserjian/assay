# Assay Deep Dive

How Assay works, what it proves, and what it doesn't.

Audience: engineers implementing Assay, operators running CI gates,
security/compliance reviewers validating evidence, anyone deciding
whether to trust a Proof Pack.

---

## 1) What Assay Is

Assay is a verification layer for AI systems. It produces tamper-evident,
independently verifiable evidence bundles that prove what an AI system did.

It does two jobs on purpose:

- **Courthouse job**: prove structural integrity of evidence (signatures,
  hashes, required files)
- **Laboratory job**: test behavioral claims against that evidence
  (RunCards)

These are deliberately orthogonal. Integrity can pass while claims fail.
That's the honesty property -- and it's the central design invariant.

Assay is not a logging framework, an observability platform, or an agent
runtime. It is the evidence and verification spine you attach to an
existing system.

---

## 2) The Primitive Stack

Assay introduces a small number of new primitives. Everything else is
composition of these.

### 2.1 Receipt (the atomic evidence event)

A receipt is a single structured statement: "this action happened."

```json
{
  "receipt_id": "r_abc123",
  "type": "model_call",
  "timestamp": "2026-02-08T10:00:00Z",
  "schema_version": "3.0",
  "provider": "openai",
  "model_id": "gpt-4",
  "input_tokens": 500,
  "output_tokens": 200,
  "total_tokens": 700,
  "prompt_hash": "sha256:...",
  "response_hash": "sha256:..."
}
```

Receipts are not logs. Logs are mutable narrative under infrastructure you
control. A receipt is evidence bytes designed to be a portable input to
independent verification.

Key properties:
- Content-addressed (hashes of inputs/outputs, not the raw content)
- Canonicalizable (JCS for cross-language determinism)
- Typed (model_call, guardian_verdict, capability_use, etc.)
- Self-describing (schema_version, auto-populated receipt_id and timestamp)

### 2.2 Proof Pack (the portable evidence bundle)

A Proof Pack is a minimal kernel that makes receipts transportable and
tamper-evident. Five files:

| File | Purpose |
|------|---------|
| `receipt_pack.jsonl` | All receipts from the run (append-only) |
| `pack_manifest.json` | SHA-256 hashes of all files, Ed25519 signature, attestation metadata |
| `pack_signature.sig` | Detached signature for offline verification |
| `verify_report.json` | Machine-readable verification verdict |
| `verify_transcript.md` | Human-readable summary |

Five is the right number. Fewer files and you're stuffing too much into
each one. More files and the pack becomes unwieldy to transport. Five is
where a human can open each file, understand what it does, and mentally
model the whole pack.

Key property: you can hand this folder to someone who does not trust you
or your infrastructure, and they can verify integrity independently.

### 2.3 Integrity vs Claims (the honest failure split)

**Integrity** answers: "Were these bytes tampered with after creation?"
- Validates Ed25519 signature over canonical manifest
- Recomputes SHA-256 hashes of all pack files
- Checks required files are present
- Checks schema version compatibility

**Claims** answer: "Does this evidence satisfy the declared behavioral checks?"
- Executes RunCard claim specifications against receipt data
- Each claim is a simple predicate (receipt type present, count >= N,
  field value matches, timestamps monotonic)

Four outcomes:

| Integrity | Claims | Exit Code | Meaning |
|-----------|--------|-----------|---------|
| PASS | PASS | 0 | Evidence authentic, behavior meets standards |
| PASS | FAIL | 1 | **Honest failure**: authentic evidence proving standards violated |
| FAIL | -- | 2 | Evidence tampered with or structurally invalid |
| PASS | SKIPPED | 0 | Evidence authentic, no behavioral checks declared |

The honest failure (exit 1) is the most valuable outcome for trust.
It proves the system reports truthfully even when the news is bad.
Every current accountability system -- corporate compliance, government
auditing, academic peer review -- incentivizes hiding failures. Assay
inverts this: a claim failure with integrity pass is *more trustworthy*
than a claim pass, because it proves honest reporting.

Orthogonality rule: claim results never upgrade integrity. Integrity
failure is always authoritative.

### 2.4 Lockfile (the governance contract)

The lockfile pins verification semantics so they can't drift silently:

- Which RunCards are required
- Their exact claim definitions (content-addressed hashes)
- Pack format version
- Minimum Assay version
- Allowed signer identities
- Exit contract behavior

```bash
assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
```

Without a lockfile, you can quietly weaken your verification criteria
between runs. With a lockfile, any drift triggers exit code 2.

Key property: the lockfile turns "we comply" into "we comply under this
pinned contract, and drift is detectable." This is a machine-readable
governance contract.

Lockfile behavior is fail-closed:
- Missing required fields in a lockfile = rejection (not skip)
- Invalid signer mode = rejection
- Version below minimum = rejection
- Hash mismatch = rejection

### 2.5 Scanner (the integration wedge)

The scanner finds uninstrumented LLM call sites using AST analysis:

- **High confidence**: direct SDK calls (`chat.completions.create`,
  `messages.create`)
- **Medium confidence**: framework wrappers (LangChain `.invoke()`,
  LiteLLM), gated behind framework import evidence
- **Low confidence**: heuristic function name matches

The scanner is a wedge, not a source of truth. Its job is to surface
where the evidence gap is, create urgency, and propose the smallest fix.
The actual product is evidence + verification, not scanning.

---

## 3) Runtime Flow

### 3.1 How `assay run` works

```
assay run -c receipt_completeness -- python my_agent.py
```

1. Generates a trace ID, sets `ASSAY_TRACE_ID` in subprocess environment
2. Runs the command
3. Any `emit_receipt()` call in the subprocess writes to
   `~/.loom/assay/<date>/<trace>.jsonl` (keyed by the env var)
4. After exit, reads all receipts for the trace
5. Builds pack files (receipt_pack.jsonl, verify_report, transcript)
6. Computes SHA-256 hashes into manifest
7. Signs manifest with Ed25519 key (from keystore)
8. Writes detached signature
9. Runs verification (integrity + claims) on the completed pack
10. Prints verdict and exits with appropriate code

### 3.2 How `assay verify-pack` works

```
assay verify-pack ./proof_pack_abc/ --lock assay.lock --require-claim-pass
```

1. If `--lock`: loads lockfile, validates all required fields, checks
   claim hashes and composite hash against current card definitions.
   Any mismatch = exit 2.
2. Integrity check: re-hash all files, verify Ed25519 signature over
   canonical manifest, check required files present.
3. If integrity fails: exit 2.
4. Claim check: execute each RunCard's claims against receipt data.
5. If `--require-claim-pass` and any claim fails: exit 1.
6. Otherwise: exit 0.

Order matters: lockfile validation happens before integrity check.
Invalid governance contracts are rejected at entry.

### 3.3 Signing and keys

- Ed25519 key pairs stored in `~/.assay/keys/`
- `assay doctor --fix` auto-generates a key if none exists
- Signing uses JCS (JSON Canonicalization Scheme, RFC 8785) for
  deterministic byte representation
- JCS ensures cross-language verification compatibility (a Go or
  JavaScript verifier produces identical canonical bytes)

---

## 4) Implementation Details

### 4.1 Source Layout

```
src/assay/
  cli.py              # Typer entrypoint
  commands.py         # All CLI commands
  store.py            # Receipt store (emit_receipt, file-backed)
  keystore.py         # Ed25519 key management
  integrity.py        # Integrity verifier
  proof_pack.py       # Pack builder
  claim_verifier.py   # Claim execution engine
  run_cards.py        # Built-in RunCard definitions
  lockfile.py         # Lockfile load/write/check/validate
  scanner.py          # AST-based LLM call site scanner
  doctor.py           # Preflight check engine (13 checks, 4 profiles)
  explain.py          # Plain-English pack explanation
  guardian.py         # Guardian verdict types
  health.py           # Health check types
  evidence_pack.py    # Evidence pack assembly
  _receipts/          # Vendored: canonicalize, jcs, merkle, compat, domains
  integrations/
    openai.py         # OpenAI SDK monkey-patch
    anthropic.py      # Anthropic SDK monkey-patch
    langchain.py      # LangChain callback handler
  schemas/
    *.json            # JSON Schema files for validation
```

### 4.2 Test Coverage

407 tests across 16 test files:
- Lockfile: 25 tests (write, validate, check, fail-closed load, fail-closed validate, semantic check, conformance)
- Scanner: 72 tests (high/medium/low confidence, guarded patterns, framework import gating)
- Doctor: 40 tests (13 checks, 4 profiles)
- Integrity + claims + pack building: remaining tests

### 4.3 Conformance Corpus

Deterministic test fixtures with known expected outcomes:

```bash
python conformance/generate_corpus.py
python conformance/run_corpus.py
```

6 packs: 3 good (exit 0), 1 claim-fail (exit 1), 2 tampered (exit 2).
Generation is seeded (SHA-256 derived IDs, fixed timestamps) so
regeneration produces identical bytes. This is the verifier ABI contract.

### 4.4 CI

`.github/workflows/ci.yml` runs:
- Full test suite
- Wheel smoke test (build + install + verify)
- Conformance corpus verification

`.github/workflows/assay-verify.yml` is a reusable workflow for
drop-in cross-repo pack verification.

---

## 5) Trust Model

### 5.1 What Assay currently provides

- Tamper-evident bundles (Ed25519 + SHA-256)
- Deterministic verifier behavior (same inputs = same verdict)
- Explicit integrity/claims split
- Fail-closed lockfile enforcement
- JCS canonicalization for cross-language compatibility
- Portable, offline-verifiable evidence

### 5.2 What Assay does NOT currently provide

- **Completeness guarantee**: only emitted receipts are in the pack.
  Receipts that should exist but weren't emitted are invisible.
- **Source attestation**: integrity proves "not tampered after creation,"
  not "honestly created." A compromised runtime can emit false receipts.
- **External time anchoring**: timestamps are local clock. No RFC 3161
  time authority.
- **Third-party witnessing**: packs are self-attested. No independent
  witness protocol yet.
- **Confidentiality**: receipt hashes of low-entropy fields can be
  brute-forced. No keyed commitments.

### 5.3 Design philosophy

Over-claiming destroys trust faster than bugs. Every limitation above
is stated explicitly in pack explanations (`assay explain`) and
documentation. The system earns trust by being honest about what it
can and cannot prove -- which is itself an instance of the honest
failure principle.

---

## 6) Architecture Invariants

These are non-negotiable and should survive any future changes:

1. **Never merge integrity and claims into one verdict.** The
   orthogonality is what enables honest failure.
2. **Verifier semantics stay deterministic and strict.** Same pack +
   same cards = same verdict. Always.
3. **Docs state what is and is not proven.** Over-claiming is a bug.
4. **The pack is the product, not the platform.** Independence from
   infrastructure is the value proposition.
5. **Fail closed on governance drift.** Lock mismatch = exit 2, not
   a warning.
6. **JCS canonicalization everywhere.** Cross-language verification
   is not optional.

---

## 7) Ecosystem

| Repo | Purpose |
|------|---------|
| [assay](https://github.com/Haserjian/assay) | Core CLI + SDK (this repo) |
| [assay-verify-action](https://github.com/Haserjian/assay-verify-action) | GitHub Action for CI verification |
| [assay-ledger](https://github.com/Haserjian/assay-ledger) | Public transparency ledger (GitHub Pages) |

Boundary rule: the trust chain (signing, verification, evidence format)
is open source. Operations (key management, deployment) are private.

---

## 8) Current State (v1.2.0)

- 407 tests, all passing
- Published on PyPI: `pip install assay-ai`
- 10 CLI commands (demo-pack, demo-incident, demo-challenge, scan, run,
  verify-pack, explain, lock write, lock check, doctor)
- 5 built-in RunCards
- 6-pack conformance corpus (deterministic, seeded)
- Lockfile contract with fail-closed semantics
- AST-based scanner with 3 confidence levels
- Ed25519 signing with JCS canonicalization
- GitHub Action for CI gating
- Public transparency ledger
