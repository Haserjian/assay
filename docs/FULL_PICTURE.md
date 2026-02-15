# Assay: Full Picture

Architecture, trust model, repo boundaries, and release history.
For the adoption path, see [README](../README.md). For compliance teams,
see [for-compliance.md](for-compliance.md).

## What problem Assay solves

Companies ship AI agents that call LLM APIs to make decisions, generate
content, and take actions. When an auditor asks "prove your AI used the
model you claimed, ran the safety check you promised, and didn't exceed
your cost budget," the answer today is "trust our server logs."

That's not evidence. That's a claim.

Assay produces **tamper-evident audit trails** -- cryptographically signed
bundles of receipts that a third party can verify offline, on their own
machine, without trusting you. Edit one byte and verification fails. Skip
a call site and the completeness contract catches it.

## The four-layer architecture

### Layer 1: Receipt emission

Every LLM API call (OpenAI, Anthropic, LangChain) emits a signed receipt --
a JSON record with the model used, token counts, latency, timestamps, and a
hash chain linking it to the previous receipt. Two lines of code:

```python
from assay.integrations.openai import patch; patch()
```

Or `assay patch .` does it automatically.

### Layer 2: Evidence Pack

`assay run` wraps your command, collects all receipts emitted during
execution, and bundles them into a 5-file evidence pack:

| File | Purpose |
|------|---------|
| `receipt_pack.jsonl` | All receipts, ordered |
| `pack_manifest.json` | Metadata, hashes, attestation, signer public key fingerprint |
| `pack_signature.sig` | Ed25519 signature over the manifest |
| `verify_report.json` | Machine-readable verification result |
| `verify_transcript.md` | Human-readable verification narrative |

The manifest contains SHA-256 hashes of every file. The signature covers
the manifest. Change any byte in any receipt, the hash changes, the
manifest doesn't match, verification fails.

> **Naming note:** The code uses "Proof Pack" internally. External
> documentation prefers "evidence pack" because evidence is what it
> produces -- not proof of external truth.

### Layer 3: Verification

`assay verify-pack` checks two independent things:

- **Integrity**: "Were these bytes tampered with?" (hashes, signatures, required files)
- **Claims**: "Does this evidence satisfy declared governance checks?" (receipt types, counts, field values)

| Exit | Integrity | Claims | Meaning |
|------|-----------|--------|---------|
| 0 | PASS | PASS | Evidence checks out |
| 1 | PASS | FAIL | Honest failure -- authentic evidence of a violation |
| 2 | FAIL | -- | Tampered evidence |
| 3 | -- | -- | Bad input |

Exit 1 is **audit gold**: authentic evidence that a control failed, with
no ability to edit history. Auditors value "controls can fail, but failure
is detectable and retained."

### Layer 4: CI gate

Three commands in your GitHub Actions workflow:

```bash
assay run -c receipt_completeness -- python app.py
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
assay diff ./baseline/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0
```

The lockfile catches config drift. Verify catches tampering. Diff catches
regressions and budget overruns. Every PR gets an evidence check.

## The Evidence Compiler

Assay is an **evidence compiler** for AI execution:

| Concept | Build System | Assay |
|---------|-------------|-------|
| Source | `.c` / `.ts` files | Receipts (one per LLM call) |
| Artifact | Binary / bundle | Evidence pack (5 files, 1 signature) |
| Tests | Unit / integration tests | Verification (integrity + claims) |
| Lock | `package-lock.json` | `assay.lock` |
| Gate | CI deploy check | CI evidence gate |

Developers already understand this mental model.

## Trust tiers

| Tier | What | Status |
|------|------|--------|
| T0 | Self-signed (single machine, single key) | Shipped (v1.0+) |
| T1 | Time-anchored (RFC 3161 external timestamps) | Spec written |
| T2 | Independent witness ([assay-ledger](https://github.com/Haserjian/assay-ledger), Sigstore/Rekor) | Ledger shipped, Sigstore planned |
| T3 | Runtime attestation (hardware-backed) | Future |

T0 proves internal consistency. Each tier adds an independent constraint
that makes fabrication progressively harder.

### Signer identity and key distribution

The evidence pack manifest includes the signer's public key fingerprint.
For third-party verification:

- **T0 (self-signed):** The verifier gets the public key out of band (e.g.,
  committed to the repo, shared via secure channel). Verification proves
  "this pack was signed by the holder of this key."
- **T1+ (anchored):** Key identity is bound to an organization or workflow
  via a transparency log or certificate chain.

Current key commands: `assay key list`, `assay key rotate`, `assay key set-active`.

## Completeness contract

The completeness contract bridges the scanner (static analysis) and the
receipt store (runtime evidence):

1. `assay scan --emit-contract` enumerates call sites with stable IDs
2. `assay run` collects receipts, each tagged with a `callsite_id`
3. `assay verify-pack --coverage-contract` checks coverage ratio

Completeness is enforced **relative to the enumerated call sites detected
by the scanner and/or declared by policy**. Undetected call sites are a
known residual risk, reduced via multi-detector scanning and CI gating.

LangChain and LiteLLM call sites are excluded from the contract denominator
by default because they use callbacks, not direct SDK calls, and cannot
propagate stable `callsite_id` values.

## Repository boundaries

### Public (trust chain)

| Repo | What | URL |
|------|------|-----|
| assay | Core CLI, SDK, scanner, patcher, evidence packs, verification | [github.com/Haserjian/assay](https://github.com/Haserjian/assay) |
| assay-verify-action | GitHub Action: runs verify-pack in CI, posts PR comments | [github.com/Haserjian/assay-verify-action](https://github.com/Haserjian/assay-verify-action) |
| assay-ledger | Public transparency ledger: independent witness (Ed25519 + JCS) | [github.com/Haserjian/assay-ledger](https://github.com/Haserjian/assay-ledger) |

### Private (operations)

| Repo | What |
|------|------|
| ccio | Internal monorepo: agent engine, memory graph, governance |
| Loom | Agent orchestration framework |
| puppetlabs (Quintet) | Policy scientist: analyzes agent behavior, recommends lever changes |

Rule: **public trust chain, private operations.** Assay audits agents;
it doesn't become one.

## Source architecture

```
src/assay/
  store.py           Thread-safe (RLock) + process-safe (O_APPEND + fcntl.flock) receipt storage
  keystore.py        Ed25519 key management (AssayKeyStore, rotation, active signer)
  integrity.py       Hash verification, signature checking
  proof_pack.py      5-file evidence pack builder
  claim_verifier.py  Claim evaluation engine
  run_cards.py       6 built-in verification cards (incl coverage_contract)
  schema.py          Version registry (CURRENT_VERSION, is_compatible, validate_receipt_fields)
  lockfile.py        Fail-closed verification contract (PEP 440 version checks)
  scanner.py         AST-based LLM call site detection (OpenAI, Anthropic, LangChain)
  patcher.py         Auto-insert SDK patches (backup/undo, # assay:patched marker)
  coverage.py        Completeness contract (scan-to-receipt callsite_id bridge)
  diff.py            Pack comparison, --against-previous, --why (causal chain traversal)
  explain.py         Plain-English pack summaries (text/md/json)
  analyze.py         Cost/latency/error analytics
  doctor.py          15 preflight checks across 4 profiles
  mcp_proxy.py       Transparent stdio proxy, dual-format reader (NDJSON + Content-Length)
  commands.py        CLI (Typer-based, 30 commands)
  integrations/      OpenAI, Anthropic, LangChain monkey-patching
  _receipts/         Vendored: JCS canonicalization, Merkle tree, domain separation
  reporting/
    evidence_gap.py  Self-contained HTML gap report from scan
    diff_gate.py     HTML/JSON diff report for CI artifacts
```

## Release history

| Version | What |
|---------|------|
| 1.0.0 | Initial release (core receipt + pack + verify) |
| 1.1.0 | Scanner, doctor |
| 1.2.0 | Explain, demo-incident, demo-challenge |
| 1.2.2 | Completeness contract, coverage.py |
| 1.3.0 | Quickstart, patch, CI doctor, HTML reports, landing page |
| 1.3.3 | Store prompts/responses fix, version sync |
| 1.4.0 | Diff with gate thresholds, Decision Escrow docs |
| 1.4.2 | Store hardening, quickstart guard, scan-first diagnostic |
| 1.5.0 | Schema registry, parent_receipt_id, diff --against-previous/--why |
| 1.5.1 | Diff --report, MCP proxy v0, repo charters, smoke script |
| 1.5.2 | Activation Engine: status, start ci/mcp, mcp policy init, template generators, QA harness |
| 1.5.3 | Bug fixes: model field compatibility, scan guidance, CLI tagline alignment |

940 tests. 30 commands. 3 public repos. Apache-2.0.
