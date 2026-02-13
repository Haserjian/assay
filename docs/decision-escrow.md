# Decision Escrow

> **Current trust tier: T0 (self-signed)** | Next: T1 (time-anchored)

**Agent actions don't settle until they're verified.**

Decision Escrow is the protocol model behind Assay. It treats every AI
agent action as a transaction that moves through four phases before it
settles. The evidence produced at each phase is cryptographically signed,
portable, and independently verifiable.

## The Problem

An AI agent calls a tool, sends an email, modifies a database, or makes
a trade. Did the action match its authorization? Was the output within
constraints? Was the evidence complete?

Today, the answer is "check the logs." But logs are mutable, incomplete,
and require trust in the operator. There is no settlement step. The
action just happens.

## The Protocol

```
1. PREFLIGHT PERMIT
   Agent requests action -> policy gate checks constraints -> issues permit
   Evidence: permit receipt (policy hash, constraints, expiry)

2. EXECUTION WITH EVIDENCE
   Agent executes action -> runtime emits receipts for every operation
   Evidence: execution receipts (inputs, outputs, model, timing, hashes)

3. SETTLEMENT
   Verifier checks: permit valid? execution within constraints? evidence complete?
   Evidence: verification report (integrity check, claim results, coverage)

4. REPUTATION UPDATE
   Outcome feeds back into agent trust scoring
   Evidence: reputation receipt (delta, new score, basis)
```

Each phase produces a signed receipt. The receipts bundle into a proof
pack. The pack verifies offline. No server access. No trust relationship.

## What Exists Today (Assay Core v1.3)

Assay Core implements phases 2 and 3 of Decision Escrow:

| Phase | Status | How |
|-------|--------|-----|
| Preflight Permit | Future | Requires Guardian policy gate (private stack) |
| **Execution with Evidence** | **Shipping** | `assay patch` + `assay run` emit signed receipts for every LLM call |
| **Settlement** | **Shipping** | `assay verify-pack` checks integrity + claims; `assay diff --gate` enforces budget thresholds |
| Reputation Update | Future | Requires trust scoring infrastructure |

The core loop a developer uses today:

```bash
assay quickstart              # see it work
assay patch                   # instrument your SDK calls
assay run -c receipt_completeness -- python my_app.py
assay verify-pack ./proof_pack_*/
assay diff ./baseline_pack/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0 --gate-strict
```

This produces a portable proof pack that any third party can verify
offline with `pip install assay-ai && assay verify-pack ./proof_pack_*/`.

## What Assay Proves

- **Integrity**: evidence was not altered after creation (Ed25519 + SHA-256)
- **Completeness**: all instrumented call sites emitted receipts (coverage contract)
- **Claim compliance**: declared governance checks passed or failed honestly
- **Budget compliance**: cost, latency, and error thresholds are within bounds (gates)

## What Assay Does Not Prove

- That the receipts describe reality (a dishonest operator can fabricate a run)
- That all call sites were instrumented (scanner detects gaps, but can't force instrumentation)
- That timestamps are accurate (without external anchoring)
- That the model behaved correctly (Assay proves what happened, not whether it was right)

## How to Strengthen Guarantees

| Trust Tier | What it adds | Status |
|------------|-------------|--------|
| **T0: Self-signed** | Ed25519 keypair, local signing | Shipping |
| T1: Time-anchored | RFC 3161 TSA or Sigstore timestamp | Planned |
| T2: Independent witness | Transparency log (assay-ledger) or Rekor | Planned |
| T3: Runtime attestation | Hardware-backed signing (TPM/SGX) | Future |

Each tier makes fabrication harder. At T0, the operator controls the key.
At T2, a third party independently witnesses the evidence. At T3, the
hardware itself attests to execution.

**The cost of cheating scales with the complexity of the lie.** Assay
doesn't make fraud impossible. It makes fraud expensive.

## For Procurement Teams

When evaluating an AI vendor:

1. Ask for a proof pack from a recent run.
2. Install Assay: `pip install assay-ai`
3. Verify: `assay verify-pack ./their_pack/`
4. Read the summary: `assay explain ./their_pack/`

If they can't produce a pack, they have no evidence infrastructure.
If the pack fails integrity, the evidence was altered.
If the pack fails claims, controls were violated -- but the failure
itself is authentic evidence.

## For Agent Platform Builders

If you build agent orchestration (MCP servers, tool-use frameworks,
multi-agent systems), Decision Escrow gives you a settlement layer:

- Every tool call produces a receipt
- Every agent action has verifiable evidence
- Every session bundles into a portable proof pack
- CI gates enforce budget and regression thresholds

The receipt is the atomic unit. The proof pack is the artifact.
The verifier is the judge. The gate is the enforcer.

## Relationship to Standards

| Standard | What Assay provides |
|----------|-------------------|
| SOC 2 (CC7.2) | Tamper-evident audit trail with integrity verification |
| ISO 42001 | Evidence artifacts for AI management system audits |
| EU AI Act (Articles 12, 19) | Logging and documentation for high-risk AI systems |
| NIST AI RMF | Evidence of governance controls and monitoring |
| Colorado AI Act | Documentation of algorithmic decision-making |

Assay is one building block toward compliance, not full compliance
by itself. It provides the evidence layer; policy and process are
the organization's responsibility.
