# Compiled Packet Architecture

## Executive Summary

A compiled packet is a reviewer-ready trust artifact: a signed, self-contained bundle
that lets a third party verify what an AI system did, what claims are being made about
it, and whether the packet is admissible under a declared policy for a trust decision —
offline.

This matters because evidence that only the producer can interpret is a log. Evidence
that a third party can verify offline and use for a trust decision is a product.

A compiled packet separates three independent layers:

- **Evidence Layer**: what artifacts are signed, packaged, and bound to a subject.
- **Truth Layer**: what the verifier can conclude deterministically about integrity and evidence coverage.
- **Decision Layer**: what policy decides to do with those verified facts.

This separation is the core architectural invariant. The verifier answers facts. The
gate answers policy. Reviewers can inspect truth without trusting the producer's
runtime, dashboard, or API.

### Concrete Example

```
subject:      artifact  model://fraud-classifier-v3
claim:        "evaluation dataset provenance documented"
claim status: SUPPORTED → bound to pack root sha256:a1b2c3...
claim:        "human review required before production deployment"
claim status: PARTIAL   → evidence exists but incomplete

integrity_verdict:     INTACT
completeness_verdict:  PARTIAL

admissible under merge policy:       false  (completeness threshold not met)
admissible under human review policy: true   (INTACT + bundled + subject bound)
```

The same packet produces different admissibility results under different declared
policies. That is intentional. The verifier establishes what is true; policy decides
what to do with it.

---

## Three-Layer Model

```
┌─────────────────────────────────────────────┐
│  Decision Layer                             │
│  admissibility, gates, reviewer policy      │
├─────────────────────────────────────────────┤
│  Truth Layer                                │
│  integrity_verdict × completeness_verdict   │
├─────────────────────────────────────────────┤
│  Evidence Layer                             │
│  packs, signatures, claim binding, subject  │
└─────────────────────────────────────────────┘
```

Each layer is independently evolvable:

- Evidence can be hardened without changing truth semantics.
- Truth can be interrogated without running the gate.
- Decision policy can change without changing the verifier.

That independence is what makes the packet reusable across CI, review, audit,
procurement, and external trust workflows.

---

## Evidence Layer

The Evidence Layer packages everything a third party needs to verify the packet
without access to the producer's systems.

### Proof Packs

Proof packs are the trust root. Each pack is a signed bundle of operational claims:
tool invocations, outputs, timing, chain-of-custody metadata. The pack root SHA256 is
the stable identifier. Packs are immutable once signed.

### Claim Binding

Claim bindings link compliance claims to pack roots. The system does not infer that a
claim is supported. An operator or system author explicitly binds each claim — using a
status of `SUPPORTED`, `PARTIAL`, `UNSUPPORTED`, `OUT_OF_SCOPE`, or `NON_CLAIM` — to
a specific proof pack root. That signed binding makes responsibility explicit.

| Status | Meaning |
|--------|---------|
| `SUPPORTED` | Pack root provides direct evidence for this claim |
| `PARTIAL` | Evidence exists but does not fully cover the claim |
| `UNSUPPORTED` | Claim is not covered by available evidence |
| `OUT_OF_SCOPE` | Claim is intentionally excluded from this packet |
| `NON_CLAIM` | Not a verifiable claim (policy statement, intent, description) |

Claim binding is the primitive that turns evidence blobs into accountable assertions.
Without it, you have receipts. With it, you have a signed assertion, a named claimant
or system actor, a bound proof root, and a reviewable responsibility boundary.

### Subject Binding

Every compiled packet declares what it is about:

```json
{
  "subject_type": "artifact",
  "subject_id":   "repo:assay@v1.19.0",
  "subject_digest": "sha256:<64 lowercase hex>"
}
```

The `subject_digest` is included in the packet root computation and signed. Changing
the subject after signing invalidates the signature, which the verifier reports as
`TAMPERED`. This is jurisdiction: the packet asserts scope, and that assertion is
cryptographically enforced.

Supported `subject_type` values: `artifact`, `run`, `decision`.
Digest format: `sha256:<64 lowercase hex>` only. SHA-1 commit IDs and bare hex without
a prefix are rejected.

### Bundle Mode

All proof packs are copied inline into the packet directory at compile time. A
non-bundled packet cannot be verified offline. It is therefore not an admissible
reviewer-ready artifact, regardless of its integrity verdict. This is structural, not
optional.

---

## Truth Layer

The verifier produces a two-axis verdict. The axes are independent.

### Integrity Axis

Answers: is the packet structurally sound and untampered?

| Verdict | Meaning |
|---------|---------|
| `INTACT` | Signatures valid; all pack roots match their references |
| `DEGRADED` | Structural damage: missing packs, reference hash mismatch |
| `TAMPERED` | Signature verification failed; content modified after signing |
| `INVALID` | Packet cannot be parsed or is structurally malformed |

`DEGRADED` and `TAMPERED` require different responses. `DEGRADED` means something is
broken or missing. `TAMPERED` means cryptographic proof of modification after signing.

### Completeness Axis

Answers: are the claims covered by evidence?

| Verdict | Meaning |
|---------|---------|
| `COMPLETE` | All questionnaire items have `SUPPORTED` bindings |
| `PARTIAL` | Some items are unsupported or partially supported |
| `INCOMPLETE` | Major coverage gaps across the questionnaire |

### Top-Level Verdict

Derived deterministically from the two axes:

| Integrity | Completeness | Verdict |
|-----------|-------------|---------|
| `INTACT` | `COMPLETE` | `PASS` |
| `INTACT` | `PARTIAL` | `PARTIAL` |
| `INTACT` | `INCOMPLETE` | `PARTIAL` |
| `DEGRADED` | any | `DEGRADED` |
| `TAMPERED` | any | `TAMPERED` |
| `INVALID` | any | `INVALID` |

`PARTIAL` is a first-class informative state, not a failure. It tells reviewers exactly
where gaps exist. Binary pass/fail systems incentivize overclaiming to get to green. A
first-class `PARTIAL` preserves signal and reduces representational pressure under
compliance deadlines.

### CLI Exit Code Contract

```
exit 0 = INTACT   (verification succeeded structurally; PARTIAL coverage is honest)
exit 1 = TAMPERED / DEGRADED / INVALID   (structural problem)
```

The exit code answers: *did verification succeed?*

It does not answer: *should this gate a decision?* That is the Decision Layer's
question. Admissibility is available in `--json` output for callers that need it.

---

## Decision Layer

### Admissibility

Admissibility is a policy judgment, not a cryptographic fact. A packet is admissible
when:

1. `integrity_verdict = INTACT`
2. Subject binding is present and correctly formatted
3. Bundle mode is true (offline-verifiable)

Inadmissible packets produce structured reason codes rather than a naked boolean:

| Code | Meaning |
|------|---------|
| `NOT_SELF_CONTAINED` | Packs not bundled; cannot verify offline |
| `INTEGRITY_FAILURE` | Integrity verdict is not `INTACT` |
| `SUBJECT_BINDING_MISSING` | Subject block absent or malformed |

Admissibility is available in the `--json` output as `admissible: true/false` plus
`admissibility_reasons: [...]`.

### The Gate

`assay-gate.sh` is a shell enforcement membrane:

1. Invokes `assay packet verify --json` and captures stdout (JSON) and stderr
   (diagnostics) into separate streams via a tempfile.
2. Parses JSON from stdout.
3. Passes only if `integrity_verdict = INTACT` AND `admissible = true`.
4. On empty stdout or unparseable JSON, displays captured stderr so the operator sees
   verifier crash traces rather than a silent failure message.

The gate is intentionally simple. All logic lives in the Python verifier. The shell
script enforces; it does not interpret.

---

## The Verify / Gate Boundary

This boundary is the central contract of the system.

| Layer | Command | Answers |
|-------|---------|---------|
| Truth | `assay packet verify` | What is true about this packet? |
| Decision | `assay-gate.sh` | Should this packet gate an action? |

Collapsing these — for example, having `verify` exit based on admissibility rather than
integrity — creates category confusion: a tool named "verify" would then answer a policy
question, and downstream callers would inherit hidden policy. CI scripts, batch
validators, review tooling, and future TS/browser wrappers would all silently carry
policy assumptions they did not opt into.

The correct contract:

- `verify` exits on integrity. Admissibility is available in JSON for callers that want
  it.
- The gate reads JSON and enforces its own policy check, independently.
- stderr is preserved and displayed on failure so diagnostics survive verifier crashes.

---

## Non-Goals

A compiled packet does not by itself guarantee:

- That the underlying operational evidence is true in the world (the verifier checks
  cryptographic linkage, not real-world correctness).
- That the policy is correct for the use case (policy is the caller's responsibility).
- That the packet is fresh enough for every use case (freshness enforcement is deferred;
  see Known Gaps).
- That a claim should be trusted without reviewer judgment (the packet supports a
  decision; it does not make one).

---

## What the Verifier Guarantees

- The packet manifest has not been modified since signing.
- All bundled pack roots match their signed references.
- The subject binding digest is correctly formatted.
- The claim bindings hash matches the signed value in the manifest.
- The completeness verdict accurately counts questionnaire coverage against binding
  statuses.

## What the Verifier Does Not Guarantee

- **Freshness**: a six-month-old packet verifies identically to a fresh one.
- **Claim truthfulness**: the verifier checks that bindings are cryptographically
  linked to pack roots. It does not verify that the underlying operational claims are
  true.
- **Policy compliance**: admissibility is a gate-layer concern, not a verifier concern.
- **Per-subject-type digest semantics**: only `artifact` has defined digest conventions.
  Semantics for `run` and `decision` are deferred.

---

## Known Gaps

| Gap | Impact | Status |
|-----|--------|--------|
| Freshness enforcement | `INTACT` packets may be operationally stale | Deferred to first buyer signal |
| Policy engine | Admissibility logic is hardcoded; `policy_id: "default"` is a stub | Scaffolding only |
| Gate integration tests | Shell-level gate behavior has no test coverage | Deferred |
| TS verifier parity | `assay-verify-ts` covers packs; compiled packet semantics not yet implemented | Next chapter |
| Subject-type canonicalization | Only `artifact` has defined `subject_digest` rules | Deferred to real usage |

### The "Verified for When?" Problem

The most consequential open question is freshness. A compiled packet can be `INTACT`,
admissible, and six months stale. The manifest has a `freshness_policy` field. Nothing
enforces it. Until freshness is enforced, the system provides portable proof but not
time-bounded trust.

The natural model: packets carry a declared validity window, and gates reject packets
beyond that window. That is the next major contract question after policy pluggability.

---

## One-Sentence Version

A compiled packet turns evidence into a signed, portable trust object with three
independent judgments: a cryptographic integrity verdict, a completeness verdict over
claimed evidence, and an admissibility verdict under declared policy — each answerable
separately, each independently useful.
