# Compiled Packet Semantics v1

**Date**: 2026-03-26
**Status**: NORMATIVE — implementations must agree on these meanings.
**Companion to**: COMPILED_PACKET_SPEC_V1.md

This document freezes the meanings of all enum values in the compiled packet system. Code, TS verifier, CLI output, and reviewer documentation must agree with these definitions.

---

## 1. Binding Status (disposition)

What is the operator's assertion about this questionnaire item?

| Status | Normative Meaning | Verifier Checks |
|--------|-------------------|-----------------|
| `SUPPORTED` | Operator asserts the claim is backed by evidence. `evidence_refs` MUST be non-empty. `evidence_basis` MUST be `MACHINE`, `HUMAN`, or `MIXED`. | Refs resolvable, basis consistent |
| `PARTIAL` | Operator asserts some evidence exists but coverage is incomplete. `missing_evidence` MUST be non-empty. | Refs resolvable, missing_evidence non-empty |
| `UNSUPPORTED` | Operator declares no evidence exists. Binding is present to make the gap visible. `evidence_refs` MUST be empty. `evidence_basis` MUST be `NONE`. | No refs, basis=NONE |
| `NON_CLAIM` | Operator acknowledges the question but declines to assert a claim. Example: "We do not offer SLA for this tier." `evidence_refs` MUST be empty. `evidence_basis` MUST be `NONE`. | No refs, basis=NONE |
| `OUT_OF_SCOPE` | Operator declares the question does not apply to the assessed system. Example: "We do not process PII." `evidence_refs` MUST be empty. `evidence_basis` MUST be `NONE`. | No refs, basis=NONE |

### Constraint Table

| Status | evidence_refs | evidence_basis | missing_evidence |
|--------|--------------|----------------|-----------------|
| SUPPORTED | non-empty | MACHINE, HUMAN, or MIXED | may be empty |
| PARTIAL | may be non-empty | MACHINE, HUMAN, MIXED, or NONE | must be non-empty |
| UNSUPPORTED | empty | NONE | may be non-empty |
| NON_CLAIM | empty | NONE | must be empty |
| OUT_OF_SCOPE | empty | NONE | must be empty |

---

## 2. Evidence Basis (what supports the binding)

Orthogonal to status. Describes the *kind* of evidence, not whether it is sufficient.

| Basis | Normative Meaning |
|-------|-------------------|
| `MACHINE` | All referenced evidence is machine-verifiable: receipts from proof packs that can be independently verified by a verifier without human judgment. |
| `HUMAN` | Evidence is human-attested. The operator or a named person asserts the claim. No machine-verifiable proof pack reference supports it. `evidence_refs` MAY be empty or MAY reference an attestation record in a pack. |
| `MIXED` | Some evidence is machine-verifiable, some is human-attested. `evidence_refs` MUST be non-empty (the machine part). The human part is described in `answer_summary` and `scope_notes`. |
| `NONE` | No evidence of any kind. Required for `UNSUPPORTED`, `NON_CLAIM`, and `OUT_OF_SCOPE`. |

---

## 3. Verifier Verdicts (two-axis)

The verifier produces two independent verdicts:

### 3.1 Integrity Verdict

"Can I trust the structural authenticity of this packet?"

| Verdict | Normative Meaning |
|---------|-------------------|
| `INTACT` | Packet signature is valid. All file hashes match manifest. Detached signature matches. Packet root invariant holds. All bundled packs pass their own verification. |
| `DEGRADED` | Packet signature and file hashes are valid, but one or more bundled packs are missing or fail their own verification. The packet envelope is trustworthy; the nested evidence is not fully available or intact. |
| `TAMPERED` | Packet-level integrity failure: signature invalid, file hash mismatch, root invariant broken, or questionnaire/binding content does not match manifest. |
| `INVALID` | Packet is structurally malformed and cannot be verified (missing manifest, unparseable JSON, missing required fields). |

**Key distinction**: `DEGRADED` means the *packet* is authentic but some *nested evidence* is absent or broken. `TAMPERED` means the *packet itself* has been modified after signing.

### 3.2 Completeness Verdict

"How well does this packet answer the questionnaire?"

| Verdict | Normative Meaning |
|---------|-------------------|
| `COMPLETE` | Every questionnaire item has a binding. No items are `UNSUPPORTED`. All evidence refs are resolvable. |
| `PARTIAL` | Every questionnaire item has a binding, but some are `UNSUPPORTED`, `PARTIAL`, or have unresolvable evidence refs. |
| `INCOMPLETE` | One or more questionnaire items have no binding at all. |

**Note**: `COMPLETE` does not mean "all claims are strong." A packet where every item is `OUT_OF_SCOPE` or `NON_CLAIM` is `COMPLETE` — it fully answers the questionnaire, just not affirmatively.

### 3.3 Top-Level Verdict (derived)

For CLI output and simple consumers, a single top-level verdict is derived:

```
if integrity == INVALID:    → INVALID
if integrity == TAMPERED:   → TAMPERED
if integrity == DEGRADED:   → DEGRADED
if completeness == COMPLETE: → PASS
else:                        → PARTIAL
```

The two-axis verdicts are always available in the machine-readable output. The top-level verdict is a convenience, not a replacement.

### 3.4 Full Cross-Product Truth Table

| Integrity | Completeness | Top-Level Verdict |
|-----------|-------------|-------------------|
| INVALID | COMPLETE | INVALID |
| INVALID | PARTIAL | INVALID |
| INVALID | INCOMPLETE | INVALID |
| TAMPERED | COMPLETE | TAMPERED |
| TAMPERED | PARTIAL | TAMPERED |
| TAMPERED | INCOMPLETE | TAMPERED |
| DEGRADED | COMPLETE | DEGRADED |
| DEGRADED | PARTIAL | DEGRADED |
| DEGRADED | INCOMPLETE | DEGRADED |
| INTACT | COMPLETE | PASS |
| INTACT | PARTIAL | PARTIAL |
| INTACT | INCOMPLETE | PARTIAL |

**Priority order**: INVALID > TAMPERED > DEGRADED > (completeness).

INTACT + INCOMPLETE produces PARTIAL (not INCOMPLETE) at the top level because "incomplete" is a completeness-only concept; the top-level enum does not expose it separately. Consumers who need the distinction MUST read `completeness_verdict`.

### 3.5 Completeness Is Conditional on Integrity

**Completeness describes questionnaire coverage, independent of authenticity.** It answers "if this packet were trustworthy, how fully does it respond?"

When `integrity_verdict` is TAMPERED or INVALID, `completeness_verdict` is still computed and reported but is **informational only**. A tampered packet with COMPLETE completeness does not mean "good to go" — it means the structure was parseable before trust was broken.

Reviewer-facing copy MUST present completeness as secondary when integrity is not INTACT:
- "Integrity describes authenticity and evidence-envelope health."
- "Completeness describes questionnaire coverage, independent of authenticity."
- When integrity is TAMPERED: "Completeness is reported but should not inform decisions — the packet is not trustworthy."

---

## 4. Error Codes

Stable meanings. Implementations MUST use these codes for these conditions.

| Code | Severity | Integrity Impact | Meaning | Remediation |
|------|----------|-----------------|---------|-------------|
| `E_PKT_SCHEMA` | FATAL | → INVALID | Manifest or kernel file is structurally malformed | Fix or regenerate packet |
| `E_PKT_TAMPER` | FATAL | → TAMPERED | File hash does not match manifest declaration | Packet has been modified after signing. Recompile from draft |
| `E_PKT_SIG_INVALID` | FATAL | → TAMPERED | Ed25519 signature is invalid, missing, or detached sig disagrees | Recompile and re-sign |
| `E_PKT_ROOT_INVARIANT` | FATAL | → TAMPERED | Packet root hash does not match recomputed root | Packet content or manifest has been modified. Recompile |
| `E_PKT_PACK_MISSING` | DEGRADING | → DEGRADED | Referenced bundled pack directory not found | Re-bundle with all referenced packs |
| `E_PKT_PACK_INVALID` | DEGRADING | → DEGRADED | Bundled pack fails its own verification (tampered receipt, broken sig, etc.) | Replace corrupted pack with valid copy and recompile |
| `E_PKT_REF_BROKEN` | WARNING | completeness only | Binding references a receipt/pack not declared in manifest | Fix binding evidence_refs or add pack reference |
| `E_PKT_REF_MISMATCH` | WARNING | completeness only | `pack_root_sha256` in binding does not match referenced pack | Fix evidence_ref or update pack reference |
| `E_PKT_COVERAGE_GAP` | WARNING | completeness only | Questionnaire item has no binding | Author missing bindings |
| `E_PKT_STALE` | POLICY | completeness only | Evidence freshness exceeds threshold | Refresh evidence and recompile |

### Severity Levels

| Level | Meaning |
|-------|---------|
| FATAL | Verification cannot proceed or packet is untrustworthy. Integrity verdict is TAMPERED or INVALID. |
| DEGRADING | Packet envelope is authentic but nested evidence is compromised. Integrity verdict is DEGRADED. |
| WARNING | Does not affect integrity verdict. Affects completeness verdict only. |
| POLICY | Configurable threshold. Does not affect integrity by default. |

---

## 5. Coverage Report Axes

The coverage report separates status counts from basis counts (they are orthogonal):

```json
{
  "status_counts": {
    "SUPPORTED": 3,
    "PARTIAL": 1,
    "UNSUPPORTED": 1,
    "NON_CLAIM": 1,
    "OUT_OF_SCOPE": 0
  },
  "basis_counts": {
    "MACHINE": 2,
    "HUMAN": 1,
    "MIXED": 1,
    "NONE": 2
  }
}
```

These are always separate sections, never mixed into one flat block.

---

## 6. Cross-Implementation Contract

Python and TypeScript verifiers MUST agree on:
- Integrity verdict (INTACT / DEGRADED / TAMPERED / INVALID)
- Completeness verdict (COMPLETE / PARTIAL / INCOMPLETE)
- Top-level verdict derivation
- Error codes for the same failure conditions

Implementations MAY differ on:
- Internal verification step ordering
- Warning text (not normative)
- Coverage report formatting (structure is normative, wording is not)
