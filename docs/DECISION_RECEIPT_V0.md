# Decision Receipt v0 Specification

## Loom/CCIO Constitutional Artifact

**Version**: 0.1.0
**Date**: 2026-03-15
**Status**: Implementation-ready (Phase 1: schema + validator)

---

## 1. Purpose

A Decision Receipt is a constitutional artifact that records **what was decided, under what authority, with what evidence, at what uncertainty, and what disposition followed**. It is the minimum auditable unit of a constitutional decision.

It answers five questions a downstream consumer (human auditor, replay engine, Assay verifier, or counterparty) needs answered:

1. **What was decided?** (the verdict and its scope)
2. **Who/what decided it?** (the deciding authority and its jurisdiction)
3. **Under what rules?** (the policy that governed the decision)
4. **On what evidence?** (what supported the verdict, and what was missing)
5. **What happened next?** (the disposition: action taken, deferred, or refused)

A Decision Receipt is NOT a record of execution, NOT a witness attestation, and NOT a policy artifact. It sits between evidence-gathering and execution, at the moment where authority meets uncertainty and produces a binding determination.

## 2. Scope

**In scope for v0:**
- Single-authority decisions (one decider, one verdict)
- Decisions made by Guardian, Spine controller, constitutional gates, and settlement transitions
- Approve, refuse, defer, abstain, and rollback verdicts
- Dissent and uncertainty recording
- Evidence reference binding (by hash, not by inclusion)
- Policy pinning (which rules governed this decision)
- Proof tier attachment
- CEID-compatible identity
- JCS canonicalization and Ed25519 signing readiness

**Not in scope for v0:**
- Multi-party voting or quorum decisions (v1 candidate)
- Decision chains or DAG structures beyond single parent_id (v1 candidate)
- Automated decision replay (v1 — receipt enables it, does not implement it)
- Real-time streaming of decisions (out of scope)
- Decision Receipt as a product surface (it is an infrastructure artifact)
- Merging with or replacing execution receipts (they remain separate)
- Human-in-the-loop approval workflows (v1 candidate, after disposition patterns stabilize)

## 3. Non-Goals

- **Not a dump of all runtime data.** The receipt records the decision point, not the full computation that preceded it.
- **Not a replacement for execution receipts.** Execution receipts record what was done. Decision receipts record what was decided. A single episode may produce one decision receipt and many execution receipts.
- **Not a policy store.** The receipt pins the policy by hash. The policy itself lives elsewhere.
- **Not a verification result.** Assay verification produces attestations. Decision receipts reference evidence but do not re-verify it.
- **Not a consensus protocol.** v0 records the output of a single authority. If multiple authorities were consulted, each produces its own receipt; aggregation is a consumer concern.

## 4. Lifecycle

```
  Evidence gathered
        |
        v
  +------------------+
  | DECISION POINT   |  <-- Decision Receipt is emitted here
  | (authority +     |
  |  policy +        |
  |  evidence)       |
  +------------------+
        |
        v
  Disposition: one of
    APPROVE  -> execution proceeds, execution receipt follows
    REFUSE   -> no execution, refusal receipt follows
    DEFER    -> decision postponed, obligation receipt follows
    ABSTAIN  -> authority declines to decide, escalation follows
    ROLLBACK -> prior decision reversed, compensation receipt follows
    CONFLICT -> split authority, escalation required
```

A Decision Receipt is immutable once emitted. If a decision is reversed, a new Decision Receipt is produced with `supersedes` pointing to the original. The original is never mutated.

## 5. Producer/Consumer Model

**Producers** (systems that emit Decision Receipts):
- Loom Spine controller (proof-tier decisions, escalation decisions)
- Loom Guardian capability gate (tool visibility decisions)
- Loom state transition engine (obligation/contradiction decisions)
- CCIO constitutional gates (admissibility verdicts)
- CCIO settlement transitions (reliance validation decisions)
- CCIO refusal path (refusal classification decisions)

**Consumers** (systems that read Decision Receipts):
- Assay proof pack builder (binds decision receipts into evidence chains)
- Assay ADC issuer (references decision receipts as claim evidence)
- Replay engine (reconstructs decision conditions for audit)
- CEID resolver (resolves decision identity across migration boundaries)
- Decision Hinge UI component (renders current authority state from latest receipt)
- Human auditors (reads the receipt to understand what happened and why)

**Contract**: Producers MUST emit a valid Decision Receipt for every constitutional decision. Consumers MUST NOT assume fields beyond the required set. Consumers MUST tolerate unknown `decision_type` values by treating them as opaque strings (forward compatibility).

## 6. Canonical JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://assay.dev/schemas/decision_receipt_v0.1.0.schema.json",
  "title": "Decision Receipt v0.1.0",
  "description": "Constitutional decision artifact. Records what was decided, under what authority, with what evidence, and what disposition followed.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "receipt_id",
    "receipt_type",
    "receipt_version",
    "timestamp",
    "decision_type",
    "decision_subject",
    "verdict",
    "authority_id",
    "authority_class",
    "authority_scope",
    "policy_id",
    "policy_hash",
    "episode_id",
    "disposition",
    "evidence_sufficient",
    "provenance_complete"
  ],
  "properties": {

    "receipt_id": {
      "type": "string",
      "description": "Unique identifier for this receipt. UUID v4.",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    },
    "receipt_type": {
      "type": "string",
      "description": "Receipt type discriminator.",
      "const": "decision_v1"
    },
    "receipt_version": {
      "type": "string",
      "description": "Schema version. Consumers MUST reject unknown versions.",
      "const": "0.1.0"
    },
    "ceid": {
      "type": ["string", "null"],
      "description": "Constitutional Entity ID if available. Null during migration or if CEID generation fails.",
      "minLength": 1
    },
    "timestamp": {
      "type": "string",
      "description": "ISO-8601 UTC timestamp when the decision was made.",
      "format": "date-time"
    },
    "parent_receipt_id": {
      "type": ["string", "null"],
      "description": "Receipt ID of the prior decision this one supersedes or continues. Null for first-in-chain."
    },
    "supersedes": {
      "type": ["string", "null"],
      "description": "Receipt ID of a decision this one explicitly reverses or replaces. Null if original."
    },

    "decision_type": {
      "type": "string",
      "description": "What kind of constitutional decision this is. Free string, not enum-locked. Recommended v0 values: gate_evaluation, proof_tier_determination, admissibility_verdict, refusal_classification, settlement_transition, escalation_determination, obligation_assessment, contradiction_resolution, rollback_authorization. New types do not require schema revision.",
      "minLength": 1
    },
    "decision_subject": {
      "type": "string",
      "description": "Stable identifier of what this decision is about. E.g. tool grant request ID, settlement packet ID, claim ID, transition ID, proof-tier candidate ID. Enables joining decisions to their subjects without parsing verdict_reason.",
      "minLength": 1
    },
    "verdict": {
      "type": "string",
      "description": "The decision outcome. Six canonical values.",
      "enum": ["APPROVE", "REFUSE", "DEFER", "ABSTAIN", "ROLLBACK", "CONFLICT"]
    },
    "verdict_reason": {
      "type": "string",
      "description": "Human-readable explanation of why this verdict was reached. Not machine-parsed. Max 500 chars.",
      "maxLength": 500
    },
    "verdict_reason_codes": {
      "type": "array",
      "description": "Machine-readable reason codes for the verdict. Ordered by significance.",
      "items": {
        "type": "string",
        "minLength": 1
      }
    },

    "authority_id": {
      "type": "string",
      "description": "Identifier of the deciding authority (e.g. 'loom:guardian:capability_gate', 'ccio:settlement:transitions', 'loom:spine:controller').",
      "minLength": 1
    },
    "authority_class": {
      "type": "string",
      "description": "CCOI authority class under which this decision was made.",
      "enum": ["ADVISORY", "AUDITING", "BINDING", "MUTATING", "OVERRIDING"]
    },
    "authority_scope": {
      "type": "string",
      "description": "What jurisdiction this authority covers (e.g. 'tool_visibility', 'proof_tier', 'provider_routing', 'settlement'). Prevents authority cross-contamination.",
      "minLength": 1
    },
    "delegated_from": {
      "type": ["string", "null"],
      "description": "If this decision was made under delegated authority, the ID of the delegating authority. Null for primary authority."
    },



    "policy_id": {
      "type": "string",
      "description": "Identifier of the policy that governed this decision.",
      "minLength": 1
    },
    "policy_hash": {
      "type": "string",
      "description": "SHA-256 hex digest of the JCS-canonicalized effective policy bundle applied at decision time, including inherited rules after resolution. Computed as: sha256(jcs_canonicalize(resolved_policy_document)). Prevents silent policy swap between decision and audit.",
      "pattern": "^[a-f0-9]{64}$"
    },
    "policy_hash_alg": {
      "type": "string",
      "description": "Hash algorithm used for policy_hash. Always 'sha256' in v0.1.0.",
      "const": "sha256"
    },
    "policy_version": {
      "type": ["string", "null"],
      "description": "Human-readable policy version if available. Recommended format: '<policy_name>.v<N>' (e.g. 'guardian.capability_gate.v3')."
    },


    "episode_id": {
      "type": "string",
      "description": "Episode within which this decision was made.",
      "minLength": 1
    },
    "session_state_hash": {
      "type": ["string", "null"],
      "description": "SHA-256 prefix (16 hex chars) of the canonical session state at decision time. Enables replay verification.",
      "pattern": "^[a-f0-9]{16}$"
    },
    "proof_tier_at_decision": {
      "type": ["string", "null"],
      "description": "Proof tier of the episode when this decision was made.",
      "enum": ["DRAFT", "CHECKED", "TOOL_VERIFIED", "ADVERSARIAL", "CONSTITUTIONAL", null]
    },
    "runtime_condition_vector": {
      "type": ["object", "null"],
      "description": "RCV snapshot at decision time. Observational only. Null if no signal was available.",
      "properties": {
        "contradiction_pressure": { "type": ["string", "null"] },
        "coherence_band": { "type": ["string", "null"] },
        "uncertainty_band": { "type": ["string", "null"] },
        "dignity_margin": { "type": ["string", "null"] },
        "routing_stress": { "type": ["string", "null"] }
      },
      "additionalProperties": false
    },


    "evidence_refs": {
      "type": "array",
      "description": "References to evidence considered for this decision. Each ref is a typed pointer, not the evidence itself.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["ref_type", "ref_id", "ref_role"],
        "properties": {
          "ref_type": {
            "type": "string",
            "description": "Kind of evidence referenced.",
            "enum": ["receipt", "claim", "attestation", "witness_bundle", "metric", "external"]
          },
          "ref_id": {
            "type": "string",
            "description": "Identifier of the referenced evidence artifact.",
            "minLength": 1
          },
          "ref_uri": {
            "type": ["string", "null"],
            "description": "Locator for the evidence artifact. URI, path, or system-qualified reference. Null if ref_id is sufficient for resolution within the same system."
          },
          "ref_hash": {
            "type": ["string", "null"],
            "description": "SHA-256 of the referenced artifact for integrity binding.",
            "pattern": "^[a-f0-9]{64}$"
          },
          "ref_role": {
            "type": "string",
            "description": "What role this evidence played in the decision.",
            "enum": ["supporting", "contradicting", "contextual", "superseded"]
          }
        }
      }
    },
    "evidence_sufficient": {
      "type": "boolean",
      "description": "Whether the decider judged evidence to be sufficient for this verdict under the governing policy and proof tier. Sufficient means: the evidence meets the minimum threshold defined by the active policy for a verdict of this type. False means: evidence was below threshold, which constrains the verdict (APPROVE is forbidden when false)."
    },
    "evidence_gaps": {
      "type": "array",
      "description": "Named gaps in evidence that were identified but not resolved at decision time.",
      "items": {
        "type": "string",
        "minLength": 1
      }
    },


    "confidence": {
      "type": ["string", "null"],
      "description": "Decider's epistemic confidence in the verdict. Enum band, not a float — bands are honest about the granularity of self-assessment. This is an epistemic summary chosen by the authority, constrained by evidence sufficiency and proof tier; it is not a probabilistic claim unless a policy explicitly defines it as such. Null means confidence was not assessed.",
      "enum": ["high", "moderate", "low", "minimal", null]
    },
    "conflict_refs": {
      "type": "array",
      "description": "Receipt IDs of authoritative decisions that are incompatible with this one. Used when verdict=CONFLICT. Distinct from dissent: dissent is advisory disagreement metadata; conflict_refs are authoritative contradictions requiring escalation.",
      "items": { "type": "string", "minLength": 1 }
    },
    "dissent": {
      "type": ["object", "null"],
      "description": "Structured dissent record if any advisory input disagreed with the verdict. Null if no dissent.",
      "properties": {
        "dissenter_ids": {
          "type": "array",
          "description": "Identifiers of advisory sources that disagreed.",
          "items": { "type": "string", "minLength": 1 }
        },
        "dissent_summary": {
          "type": "string",
          "description": "Human-readable summary of the dissenting position. Max 300 chars.",
          "maxLength": 300
        },
        "dissent_severity": {
          "type": "string",
          "description": "How serious the disagreement is.",
          "enum": ["note", "concern", "objection", "block"]
        }
      },
      "required": ["dissenter_ids", "dissent_summary", "dissent_severity"],
      "additionalProperties": false
    },
    "abstention_reason": {
      "type": ["string", "null"],
      "description": "If verdict is ABSTAIN, why the authority declined to decide. Null otherwise.",
      "maxLength": 300
    },
    "unresolved_contradictions": {
      "type": "array",
      "description": "Contradictions that existed at decision time and were NOT resolved by this decision.",
      "items": { "type": "string", "minLength": 1 }
    },


    "disposition": {
      "type": "string",
      "description": "What action followed from this decision.",
      "enum": [
        "execute",
        "block",
        "defer_with_obligation",
        "escalate",
        "compensate",
        "no_action"
      ]
    },
    "disposition_target": {
      "type": ["string", "null"],
      "description": "If disposition routes to a specific system or actor, its identifier. E.g. 'human_review', 'guardian_override', 'loom:spine:controller'."
    },
    "obligations_created": {
      "type": "array",
      "description": "New obligations that this decision created (must be satisfied before next transition).",
      "items": { "type": "string", "minLength": 1 }
    },


    "proof_tier_achieved": {
      "type": ["string", "null"],
      "description": "If this decision determined or changed a proof tier, the tier achieved. Null if decision does not affect proof tier.",
      "enum": ["DRAFT", "CHECKED", "TOOL_VERIFIED", "ADVERSARIAL", "CONSTITUTIONAL", null]
    },
    "proof_tier_minimum_required": {
      "type": ["string", "null"],
      "description": "Minimum proof tier required by policy for this decision to be valid. Null if no minimum was specified.",
      "enum": ["DRAFT", "CHECKED", "TOOL_VERIFIED", "ADVERSARIAL", "CONSTITUTIONAL", null]
    },


    "provenance_complete": {
      "type": "boolean",
      "description": "Whether all required provenance fields for claimed support are present and resolvable. True means: every evidence_ref has a valid ref_id, policy_hash matches a retrievable policy, and no known_provenance_gaps exist. False means: the receipt is structurally valid but epistemically degraded — some upstream references cannot be verified."
    },
    "known_provenance_gaps": {
      "type": "array",
      "description": "Fields that should be populated but are not, with reasons.",
      "items": { "type": "string", "minLength": 1 }
    },
    "source_organ": {
      "type": "string",
      "description": "Which system produced this receipt.",
      "enum": ["ccio", "loom", "agentmesh", "assay-toolkit", "assay-ledger", "puppetlabs"]
    },


    "content_hash": {
      "type": ["string", "null"],
      "description": "SHA-256 hex digest of the JCS-canonicalized receipt with signature and content_hash fields removed. Enables content-addressable lookup.",
      "pattern": "^[a-f0-9]{64}$"
    },
    "signature": {
      "type": ["string", "null"],
      "description": "Ed25519 signature over the JCS-canonicalized receipt with signature field removed. Null if unsigned.",
      "minLength": 1
    },
    "signer_pubkey_sha256": {
      "type": ["string", "null"],
      "description": "SHA-256 fingerprint of the signing public key. Null if unsigned.",
      "pattern": "^[a-f0-9]{64}$"
    }
  }
}
```

## 7. Required vs Optional Fields

### Existentially required (16 fields)

The irreducible minimum. Without these, no constitutional decision occurred.

| Field | Why required |
|-------|-------------|
| `receipt_id` | Identity — every receipt must be addressable |
| `receipt_type` | Discriminator — consumers must know what this is |
| `receipt_version` | Compatibility — consumers must reject unknown versions |
| `timestamp` | Temporality — decisions happen at a point in time |
| `decision_type` | Classification — what kind of decision |
| `decision_subject` | Target — what the decision is about |
| `verdict` | The decision itself |
| `authority_id` | Who decided — prevents orphaned decisions |
| `authority_class` | What power was exercised |
| `authority_scope` | Jurisdiction — prevents authority bleed |
| `policy_id` | What rules governed — prevents unaccountable decisions |
| `policy_hash` | Policy integrity — detects silent policy changes |
| `episode_id` | Context — which episode this belongs to |
| `disposition` | What followed — a decision without disposition is incomplete |
| `evidence_sufficient` | Epistemic honesty — was there enough evidence? |
| `provenance_complete` | Self-awareness — does the receipt know its own gaps? |

### Conditionally required (by verdict/disposition)

| Field | Required when |
|-------|--------------|
| `abstention_reason` | `verdict=ABSTAIN` |
| `supersedes` | `verdict=ROLLBACK` |
| `conflict_refs` or `dissent` | `verdict=CONFLICT` (at least one must be non-null/non-empty) |
| `obligations_created` | `disposition=defer_with_obligation` (must be non-empty) |
| `known_provenance_gaps` | `provenance_complete=false` (must be non-empty) |

### Optional enrichments

All non-required fields are optional. Producers may omit them unless otherwise constrained by invariants. A receipt with only existentially required fields is valid but considered **degraded** if `provenance_complete` is false.

## 8. Validation Invariants

These are machine-checkable rules that every valid Decision Receipt must satisfy:

**I-1: Verdict-disposition coherence.**
- `verdict=APPROVE` requires `disposition` in `{execute}`
- `verdict=REFUSE` requires `disposition` in `{block, escalate}`
- `verdict=DEFER` requires `disposition` in `{defer_with_obligation, escalate}`
- `verdict=ABSTAIN` requires `disposition` in `{escalate, no_action}` AND `abstention_reason` is non-null
- `verdict=ROLLBACK` requires `disposition` in `{compensate, execute}` AND `supersedes` is non-null
- `verdict=CONFLICT` requires `disposition` in `{escalate}` AND (`conflict_refs` is non-empty OR `dissent` is non-null)

**I-2: Authority-class escalation.**
- `authority_class=ADVISORY` requires `verdict` in `{APPROVE, REFUSE, DEFER, ABSTAIN}` (advisory cannot ROLLBACK or produce CONFLICT)
- `authority_class=OVERRIDING` requires `delegated_from` is non-null (overrides must cite source)

**I-3: Evidence sufficiency coherence.**
- If `evidence_sufficient=false`, then `verdict` must NOT be `APPROVE` (you cannot approve with known-insufficient evidence)
- If `evidence_sufficient=false` and `verdict=REFUSE`, then `evidence_gaps` must be non-empty (refusal on insufficient evidence must name what is missing)

**I-4: Proof tier monotonicity.**
- If `proof_tier_achieved` is non-null and `proof_tier_minimum_required` is non-null, then `proof_tier_achieved >= proof_tier_minimum_required` (the tier achieved cannot be below the minimum required and still produce an APPROVE verdict)
- Comparison is by ordinal rank: DRAFT(0) < CHECKED(1) < TOOL_VERIFIED(2) < ADVERSARIAL(3) < CONSTITUTIONAL(4). Validators MUST use this rank order, not lexicographic string comparison.
- Exception: when `verdict` is not `APPROVE`, achieved may be below minimum (that is why it was not approved)

**I-5: Supersession integrity.**
- `supersedes` must not equal `receipt_id` (a receipt cannot supersede itself)
- If `supersedes` is non-null, `parent_receipt_id` SHOULD also be non-null (recommended for lineage, but not invariant — some supersessions occur without explicit chain, e.g. emergency overrides)

**I-6: Provenance self-consistency.**
- If `provenance_complete=true`, then `known_provenance_gaps` must be empty
- If `provenance_complete=false`, then `known_provenance_gaps` must be non-empty

**I-7: Signature scope.**
- If `signature` is non-null, then `signer_pubkey_sha256` must also be non-null
- If `content_hash` is non-null, it must match the SHA-256 of the JCS-canonicalized receipt with `signature` and `content_hash` fields removed

## 9. Forbidden States

These combinations are structurally invalid and must be rejected at construction time:

| Forbidden state | Why |
|----------------|-----|
| `verdict=APPROVE` + `evidence_sufficient=false` | Cannot approve without sufficient evidence |
| `verdict=APPROVE` + `disposition=block` | Approval that blocks is incoherent |
| `verdict=REFUSE` + `disposition=execute` | Refusal that executes violates separation of decision/execution |
| `verdict=ABSTAIN` + `abstention_reason=null` | Abstention without explanation is silent abdication |
| `verdict=CONFLICT` + `conflict_refs` empty AND `dissent=null` | Conflict without either authoritative contradiction refs or dissent record is unauditable |
| `verdict=ROLLBACK` + `supersedes=null` | Cannot roll back nothing |
| `authority_class=ADVISORY` + `verdict=ROLLBACK` | Advisory authority cannot reverse prior decisions |
| `confidence=high` + `evidence_sufficient=false` | Confidence claim unsupported by evidence (`unsupported_high_confidence`) |
| `provenance_complete=true` + `known_provenance_gaps` non-empty | Self-contradictory provenance claim |
| `signature` non-null + `signer_pubkey_sha256=null` | Signature without verifiable key is theater |

## 10. Proof Tier Attachment

Decision Receipts interact with proof tiers in two ways:

**10a. Recording proof context.** Every decision receipt carries `proof_tier_at_decision` — the proof tier of the episode when the decision was made. This is observational (the decision does not change it).

**10b. Changing proof tier.** Some decisions (specifically `decision_type=proof_tier_determination`) produce a new proof tier. These set `proof_tier_achieved` and `proof_tier_minimum_required`. The receipt chain then shows:

```
[Decision Receipt: proof_tier_determination]
  proof_tier_at_decision: DRAFT
  proof_tier_achieved: CHECKED
  proof_tier_minimum_required: CHECKED
  verdict: APPROVE
  disposition: execute
  evidence_refs: [{ref_type: "receipt", ref_id: "critique_run_001", ...}]
```

This receipt is the authority for why the tier changed. The subsequent `state_transition` receipt records that the tier *did* change. These are distinct artifacts:
- Decision Receipt = "we determined the tier should be CHECKED because critique passed"
- Transition Receipt = "the state moved from DRAFT to CHECKED at timestamp T"

**Proof tier hierarchy for validation** (from `spine/models.py`):
```
DRAFT(0) < CHECKED(1) < TOOL_VERIFIED(2) < ADVERSARIAL(3) < CONSTITUTIONAL(4)
```

## 11. Dissent, Uncertainty, and Abstention

### 11a. Dissent

Dissent records advisory-level disagreement. It does NOT block the verdict (that would be CONFLICT). Dissent is structured to be queryable:

```json
{
  "dissent": {
    "dissenter_ids": ["ccio:quintet:adapter", "ccio:council:model_b"],
    "dissent_summary": "Model B flagged coherence degradation below 0.5 threshold; quintet scored policy compliance at 0.4.",
    "dissent_severity": "concern"
  }
}
```

Severity levels:
- `note` — informational disagreement, no action expected
- `concern` — substantive disagreement, should be reviewed
- `objection` — strong disagreement, should delay execution
- `block` — dissenter asserts the decision should not proceed (if the decision proceeds anyway, this is recorded as acknowledged-but-overridden)

### 11b. Uncertainty

Uncertainty is encoded via three orthogonal mechanisms:

1. **`confidence` field** — the decider's self-assessed confidence in the verdict (high/moderate/low/minimal)
2. **`evidence_sufficient` field** — whether the evidence met the threshold for this decision type
3. **`runtime_condition_vector`** — the observational operating envelope (coherence band, uncertainty band, etc.)

These are deliberately independent. A decider can have high confidence with sufficient evidence (normal case), low confidence with sufficient evidence (evidence was contradictory), or moderate confidence with insufficient evidence (decision was forced by deadline despite gaps).

The combination of `confidence=low` + `evidence_sufficient=false` + `verdict=DEFER` is the canonical "honest uncertainty" receipt.

### 11c. Abstention

Abstention means the authority **declines to decide**. This is distinct from DEFER (which is a decision to postpone). Abstention happens when:

- The authority lacks jurisdiction (`abstention_reason: "outside_authority_scope"`)
- The evidence is so incomplete that any verdict would be misleading (`abstention_reason: "evidence_below_minimum_for_any_verdict"`)
- The authority detects a conflict of interest (`abstention_reason: "conflict_of_interest"`)

Abstention always requires `abstention_reason` and always produces `disposition=escalate` or `disposition=no_action`.

## 12. Example Receipts

### 12a. Approve — Guardian capability gate allows tool access

```json
{
  "receipt_id": "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
  "receipt_type": "decision_v1",
  "receipt_version": "0.1.0",
  "ceid": "CDE-loom-gat-20260315T140000Z-a1b2c3d4",
  "timestamp": "2026-03-15T14:00:00.123Z",
  "parent_receipt_id": null,
  "supersedes": null,
  "decision_type": "gate_evaluation",
  "decision_subject": "tool_grant:shell_exec+file_write:session_0a3f",
  "verdict": "APPROVE",
  "verdict_reason": "All requested tools permitted under current session state: environment=development, proof_tier=CHECKED, operator_mode=interactive.",
  "verdict_reason_codes": ["policy_permits", "tier_sufficient", "no_contraindications"],
  "authority_id": "loom:guardian:capability_gate",
  "authority_class": "BINDING",
  "authority_scope": "tool_visibility",
  "delegated_from": null,
  "policy_id": "guardian.capability_gate.v3",
  "policy_hash": "a3f8b2c1d4e5f6789012345678901234567890abcdef1234567890abcdef1234",
  "policy_version": "3.2.1",
  "episode_id": "ep_20260315_session_042",
  "session_state_hash": "b4c5d6e7f8a9b0c1",
  "proof_tier_at_decision": "CHECKED",
  "runtime_condition_vector": {
    "contradiction_pressure": "none",
    "coherence_band": "strong",
    "uncertainty_band": "calibrated",
    "dignity_margin": "comfortable",
    "routing_stress": "nominal"
  },
  "evidence_refs": [
    {
      "ref_type": "receipt",
      "ref_id": "critique_run_041",
      "ref_hash": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      "ref_role": "supporting"
    }
  ],
  "evidence_sufficient": true,
  "evidence_gaps": [],
  "confidence": "high",
  "dissent": null,
  "abstention_reason": null,
  "unresolved_contradictions": [],
  "disposition": "execute",
  "disposition_target": null,
  "obligations_created": [],
  "proof_tier_achieved": null,
  "proof_tier_minimum_required": null,
  "provenance_complete": true,
  "known_provenance_gaps": [],
  "source_organ": "loom",
  "content_hash": null,
  "signature": null,
  "signer_pubkey_sha256": null
}
```

### 12b. Abstain — Council disagreement too high, authority declines

```json
{
  "receipt_id": "b2c3d4e5-f6a7-4890-bcde-f01234567890",
  "receipt_type": "decision_v1",
  "receipt_version": "0.1.0",
  "ceid": null,
  "timestamp": "2026-03-15T14:05:00.456Z",
  "parent_receipt_id": null,
  "supersedes": null,
  "decision_type": "admissibility_verdict",
  "decision_subject": "settlement:packet_SP-2026-0315-001",
  "verdict": "ABSTAIN",
  "verdict_reason": "Council standard deviation 0.32 exceeds critical threshold 0.25. No verdict is epistemically defensible.",
  "verdict_reason_codes": ["council_disagreement_critical", "confidence_below_floor"],
  "authority_id": "ccio:settlement:admissibility",
  "authority_class": "BINDING",
  "authority_scope": "settlement",
  "delegated_from": null,
  "policy_id": "ccio.settlement.admissibility.v2",
  "policy_hash": "c4d5e6f7890123456789abcdef0123456789abcdef0123456789abcdef012345",
  "policy_version": "2.0.0",
  "episode_id": "ep_20260315_settlement_007",
  "session_state_hash": null,
  "proof_tier_at_decision": "TOOL_VERIFIED",
  "runtime_condition_vector": {
    "contradiction_pressure": "critical",
    "coherence_band": "degraded",
    "uncertainty_band": "uncalibrated",
    "dignity_margin": null,
    "routing_stress": null
  },
  "evidence_refs": [
    {
      "ref_type": "metric",
      "ref_id": "council_std_run_007",
      "ref_hash": null,
      "ref_role": "contradicting"
    }
  ],
  "evidence_sufficient": false,
  "evidence_gaps": ["council_convergence", "secondary_model_confirmation"],
  "confidence": "minimal",
  "dissent": null,
  "abstention_reason": "Council disagreement exceeds critical threshold. Any verdict would misrepresent the state of evidence.",
  "unresolved_contradictions": ["model_a_approve_vs_model_b_refuse"],
  "disposition": "escalate",
  "disposition_target": "human_review",
  "obligations_created": ["resolve_council_disagreement_before_retry"],
  "proof_tier_achieved": null,
  "proof_tier_minimum_required": null,
  "provenance_complete": true,
  "known_provenance_gaps": [],
  "source_organ": "ccio",
  "content_hash": null,
  "signature": null,
  "signer_pubkey_sha256": null
}
```

### 12c. Defer — Evidence incomplete, decision postponed with obligation

```json
{
  "receipt_id": "c3d4e5f6-a7b8-4901-cdef-012345678901",
  "receipt_type": "decision_v1",
  "receipt_version": "0.1.0",
  "ceid": null,
  "timestamp": "2026-03-15T14:10:00.789Z",
  "parent_receipt_id": null,
  "supersedes": null,
  "decision_type": "proof_tier_determination",
  "decision_subject": "proof_tier:episode_ep-20260315-run42",
  "verdict": "DEFER",
  "verdict_reason": "Verification tool returned timeout. Cannot determine proof tier without verifier output. Deferring until verifier completes or budget expires.",
  "verdict_reason_codes": ["verifier_timeout", "evidence_incomplete"],
  "authority_id": "loom:spine:controller",
  "authority_class": "BINDING",
  "authority_scope": "proof_tier",
  "delegated_from": null,
  "policy_id": "spine.proof_budget.v2",
  "policy_hash": "d5e6f789012345678901abcdef23456789abcdef012345678901abcdef234567",
  "policy_version": "2.1.0",
  "episode_id": "ep_20260315_session_042",
  "session_state_hash": "e6f7a8b9c0d1e2f3",
  "proof_tier_at_decision": "DRAFT",
  "runtime_condition_vector": {
    "contradiction_pressure": "none",
    "coherence_band": null,
    "uncertainty_band": null,
    "dignity_margin": null,
    "routing_stress": "elevated"
  },
  "evidence_refs": [
    {
      "ref_type": "receipt",
      "ref_id": "verifier_attempt_003",
      "ref_hash": "e6f7890123456789abcdef0123456789abcdef0123456789abcdef01234567ef",
      "ref_role": "contextual"
    }
  ],
  "evidence_sufficient": false,
  "evidence_gaps": ["verifier_output"],
  "confidence": "low",
  "dissent": null,
  "abstention_reason": null,
  "unresolved_contradictions": [],
  "disposition": "defer_with_obligation",
  "disposition_target": "loom:spine:controller",
  "obligations_created": ["complete_verification_or_escalate_within_budget"],
  "proof_tier_achieved": null,
  "proof_tier_minimum_required": "CHECKED",
  "provenance_complete": true,
  "known_provenance_gaps": [],
  "source_organ": "loom",
  "content_hash": null,
  "signature": null,
  "signer_pubkey_sha256": null
}
```

### 12d. Rollback — Prior approval reversed due to new contradicting evidence

```json
{
  "receipt_id": "d4e5f6a7-b8c9-4012-def0-123456789012",
  "receipt_type": "decision_v1",
  "receipt_version": "0.1.0",
  "ceid": null,
  "timestamp": "2026-03-15T14:15:00.012Z",
  "parent_receipt_id": "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
  "supersedes": "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
  "decision_type": "rollback_authorization",
  "decision_subject": "tool_grant:shell_exec+file_write:session_0a3f",
  "verdict": "ROLLBACK",
  "verdict_reason": "Post-execution verification revealed output hash mismatch. Original approval (a1b2c3d4) based on stale evidence. Rollback authorized.",
  "verdict_reason_codes": ["post_execution_failure", "evidence_invalidated", "hash_mismatch"],
  "authority_id": "loom:guardian:capability_gate",
  "authority_class": "MUTATING",
  "authority_scope": "tool_visibility",
  "delegated_from": null,
  "policy_id": "guardian.rollback.v1",
  "policy_hash": "f6a7b8c9d0e1f23456789012abcdef3456789012abcdef3456789012abcdef34",
  "policy_version": "1.0.0",
  "episode_id": "ep_20260315_session_042",
  "session_state_hash": "a8b9c0d1e2f3a4b5",
  "proof_tier_at_decision": "CHECKED",
  "runtime_condition_vector": {
    "contradiction_pressure": "high",
    "coherence_band": "degraded",
    "uncertainty_band": "wide",
    "dignity_margin": "comfortable",
    "routing_stress": "nominal"
  },
  "evidence_refs": [
    {
      "ref_type": "receipt",
      "ref_id": "verification_run_044",
      "ref_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      "ref_role": "contradicting"
    },
    {
      "ref_type": "receipt",
      "ref_id": "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
      "ref_hash": null,
      "ref_role": "contextual"
    }
  ],
  "evidence_sufficient": true,
  "evidence_gaps": [],
  "confidence": "high",
  "dissent": null,
  "abstention_reason": null,
  "unresolved_contradictions": [],
  "disposition": "compensate",
  "disposition_target": "loom:spine:controller",
  "obligations_created": ["revert_tool_grants_from_original_approval", "emit_compensation_receipt"],
  "proof_tier_achieved": null,
  "proof_tier_minimum_required": null,
  "provenance_complete": true,
  "known_provenance_gaps": [],
  "source_organ": "loom",
  "content_hash": null,
  "signature": null,
  "signer_pubkey_sha256": null
}
```

### 12e. Conflict / Split-Brain — Two authorities disagree, escalation required

```json
{
  "receipt_id": "e5f6a7b8-c9d0-4123-ef01-234567890123",
  "receipt_type": "decision_v1",
  "receipt_version": "0.1.0",
  "ceid": null,
  "timestamp": "2026-03-15T14:20:00.345Z",
  "parent_receipt_id": null,
  "supersedes": null,
  "decision_type": "settlement_transition",
  "decision_subject": "settlement:provider_routing:model_b_v2",
  "verdict": "CONFLICT",
  "verdict_reason": "Guardian gate approved tool access but settlement validation flagged reliance on an expired receipt. Two binding authorities reached incompatible conclusions.",
  "verdict_reason_codes": ["authority_conflict", "stale_reliance", "gate_settlement_split"],
  "authority_id": "ccio:settlement:conflict_detector",
  "authority_class": "BINDING",
  "authority_scope": "settlement",
  "delegated_from": null,
  "policy_id": "ccio.settlement.conflict.v1",
  "policy_hash": "01234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "policy_version": "1.0.0",
  "episode_id": "ep_20260315_settlement_008",
  "session_state_hash": null,
  "proof_tier_at_decision": "TOOL_VERIFIED",
  "runtime_condition_vector": {
    "contradiction_pressure": "high",
    "coherence_band": "degraded",
    "uncertainty_band": "wide",
    "dignity_margin": null,
    "routing_stress": null
  },
  "evidence_refs": [
    {
      "ref_type": "receipt",
      "ref_id": "gate_approval_042",
      "ref_hash": null,
      "ref_role": "supporting"
    },
    {
      "ref_type": "receipt",
      "ref_id": "reliance_check_expired_017",
      "ref_hash": null,
      "ref_role": "contradicting"
    }
  ],
  "evidence_sufficient": true,
  "evidence_gaps": [],
  "confidence": "high",
  "conflict_refs": ["gate_approval_042", "reliance_check_expired_017"],
  "dissent": {
    "dissenter_ids": ["loom:guardian:capability_gate"],
    "dissent_summary": "Guardian gate approved based on current session state, which does not track receipt expiry. Settlement layer identified stale reliance.",
    "dissent_severity": "block"
  },
  "abstention_reason": null,
  "unresolved_contradictions": ["gate_approval_vs_settlement_expiry"],
  "disposition": "escalate",
  "disposition_target": "human_review",
  "obligations_created": ["resolve_gate_settlement_conflict", "refresh_stale_receipt"],
  "proof_tier_achieved": null,
  "proof_tier_minimum_required": null,
  "provenance_complete": true,
  "known_provenance_gaps": [],
  "source_organ": "ccio",
  "content_hash": null,
  "signature": null,
  "signer_pubkey_sha256": null
}
```

### 12f. Refuse — Ethical boundary refusal with recourse hint

```json
{
  "receipt_id": "f6a7b8c9-d0e1-4234-f012-345678901234",
  "receipt_type": "decision_v1",
  "receipt_version": "0.1.0",
  "ceid": null,
  "timestamp": "2026-03-15T14:25:00.678Z",
  "parent_receipt_id": null,
  "supersedes": null,
  "decision_type": "refusal_classification",
  "decision_subject": "request:user_query_consent_withdrawal_q-9f2a",
  "verdict": "REFUSE",
  "verdict_reason": "Request touches PHI data in production environment without explicit consent gate approval. Ethical boundary: dignity floor would be breached.",
  "verdict_reason_codes": ["ethical_boundary", "phi_without_consent", "dignity_floor_breach"],
  "authority_id": "ccio:governance:dignity_ledger",
  "authority_class": "BINDING",
  "authority_scope": "dignity",
  "delegated_from": null,
  "policy_id": "ccio.governance.dignity.v4",
  "policy_hash": "23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
  "policy_version": "4.1.0",
  "episode_id": "ep_20260315_clinical_003",
  "session_state_hash": null,
  "proof_tier_at_decision": "CONSTITUTIONAL",
  "runtime_condition_vector": {
    "contradiction_pressure": "none",
    "coherence_band": "strong",
    "uncertainty_band": "calibrated",
    "dignity_margin": "below_floor",
    "routing_stress": "nominal"
  },
  "evidence_refs": [
    {
      "ref_type": "receipt",
      "ref_id": "consent_gate_check_negative_003",
      "ref_hash": "3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
      "ref_role": "supporting"
    }
  ],
  "evidence_sufficient": true,
  "evidence_gaps": [],
  "confidence": "high",
  "dissent": null,
  "abstention_reason": null,
  "unresolved_contradictions": [],
  "disposition": "block",
  "disposition_target": null,
  "obligations_created": [],
  "proof_tier_achieved": null,
  "proof_tier_minimum_required": null,
  "provenance_complete": true,
  "known_provenance_gaps": [],
  "source_organ": "ccio",
  "content_hash": null,
  "signature": null,
  "signer_pubkey_sha256": null
}
```

## 13. Proposed Implementation Plan

### File/Module Layout

**Shared schema (assay-toolkit):**
```
assay-toolkit/src/assay/schemas/decision_receipt_v0.1.schema.json
```

**Loom (producer + consumer):**
```
loom-main-clean/spine/decision_receipt.py        # DecisionReceipt dataclass + builder
loom-main-clean/spine/decision_receipt_builder.py # Builder functions per decision_type
loom-main-clean/spine/tests/test_decision_receipt.py
loom-main-clean/spine/tests/test_decision_receipt_invariants.py
loom-main-clean/spine/tests/test_decision_receipt_builder.py
```

**CCIO (producer + consumer):**
```
ccio/src/receipts/decision_receipt.py            # DecisionReceipt Pydantic model
ccio/src/receipts/decision_receipt_validator.py   # Invariant checker (I-1 through I-7)
ccio/tests/receipts/test_decision_receipt.py
ccio/tests/receipts/test_decision_receipt_validator.py
ccio/tests/receipts/test_decision_receipt_compat.py  # Cross-repo shape guard
```

### Implementation Phases

**Phase 1: Schema + Validator (no producers yet)**
1. Land `decision_receipt_v0.1.schema.json` in assay-toolkit schemas
2. Implement `DecisionReceipt` as a frozen Pydantic model in CCIO with `extra="forbid"`
3. Implement `validate_decision_receipt()` checking all 7 invariants and 10 forbidden states
4. Write conformance tests: valid examples from section 12, plus one test per invariant and one per forbidden state
5. Implement `DecisionReceipt` as a frozen dataclass in Loom spine (no Pydantic dependency in spine)

**Phase 2: First producer — Loom gate evaluation**
1. Add `build_gate_decision_receipt()` in `decision_receipt_builder.py`
2. Call it from `GateEvaluationReceipt.from_result()` (emit both the existing gate receipt AND the new decision receipt in parallel — dual-emit, no breaking change)
3. Test that gate evaluation produces a valid decision receipt with correct invariants

**Phase 3: CCIO producers**
1. Add `build_admissibility_decision_receipt()` for settlement admissibility verdicts
2. Add `build_refusal_decision_receipt()` for refusal classification
3. Wire into existing code paths via dual-emit pattern

**Phase 4: Assay integration**
1. Register `decision_v1` as a known receipt type in Assay proof pack builder
2. Add decision receipts to the evidence chain in proof packs
3. ADC issuer can reference decision receipts via `evidence_refs`

### Testing Strategy

Per-phase, each test file covers:
- **Shape tests**: valid construction, required field enforcement, additionalProperties=false
- **Invariant tests**: one test per invariant (I-1 through I-7), both positive and negative
- **Forbidden state tests**: one test per forbidden combination from section 9
- **Builder tests**: each builder produces valid receipts for its decision type
- **Compat tests**: cross-repo shape guard (Loom receipt consumable by CCIO validator)
- **Round-trip tests**: serialize -> deserialize -> validate == original

Estimated test count: ~60-80 tests across both repos.

## 14. Migration Note: How This Differs from Existing Artifacts

### Decision Receipt vs Execution Receipt (spine_controller_run)

| Dimension | Decision Receipt | Execution Receipt |
|-----------|-----------------|-------------------|
| **Records** | What was decided and why | What was done and what it produced |
| **Authority** | The deciding entity | The executing entity |
| **Timing** | At the decision point | After execution completes |
| **Content** | Verdict, policy, evidence refs, uncertainty | Candidates, checks, claims, budget used |
| **Example** | "Guardian approved tool X under policy Y" | "Tool X ran, produced output Z, used 3 verification passes" |
| **Identity** | `receipt_type: "decision_v1"` | `receipt_type: "spine_controller_run"` |

These are complementary. A typical episode produces 1+ decision receipts followed by 1 execution receipt. The execution receipt may reference the decision receipt via `parent_ids`.

### Decision Receipt vs Attestation (proof pack attestation)

| Dimension | Decision Receipt | Attestation |
|-----------|-----------------|-------------|
| **Records** | A single decision and its rationale | Aggregate verification of a proof pack |
| **Scope** | One decision by one authority | Entire pack: integrity, claims, proof tier |
| **Producer** | Guardian, spine controller, settlement | Assay verifier |
| **Signed by** | The deciding authority's key | The verifier's key |
| **When emitted** | At decision time, during the episode | After the episode, during pack verification |

### Decision Receipt vs Witness Bundle

| Dimension | Decision Receipt | Witness Bundle |
|-----------|-----------------|---------------|
| **Records** | What was decided | That a specific hash existed at a specific time |
| **Authority** | Constitutional (internal) | External (TSA, transparency log) |
| **Content** | Rich structured decision | Minimal: hash + timestamp + token |
| **Purpose** | Audit trail for "why" | Tamper evidence for "when" |

### Decision Receipt vs Constitutional Provider Receipt

| Dimension | Decision Receipt | Constitutional Provider Receipt |
|-----------|-----------------|-------------------------------|
| **Records** | Any constitutional decision | Specifically: governed provider delegation |
| **Scope** | General-purpose | Provider routing only |
| **Relation** | The provider routing decision receipt would be a `decision_type: "provider_routing"` (future v0.2) | Existing artifact that predates this spec |
| **Migration** | No immediate migration needed | In v0.2, could be expressed as a Decision Receipt with `decision_type: "provider_routing"` and execution details moved to a companion execution receipt |

### Decision Receipt vs State Transition Record

| Dimension | Decision Receipt | Transition Record |
|-----------|-----------------|------------------|
| **Records** | The decision to change state | The state change itself |
| **Content** | Verdict, evidence, uncertainty | before_hash, after_hash, transition_type |
| **Ordering** | Emitted first | Emitted second (after decision approves) |
| **Relation** | Decision receipt authorizes the transition | Transition record proves it happened |

## 15. Design Traps to Avoid

**Trap 1: Decision-execution conflation.**
The strongest temptation is to add execution details to the decision receipt ("what tools were used," "what output was produced," "how long it took"). Resist this. The decision receipt records the moment of judgment, not the moment of action. If you find yourself adding `latency_ms` or `output_hash`, you are building an execution receipt wearing a decision receipt's name.

**Trap 2: Floating confidence numbers.**
Using `confidence: 0.73` instead of enum bands (`confidence: "moderate"`) creates a false precision trap. The decider does not actually know it is 73% confident. Enum bands (high/moderate/low/minimal) are honest about the granularity of self-assessment. Floats invite comparison and thresholding that the underlying signal cannot support.

**Trap 3: Implicit abstention.**
If an authority cannot decide, it must say so explicitly with `verdict: ABSTAIN` and `abstention_reason`. The alternative — silently producing no receipt — makes silence indistinguishable from crash, timeout, or deliberate suppression. An authority that has nothing to say must say that it has nothing to say.

**Trap 4: Policy inference from verdicts.**
Do not design systems that reconstruct policy from a stream of decision receipts. The receipt records which policy was applied (by ID and hash); it does not encode the policy itself. If you find yourself pattern-matching across receipts to figure out "what rule produced this," you need the policy artifact, not more receipt fields.

**Trap 5: Dissent as veto.**
Dissent is a record of disagreement, not a mechanism for blocking decisions. If dissent could block, it would be authority, and it would need its own receipt. The `dissent_severity: "block"` level means the dissenter *asserted* the decision should not proceed — it does not mean the decision was actually blocked. Whether the decision proceeded despite a block-level dissent is visible in the `disposition` field. This separation is load-bearing: it means you can audit "how often did we override block-level dissent?" without changing the decision protocol.

**Trap 6: Receipt inflation.**
Not every runtime event is a decision. A cache lookup is not a decision. A log write is not a decision. A metric emission is not a decision. The test is: "Did an authority exercise judgment under policy that could have gone differently?" If no, it is not a decision and does not get a Decision Receipt. Emitting receipts for non-decisions drowns signal in noise and makes the audit chain useless.

**Trap 7: Retroactive receipt mutation.**
Decision Receipts are immutable. If a decision needs to be revised, a new receipt is emitted with `supersedes` pointing to the original. The original is never modified, even if it was wrong. This is not a performance optimization — it is an integrity invariant. Any system that allows receipt mutation is unauditable.

**Trap 8: Clever field inference over explicit fields.**
It is tempting to derive `evidence_sufficient` from "are there any evidence_refs?" or `provenance_complete` from "are all optional fields non-null?" Do not. These fields carry independent semantic meaning. A receipt can have zero evidence_refs and still be evidence_sufficient (the authority may have direct knowledge). A receipt can have all optional fields populated and still be provenance_incomplete (the authority knows it is missing something not representable in the current schema). Explicit fields over clever inference, always.

**Trap 9: Mixing source_organ with authority_id.**
`source_organ` is the system that produced the receipt (infrastructure concern). `authority_id` is the entity that made the decision (constitutional concern). They often coincide but are not the same. A CCIO adapter running inside Loom would have `source_organ: "loom"` but `authority_id: "ccio:settlement:transitions"`. Collapsing these would hide delegation.

**Trap 10: Premature chain structure.**
v0 deliberately uses a single `parent_receipt_id` and `supersedes` pair instead of a full DAG. This is not laziness — it is because the actual decision chain patterns in Loom and CCIO are overwhelmingly linear (decide, then maybe revise). If v1 reveals multi-parent decision patterns, upgrade to `parent_receipt_ids: [...]`. Do not add the DAG structure before observing the need.

## 16. Verdict Boundary Matrix

| Verdict | Meaning | Allowed dispositions | Required fields |
|---------|---------|---------------------|----------------|
| `APPROVE` | Authorization granted | `execute` | `evidence_sufficient` must be `true` |
| `REFUSE` | Decision not to authorize | `block`, `escalate` | If `evidence_sufficient=false`, `evidence_gaps` must be non-empty |
| `DEFER` | Decision to postpone pending conditions | `defer_with_obligation`, `escalate` | `obligations_created` must be non-empty when `defer_with_obligation` |
| `ABSTAIN` | Authority declines to decide (not a postponement) | `escalate`, `no_action` | `abstention_reason` must be non-null |
| `ROLLBACK` | Reversal/compensation of prior action | `compensate`, `execute` | `supersedes` must be non-null |
| `CONFLICT` | Unresolved incompatible authoritative outcomes | `escalate` | `conflict_refs` non-empty OR `dissent` non-null |

Key boundaries:
- REFUSE vs ABSTAIN: REFUSE is a decision ("no"). ABSTAIN is a non-decision ("I cannot/should not decide").
- DEFER vs ABSTAIN: DEFER is an active decision to wait for conditions. ABSTAIN is withdrawal of authority.
- ROLLBACK vs REFUSE: ROLLBACK reverses a prior APPROVE. REFUSE prevents an initial APPROVE.
- CONFLICT vs REFUSE: CONFLICT means incompatible authorities disagree. REFUSE is a single authority's "no."

## 17. Signature Posture Note

A signature on a Decision Receipt proves **authorship and integrity**, not truth. Specifically:
- The signer attests: "I produced this receipt and its contents have not been modified."
- The signer does NOT attest: "The verdict was correct" or "the evidence was complete."
- Verification must still honor the signer trust/revocation policy defined elsewhere.
- A valid signature on a receipt with `evidence_sufficient=false` or `confidence=low` does not upgrade the epistemic quality — it only proves the receipt was not tampered with.

This separation is important because it prevents signing from becoming a substitute for evidence quality.

---

**End of specification. Implementation begins after review.**

---

That is the complete Decision Receipt v0 specification. Summary of what it covers:

1. **Purpose and scope** (sections 1-3): Positions the artifact precisely between evidence-gathering and execution, with clear non-goals.

2. **JSON schema** (section 6): ~42 fields, 16 existentially required + 5 conditionally required. Organized into identity, decision, authority, policy, context, evidence binding, uncertainty/dissent, disposition, proof tier, provenance, and signature blocks.

3. **Required vs optional** (section 7): 16 existentially required, 5 conditionally required, remainder optional enrichment.

4. **7 validation invariants** (section 8): Machine-checkable rules including verdict-disposition coherence, authority-class constraints, evidence sufficiency coherence, proof tier monotonicity, supersession integrity, and provenance self-consistency.

5. **10 forbidden states** (section 9): Structurally invalid field combinations that must be rejected at construction.

6. **Proof tier attachment** (section 10): Decision receipts both observe and (for proof_tier_determination types) produce proof tiers, with clear separation from transition receipts.

7. **Dissent/uncertainty/abstention** (section 11): Three orthogonal uncertainty mechanisms (confidence bands, evidence sufficiency boolean, RCV), structured dissent with severity levels, and explicit abstention semantics.

8. **6 example receipts** (section 12): Approve, abstain, defer, rollback, conflict/split-brain, and ethical refusal -- each fully populated with realistic field values grounded in the actual codebase.

9. **Implementation plan** (section 13): Four phases (schema+validator, first Loom producer, CCIO producers, Assay integration) with specific file paths and ~60-80 estimated tests.

10. **Migration note** (section 14): Five comparison tables showing how Decision Receipt differs from execution receipts, attestations, witness bundles, constitutional provider receipts, and state transition records.

11. **10 design traps** (section 15): Concrete anti-patterns grounded in the existing codebase architecture.

Key design choices grounded in what I found in the codebase:
- Enum bands for confidence and RCV (matching `/Users/timmymacbookpro/ccio/src/core/runtime_condition_vector.py` pattern)
- CCOI authority classes reused directly (matching `/Users/timmymacbookpro/ccio/src/core/ccoi_envelope.py`)
- Proof tier enum values match Loom's `ProofTier(IntEnum)` in `/Users/timmymacbookpro/loom-main-clean/spine/models.py`
- Source organ values match CCOI's `SourceOrgan` literal
- Refusal types align with `/Users/timmymacbookpro/ccio/src/receipts/refusal_classification.py`
- Frozen/immutable pattern matches existing `model_config = {"frozen": True, "extra": "forbid"}` convention
- JCS + Ed25519 signing readiness matches the ADC schema at `/Users/timmymacbookpro/assay-toolkit/src/assay/schemas/adc_v0.1.schema.json`
