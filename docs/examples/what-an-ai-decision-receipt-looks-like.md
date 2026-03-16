# What an Auditable AI Decision Looks Like

When your AI system refuses a request, blocks an action, or approves a workflow — what evidence do you have that the decision was governed?

Most systems log a status code. Some add a reason string. Almost none produce a **reviewable, policy-bound, evidence-linked decision artifact**.

A Decision Receipt does.

---

## Example: Automated Claim Denial

An AI claims adjudication system receives a request to auto-approve a claim. The system refuses.

Here is the receipt it produces:

### Decision

| Field | Value |
|-------|-------|
| **What was decided** | REFUSE — claim auto-approval blocked |
| **Why** | Claim touches protected data without required consent verification. Policy floor would be breached. |
| **Reason codes** | `consent_gate_missing`, `policy_floor_breach` |
| **Confidence** | High — evidence was sufficient to determine refusal |

### Authority

| Field | Value |
|-------|-------|
| **Who decided** | Governance gate (automated, not human override) |
| **Authority level** | BINDING — this decision blocks execution |
| **Jurisdiction** | Consent and data protection policy |
| **Policy applied** | `claims.consent_governance.v4` |
| **Policy hash** | `2345...ef01` (verifiable — the exact policy version is pinned) |

### Evidence Considered

| Evidence | Role | Integrity |
|----------|------|-----------|
| Consent verification check (negative result) | Supporting the refusal | Hash-verified |

No evidence gaps were identified. The refusal is based on complete information, not missing data.

### What Happens Next

| Field | Value |
|-------|-------|
| **Disposition** | Blocked — no downstream execution |
| **Review path** | Operator can resubmit after consent gate approval |
| **Obligations** | None created — clean refusal, no follow-up required |

### Audit Properties

| Property | Value |
|----------|-------|
| **Immutable** | This receipt cannot be edited after creation. Revisions create a new receipt pointing to this one. |
| **Signed** | Can be Ed25519-signed by the deciding authority |
| **Replayable** | Policy hash + evidence references allow reconstruction of why this decision was made |
| **Proof tier** | CONSTITUTIONAL — highest verification level |

---

## What This Proves

A Decision Receipt answers five questions that matter for compliance, audit, and trust:

1. **What was decided?** — REFUSE, with typed reason codes
2. **Who decided it?** — Identified authority with declared jurisdiction
3. **Under what rules?** — Pinned policy version, hash-verifiable
4. **On what evidence?** — Referenced, hash-bound, role-tagged
5. **What happened next?** — Blocked, with a clear review path

This is not a log line. It is a **governed artifact** that survives later review.

---

## Why Refusal Matters Most

Approval is easy to explain after the fact. Refusal is where governance earns trust.

When your AI system says "no," the people who need to understand why include:
- the operator who submitted the request
- the compliance team reviewing decisions
- the auditor asking "was this policy actually enforced?"
- the regulator asking "can you prove your AI follows your rules?"

A Decision Receipt gives all of them the same artifact — not a narrative, not a log, but a structured, verifiable, policy-bound decision record.

---

## Try It

```bash
pip install assay-ai
assay decision path/to/decision_receipt.json
```

The validator checks structural integrity, constitutional invariants (like "you cannot approve with insufficient evidence"), and forbidden states (like "high confidence with insufficient evidence").

Every consequential AI decision can leave a receipt. Including when it says no.

---

*Built with [Assay](https://github.com/Haserjian/assay) — proof infrastructure for AI systems.*
