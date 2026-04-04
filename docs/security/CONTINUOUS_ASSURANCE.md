# Assay Continuous Assurance Operating Model

This document describes how Assay keeps the settled 2026-04-03 posture from drifting.
It is not a replay of the raw audit. The controlling current-state set is:

- [`SECURITY_AUDIT_ADJUDICATION_2026-04-03.md`](SECURITY_AUDIT_ADJUDICATION_2026-04-03.md)
- [`CLAIM_LEDGER.md`](CLAIM_LEDGER.md)
- [`SECURITY_INVARIANTS.md`](SECURITY_INVARIANTS.md)
- [`SECURITY_POSTURE_TODAY.md`](SECURITY_POSTURE_TODAY.md)
- [`SIGNER_BOOTSTRAP_DECISION.md`](SIGNER_BOOTSTRAP_DECISION.md)
- [`LEDGER_SCOPE_DECISION.md`](LEDGER_SCOPE_DECISION.md)

---

## First Classification Rule

Before opening a new security work item, classify it first:

1. **Overclaim or mixed-contract confusion**
2. **Docs or assurance drift**
3. **Live design or implementation gap**

Routing rule:
- Overclaim or mixed-contract confusion goes to the adjudication memo, not the active invariant set.
- Docs or assurance drift goes to the claim ledger, posture doc, invariants, and any affected decision note.
- Live design or implementation gaps go to the invariant set, tests, or protocol/design work.

---

## Three Loops

### Loop 1 — Every Commit / PR

Runs on every push and PR.

**What runs:**
1. Proof-pack contract tests and current ReceiptV2 tests stay green.
2. Claim-surface drift check keeps these statements out of current docs and release copy unless the implementation changes:
   - `assay gate check` cryptographically verifies proof packs
   - default strong signer authorization is active
   - the ledger independently re-verifies full proof packs before acceptance
   - RFC 8785 string preservation is a JCS defect
3. Any PR that changes signer policy, ledger workflow, or receipt contract boundaries must update the affected decision note and the canonical current-state set in the same change.
4. Any historical audit note kept in-tree must point back to the canonical adjudication memo.

**Trigger**: `on: [push, pull_request]`
**Must-pass**: Yes for code and contract tests. The documentation checks may be automated later or handled as a required review item.

---

### Loop 2 — Every Release

Runs before PyPI publication, outbound materials, or customer-facing proof language.

**What runs:**
1. **Claim ledger audit** — every public assurance statement maps to [`CLAIM_LEDGER.md`](CLAIM_LEDGER.md), and no `UNPROVEN` claim ships.
2. **Canonical-set alignment** — the adjudication memo, claim ledger, invariants, and posture doc all describe the same current reality.
3. **Decision alignment** — signer bootstrap and ledger scope decisions still match the shipping workflow.
4. **Release copy audit** — release notes, docs, and external copy do not outrun the current claim boundary.

**Trigger**: release cut or manual pre-release review.
**Must-pass**: Yes.

---

### Loop 3 — Weekly Or Before External Review

Runs on a schedule or before a customer demo, audit handoff, or major announcement.

**Scope per run:**
- Deltas touching `src/assay/_receipts/`, trust policy, ledger workflow, or security docs
- Any new public-facing language about verification, signer authorization, or ledger witness scope
- Any change that could blur proof-pack contract boundaries with other receipt surfaces

**Focus lanes:**
1. Signer bootstrap drift
2. Ledger scope drift
3. Confusable-field hardening decision
4. New mixed-contract claims

**Output format:**
```
WEEK OF YYYY-MM-DD
Changed: [file list]
Lane touched: [signer | ledger | confusable | contract-boundary]
Drift found: [list or "none"]
Action required: [yes/no + what]
```

---

## File Roles

| File | Purpose | Lives in |
|------|---------|----------|
| `SECURITY_AUDIT_ADJUDICATION_2026-04-03.md` | Canonical settlement of the 2026-04-03 investigation | `assay/docs/security/` |
| `CLAIM_LEDGER.md` | Public claim boundary and proof mapping | `assay/docs/security/` |
| `SECURITY_INVARIANTS.md` | Live current-state truths | `assay/docs/security/` |
| `SECURITY_POSTURE_TODAY.md` | Short plain-English current posture | `assay/docs/security/` |
| `SIGNER_BOOTSTRAP_DECISION.md` | Current signer-bootstrap decision and reopen triggers | `assay/docs/security/` |
| `LEDGER_SCOPE_DECISION.md` | Current ledger-scope decision and stronger protocol path | `assay/docs/security/` |
| `tests/contracts/vectors/regression/` | Regression corpus for real hardening and contract work | `assay/tests/contracts/vectors/regression/` |
| Weekly delta report | Optional drift note before external review | `assay/docs/security/evidence/` |

---

## Promotion Protocol For New Issues

When a new concern appears:

1. Classify it before editing anything.
2. If it is a mixed-contract or overclaim issue, record it in the adjudication memo and do not promote it as active breakage.
3. If it changes public language, update the claim ledger, posture doc, invariants, and any relevant decision note in one sweep.
4. If it changes a current operating decision, update the decision note first, then align the rest of the current-state set.
5. If it is a real new implementation or hardening gap, add the invariant, tests, and design work needed to make it explicit.

---

## Current Short Queue

1. Optional confusable or ASCII prevalidation above JCS.
2. Stronger signer policy only if intentionally chosen and implemented.
3. Stronger ledger scope only if the full-pack protocol upgrade is intentionally chosen and implemented.

This is a settlement queue, not a fresh swarm brief.
