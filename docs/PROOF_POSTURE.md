# Proof Posture

**Status:** Normative
**Modules:** `claim_verifier.py`, `residual_risk.py`, `proof_debt.py`, `proof_posture.py`
**Canonical specimen:** `tests/assay/fixtures/proof_posture/canonical_specimen.json`

---

## Four epistemic states

Every verified claim set produces a proof posture with exactly four categories:

| State | Meaning | Example |
|---|---|---|
| **proven** | Claim passed verification AND falsifier was executed and survived | "Model calls exist" with deletion test run |
| **supported but capped** | Claim passed verification BUT cannot reach strong proof status | "Auth preserved" with no kill test named |
| **tolerated** | Risk is acknowledged, has owner + expiry + next cheapest evidence | "Coverage gap tolerated until next sprint" |
| **owed** | Constitutional obligation not yet fulfilled | "Name a falsifier" / "Assign owner" |

These four states are the complete grammar. Do not add synonyms.

---

## Falsifier statuses

| Status | Meaning |
|---|---|
| `not_required` | Warning-severity claim, or enforcement not active |
| `absent` | Critical claim with no falsifier named |
| `named` | Falsifier described but not yet executed |
| `executed_passed` | Falsifier was run; claim survived disproof |
| `executed_failed` | Falsifier was run; claim was disproved |

---

## Tier cap decision table

Caps are applied via `TIER_CAP_TABLE` in `claim_verifier.py`. The table is the single source of truth.

| Severity | Falsifier Status | Cap? | Reason |
|---|---|---|---|
| warning | any | No | Warnings are never capped |
| critical | not_required | No | Enforcement not active |
| critical | absent | **Yes** | No named falsifier |
| critical | named | **Yes** | Falsifier not executed |
| critical | executed_passed | No | Full proof eligible |
| critical | executed_failed | **Yes** | Claim disproved |

Cap is an admissibility downgrade, not a failure. The claim still passes or fails on its own evidence. The cap constrains how strongly the result can be relied upon.

---

## Proof debt sources

Proof debt accrues from **exactly three sources**. This list is closed.

| Source | Trigger | Severity | Repayment |
|---|---|---|---|
| `missing_evidence` | Critical claim failed verification | severe | Attach evidence satisfying the claim |
| `missing_falsifier` | Critical claim has no named kill test | moderate | Name the cheapest disproof test |
| `unowned_risk` | Residual risk missing owner or expiry | severe (no owner) / moderate (no expiry) | Assign owner and/or expiry condition |

Do not add sources for generic unease, low confidence, weak wording, or reviewer vibes. Those belong elsewhere.

---

## Disposition

Computed from posture components:

| Disposition | Condition |
|---|---|
| `verified` | All claims pass, no caps, no blocking risk, no severe debt |
| `supported_but_capped` | All claims pass, some tier-capped, no blocking risk |
| `incomplete` | Critical claims failed, or severe debt exists |
| `blocked` | Blocking residual risk prevents promotion |

Priority: blocked > incomplete > supported_but_capped > verified.

---

## Residual risk structure

Each item requires all seven fields:

- `claim_id` — which claim this risk relates to
- `risk_statement` — what is unresolved
- `why_tolerated` — why this is acceptable for now
- `owner` — who is responsible (empty = unowned = debt)
- `expiry_condition` — when this tolerance expires (empty = no expiry = debt)
- `next_cheapest_evidence` — what would most cheaply reduce this risk
- `blocking_on_merge` — whether this risk prevents promotion

Critical failures are NOT residual risk. They are failures. Do not smuggle failure through the residual risk side door.

---

## Vocabulary discipline

These terms are normative. Do not substitute.

| Use | Do not use |
|---|---|
| proven | verified, confirmed, validated |
| supported but capped | provisional, weak-pass, soft verified |
| tolerated | managed, accepted, known |
| owed | pending, deferred, backlogged |
| absent | missing, none, empty |
| executed_passed | survived, confirmed, cleared |
| executed_failed | disproved, contradicted, killed |
| incomplete | needs work, partially done, almost |
| blocked | held, paused, on hold |
