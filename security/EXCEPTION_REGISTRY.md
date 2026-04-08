# Assay Exception Registry

Temporary, controlled deviations from security invariants.

An exception is NOT a permanent waiver. It is a dated, approved, bounded decision
with an expiry date and compensating controls. It prevents quiet bypasses by forcing
the decision to be explicit, reviewed, and time-boxed.

**If no exception exists for a BROKEN invariant, that invariant is simply broken.**
The registry does not normalize broken things — it tracks known deviations
that have been deliberately accepted for a bounded period.

---

## Active Exceptions

*None currently registered.*

---

## Exception Format

```yaml
id: EXC-001
invariant: INV-XX
title: Short description of the exception
status: ACTIVE  # ACTIVE | EXPIRED | WITHDRAWN
granted_by: "@github-handle"
granted_date: "YYYY-MM-DD"
expiry_date: "YYYY-MM-DD"  # must be set; no open-ended exceptions
rationale: >
  Why this exception is acceptable right now.
  Must be specific, not generic ("we'll fix it later" is not a rationale).
compensating_controls:
  - What other control partially mitigates the risk during the exception window.
  - A second control if available.
review_trigger: >
  What would cause early review/withdrawal (e.g., a customer demo using this claim,
  a new attack vector discovered, a dependent system changing).
claim_impact:
  - "C-XX is blocked from use during this exception window"
  - "C-YY remains valid because compensating controls cover it"
```

---

## Expiry Protocol

On the `expiry_date`:
1. If the invariant is now ENFORCED — close the exception (move to Closed section).
2. If still BROKEN — either fix it or explicitly renew with updated rationale.
3. Renewal requires a fresh `granted_by` and a new `expiry_date`.
4. No automatic rollovers. Expired exceptions do not remain active.

---

## Closed Exceptions

*None yet.*
