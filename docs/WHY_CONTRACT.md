# `assay why` — Constitutional Interrogation Contract

**Version**: 0.1.0 (matches Decision Receipt schema)
**Status**: Landed, tested, hardened
**Files**: `src/assay/why.py`, `src/assay/override.py`, `src/assay/obligation.py`
**Tests**: `tests/assay/test_circulation_loop.py` (31 tests)

## What it does

`assay why <receipt-id>` traces a Decision Receipt backward through
supersession and obligation links. It answers:

- What happened (verdict, disposition)
- Why (execution-why: what rule fired; constitutional-why: what prior judgments
  made this permissible/impermissible)
- Under what authority
- What obligations remain

## Command

```
assay why <receipt-id> [--json] [--trace]
```

- `--json` — structured JSON output
- `--trace` — follow full parent_receipt_id chain (default: depth 1)

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Receipt found, no missing links |
| 1 | Missing links detected, or receipt not found |

## Output contract (JSON)

Top-level keys (always present):

| Key | Type | Always present |
|-----|------|---------------|
| `receipt_id` | string | yes |
| `verdict` | string | yes |
| `disposition` | string | yes |
| `authority_class` | string | yes |
| `authority_id` | string | yes |
| `decision_type` | string | yes |
| `execution_why` | string | yes |

Conditional keys (present when applicable):

| Key | Type | When present |
|-----|------|-------------|
| `timestamp` | string | when receipt has timestamp |
| `decision_subject` | string | when receipt has decision_subject |
| `supersedes` | object | when receipt supersedes another |
| `constitutional_why` | object | when supersession exists |
| `obligations` | array[object] | when obligations found |
| `parent_chain` | array[object] | when parent links exist |
| `missing_links` | array[object] | when referenced artifacts not found |

## Edge relation types

Two distinct relation types, never flattened:

| Relation | Meaning | Traversal |
|----------|---------|-----------|
| `supersedes` | Override/succession — constitutional | Always followed |
| `derived_from` | Parent/lineage — causal chain | Followed with `--trace` |

These appear in JSON output:
- `supersedes.relation == "supersedes"`
- `parent_chain[i].relation == "derived_from"`

## Missing link semantics

When a referenced artifact is not found, `why` reports it honestly:

```json
{
  "missing_links": [
    {
      "referenced_id": "OB-ghost001",
      "relation": "obligation",
      "message": "Obligation OB-ghost001 referenced in receipt but not found in store"
    }
  ]
}
```

Missing link relations: `supersedes`, `obligation`, `parent`, `target` (receipt itself).

Cycles in parent chain are reported as missing links with `"Cycle detected"` message.

## Override receipt model

**Intentional compression**: An override is represented as a Decision Receipt
with `authority_class=OVERRIDING`, not a separate receipt type. This is schema
reuse, not eternal doctrine.

Override-specific fields:
- `authority_class`: `"OVERRIDING"`
- `delegated_from`: authority seat whose decision is being overridden
  (**P0 simplification** — in reality, override authority may come from a
  higher human emergency authority, not delegation from the overridden seat)
- `supersedes`: receipt_id of the overridden decision
- `obligations_created`: array of real obligation IDs (e.g., `["OB-abc123"]`)
- `decision_type`: `"human_authority_override"`
- `verdict_reason`: justification text (min 20 chars)

Overrides require:
- Non-empty `obligations_created` (overrides without review debt are rejected)
- Justification >= 20 characters
- Superseded receipt must have verdict REFUSE, DEFER, or CONFLICT

## Obligation model

**Storage**: `~/.assay/obligations.jsonl` — full-state snapshots, newest wins
per obligation_id. Not a pure event log; latest snapshot is authoritative.

**Lifecycle**:

```
open → discharged  (review receipt provided)
open → waived      (reason required)
open → escalated   (target required)
```

**Fields**:

| Field | Required | Notes |
|-------|----------|-------|
| `obligation_id` | yes | `OB-<hex>` format |
| `source_receipt_id` | yes | override receipt that created this |
| `superseded_receipt_id` | yes | original refusal being overridden |
| `created_by_actor` | yes | who caused the obligation |
| `owner` | yes | who must resolve it |
| `obligation_type` | yes | `"override_review"` |
| `severity` | yes | HIGH, MEDIUM, LOW |
| `status` | yes | open, discharged, waived, escalated |
| `created_at` | yes | ISO-8601 |
| `due_at` | yes | ISO-8601 |
| `discharge_receipt_id` | discharged | receipt proving resolution |
| `waiver_reason` | waived | why forgiven |
| `escalated_to` | escalated | target authority |
| `status_reason` | optional | human note on transition |

## Downstream consumers

1. `assay why <receipt-id>` — primary interrogation surface
2. `assay doctor --check-orphans` → `DOCTOR_OBLIGATION_001` — reports open/overdue obligations

## DOCTOR_OBLIGATION_001 contract

**Gate**: `--check-orphans` (shared with DOCTOR_ORPHAN_001, DOCTOR_CONTRADICTION_001)

**Status ladder**:

| Status | Severity | Condition |
|--------|----------|-----------|
| PASS | INFO | No open obligations |
| WARN | MEDIUM | Open obligations, none overdue |
| FAIL | HIGH | One or more overdue obligations |
| SKIP | INFO | Store unreadable or import failure |

**Evidence keys**:

| Key | Type | When present |
|-----|------|-------------|
| `open_count` | int | always (PASS/WARN/FAIL) |
| `overdue_count` | int | always (PASS/WARN/FAIL) |
| `overdue` | array[object] | FAIL — includes obligation_id, source_receipt_id, owner, due_at, severity |
| `open` | array[object] | WARN — includes obligation_id, owner, due_at, severity |
| `error` | string | SKIP |

**Fix text**: `"assay why <receipt-id>  # inspect the override chain and resolve"` (FAIL)
or `"assay why <receipt-id>  # inspect the override chain"` (WARN).

**Skip behavior**: Returns SKIP/INFO if the obligation store is unreadable or the
import fails. This is a resilience choice — the doctor check should not crash
the entire report because obligations are not yet in use. Worth revisiting if
obligations become load-bearing for CI gating.

## Known intentional compressions

1. Override as Decision Receipt (not a separate type)
2. `delegated_from` = overridden authority seat (not necessarily the legitimizing authority)
3. Obligation storage = snapshots, not event-sourced transitions
4. `assay why` accepts receipt ID only (not decision ID, episode ID)
5. Override debt is visible but not yet enforced (doesn't block future actions)
6. No contamination inheritance (downstream decisions don't inherit override taint)
7. No scar model (persistent historical markers beyond debt lifecycle)
