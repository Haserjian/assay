# Commitment Ordering — Global vs Per-Commitment

**Status:** decided
**Scope:** gates Slice 2 (obligation-side) storage shape
**Applies to:** commitment-lifecycle reader/writer code paths
**Supersedes:** implicit assumption during Slice 1 that global total order was
the load-bearing primitive

---

## The question

Slice 1 landed `_store_seq` as a store-wide monotonic integer, stamped
atomically via `fcntl.flock` on `<base_dir>/.store_seq` for every write.
The detector, explainer, and summarizer all derive closure state by
walking receipts in `_store_seq` order.

Before Slice 2 (obligation side) commits to a storage shape, we have to
answer:

> Does commitment closure correctness require a cross-commitment total
> order, or only per-commitment order?

This memo is the decision. It does not change code; it ratifies the
semantic layering the code will be refactored to make explicit.

---

## Which invariants actually require cross-commitment total order?

None of the commitment-closure invariants require it. Walking the
evidence produces:

| Commitment-closure invariant | Cross-commitment order needed? |
|---|---|
| A terminal closes commitment `C` only if `C` was already registered | No — single-commitment causal chain |
| A terminal closes `C` only if a prior `result.observed` has refs including `C` | No — depends only on receipts touching `C` |
| A commitment has zero or one terminal fulfillment | No — scoped to that commitment |
| A terminal encountered before its anchor does not close | No — ordering need is local |
| `due_at` comparison for overdue detection | No — per-commitment timestamp + `now` |
| Mixed/corrupt store fails closed | Cross-record, but orthogonal to ordering |

The closure rule is local. Cross-commitment order adds no constitutional
strength to the commitment wedge.

## Which invariants only need per-commitment order?

Every closure invariant above. Each is a function of the receipts
naming a single commitment (plus the observations those receipts cite),
not of unrelated commitments elsewhere in the store.

## Where global order IS actually useful (but not required)

Global order provides operator-facing affordances that are nice-to-have,
not correctness-bearing:

- Deterministic `assay commitments list` ordering (currently done by
  `registered_seq`, which is a global number but could equally be any
  stable per-commitment sort)
- Audit-replay: "walk the store in append order" for forensic or
  debugging passes
- Detecting tampering: within-file seq regression surfaces at integrity
  check time
- Cross-commitment causal questions ("did commitment A's closure happen
  before commitment B was even registered?") — potential future query,
  not a current contract

All of these are satisfied by a monotonic **append id**, not by a
semantic global order. An append id is a storage primitive; a global
semantic order would be a doctrinal primitive.

## What does global order cost?

Committing to cross-commitment total order as a *semantic* requirement
creates ongoing costs:

| Dimension | Cost |
|---|---|
| Locking | Every write must serialize against every other write, across every commitment. Current `fcntl.flock` on `.store_seq` already pays this — but pays it forever. |
| Migration | Any sharding, partitioning, or per-aggregate streaming retrofit is blocked unless the global order is rebuilt. |
| Indexing | A single global index is required. Per-commitment indexes alone cannot be authoritative. |
| Repair | Mixed-state or cross-process tears require restoring the global counter before any writes resume (Slice 1's `MigrationRequiredError` already does this). |
| Scaling | One writer at a time per store, globally. Throughput ceiling is the seq-file lock. |

If commitment closure actually needed global order, these costs would be
the price of correctness. It doesn't. Paying them for audit/replay
convenience alone is a poor trade.

## What does per-commitment-only order cost?

Committing to *only* per-commitment order — no append id, no global
sequence — also has costs:

| Dimension | Cost |
|---|---|
| Cross-commitment reports | `list` needs a stable sort key that isn't causal; wall-clock or UUID tie-break |
| Global replay | Whole-store replay loses a canonical iteration order |
| Tamper detection | Within-file seq regression is no longer a signal |
| Debugging | "What order did these writes actually land in?" becomes harder to answer |
| Integrity errors | Fewer structural cross-checks available at scan time |

Per-commitment-only is *semantically* clean but operationally weaker.

## Slice 2 obligations: different shape from Slice 1 commitments?

An obligation — as distinct from a Slice 1 commitment — is an
**inherited duty**: forward-looking, possibly cross-episode, potentially
derived from a parent commitment or from a constitutional event such
as an authority override or a policy change. (See the Slice-2 design
notes in `memory/project_obligation_namespace_collision.md`; the
obligation noun's precise semantics are separately gated by that
namespace adjudication.)

For ordering purposes, this memo only needs the following properties
of any Slice-2 obligation shape — none of which require cross-aggregate
total order:

- An obligation may be inherited from a parent commitment; its causal
  predecessor lives in that parent's per-commitment chain, not in the
  global store.
- An obligation may cross process / episode boundaries; its relevant
  ordering question is **not** "which other obligation was written
  first in the whole store" but "was this obligation active when that
  commitment was registered" — a per-pair question answerable by
  comparing the two aggregates' own chains, or by comparing append-id
  timestamps as a tie-breaker.
- Obligation closure (discharge / waiver / supersession) is per-
  obligation, exactly like commitment closure.

Slice 2 does not need a stronger ordering primitive than Slice 1.
It needs the same primitive applied to a different noun, plus the
ability to link obligations to commitments via typed edges — the same
`{kind, id}` reference shape `result.observed.references` already uses
in-repo today.

## Decision: **hybrid**

```
Semantic layer   : per-commitment / per-aggregate order
Storage layer    : monotonic append id (_store_seq) for audit/replay
                   and deterministic whole-store traversal
```

Expanded contract:

1. **Lifecycle semantics project per commitment.** Closure of commitment
   `C` is a function of receipts naming `C` (and observations those
   receipts cite). No reader may reach a closure decision by consulting
   receipts that mention unrelated commitments.

2. **`_store_seq` is immutable witnessed append order.** It stays
   stamped atomically at write time, flocked across processes,
   validated strictly on every write, and — once stamped on an
   on-disk receipt — is never rewritten. Its role is:
   - ordering the single-pass scan deterministically
   - tie-breaking within and across aggregates
   - audit/replay iteration
   - tamper detection (duplicate / within-file regression)
   - NOT: expressing a semantic global happens-before relation
     between unrelated aggregates
   - NOT: a slot that repair or migration may recompute (see
     **Repair doctrine** below)

3. **Cross-commitment views may sort by `_store_seq`.** `assay
   commitments list` and similar ordered views are allowed to use it
   as a deterministic sort key. They must not use it to answer
   closure questions about any individual commitment.

4. **Slice 2 obligations use the same primitive.** No separate seq,
   no separate counter. Obligation closure is per-obligation. An
   obligation inheriting from a commitment carries a typed ref to
   that commitment, same as `result.observed.references` today.

5. **`_store_seq` is immutable witnessed append order. Repair must
   not rewrite it.** Future repair tools may rebuild derived views /
   indexes, emit superseding receipts, or introduce a distinct
   reconstructed-traversal marker (e.g. `repaired_seq`,
   `canonical_seq`, or a repair receipt that maps original
   `_store_seq` values to reconstructed order). What repair MUST NOT
   do is mutate existing `_store_seq` values — that would destroy the
   audit property the field names. Two concepts, kept separate:

   - `_store_seq` answers: "what order did this store witness
     appends?" — the historical fact
   - a future reconstructed/canonical order would answer: "what
     order should a repaired traversal use?" — a derived view

   Collapsing the two into one mutable field is the loophole this
   clause explicitly closes.

## Repair doctrine

Extracted and promoted from clause 5 because this is the place the
memo most needs to be unambiguous for future contributors:

> `_store_seq` answers "what order did this store witness appends?"
> A future reconstructed order answers "what order should a
> repaired/canonical traversal use?" **Those are different fields,
> different contracts, and must not be the same storage slot.**

What a future repair tool MAY do:

- Emit superseding receipts (new `_store_seq`, larger than any current)
- Build / rebuild derived indexes or projections
- Write a repair receipt that maps original `_store_seq` → reconstructed
  traversal order as a separate stored field
- Quarantine malformed receipts in a side-file and document which
  `_store_seq` values are quarantined

What a future repair tool MUST NOT do:

- Overwrite `_store_seq` on any existing on-disk receipt
- Reuse the name `_store_seq` for anything other than the original
  witnessed append position
- Rely on readers ignoring `_store_seq` "because the repair tool says so"

The audit property of `_store_seq` is exactly that nothing — including
repair — rewrites it. If this contract ever needs to break, it will
be via explicit new fields and a new memo, not by quiet mutation.

## What this memo does NOT decide

- **Sharded storage.** The hybrid permits it; this memo does not
  authorize it. Any move to per-aggregate sharding requires its own
  design pass (locking contract, repair story, migration path).
- **Database backend.** SQLite vs Postgres vs flat JSONL is out of
  scope. The primitive is `_store_seq` regardless.
- **Repair tooling shape.** Still deferred to a later slice. Mixed/
  corrupt stores still fail closed; an explicit repair CLI is future
  work.
- **Cross-aggregate causality queries.** Not required, not forbidden.
  If a future slice needs them, it must build them on the append id,
  not claim a semantic meaning `_store_seq` doesn't have.

## Consequences / follow-ups

- **Projector refactor** (`project_commitment_lifecycle(store)`) becomes
  safer to land: it consolidates the *per-commitment* projection code
  path shared by detector / explainer / summarizer, without baking in
  global-semantic-order assumptions this memo rejects.
- **Slice 2 design** now has a stable primitive to assume: same
  `_store_seq` envelope, same `_iter_all_receipts`, same fail-closed
  integrity rules. Obligation lifecycle uses the same mechanisms
  scoped to its own id.
- **Documentation of `_store_seq`** (module docstrings in
  `commitment_fulfillment.py` and `store.py`) should be updated in the
  projector-refactor PR to name its role as "witnessed append order,"
  not "total semantic order." Explicit so future contributors don't
  re-infer the stronger claim.

## Non-goals for this memo

- This memo does not add code.
- This memo does not change existing tests.
- This memo does not introduce a new storage primitive.
- This memo does not unblock or schedule Slice 2 on its own; Slice 2
  remains blocked by the pre-existing `src/assay/obligation.py`
  namespace collision (see
  `~/.claude/projects/-Users-timmymacbookpro/memory/project_obligation_namespace_collision.md`).

## Summary sentence

> `_store_seq` is a **storage** primitive that provides deterministic
> audit/replay order. It is **not** a semantic global order.
> Commitment lifecycle invariants are per-commitment. Slice 2
> obligations use the same shape.
