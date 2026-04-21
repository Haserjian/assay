# Commitment Terminal-State Membrane

**Status:** decided (paper + code landed together for the membrane surface)
**Scope:** commitment-lifecycle reader/writer code paths
**Supersedes:** the prose-only handling of revocation/amendment/supersession
implicit in Slice 1

---

## Doctrine sentence

> Kept, broken, revoked, amended, and superseded may all end a
> commitment's active life, but only kept/broken are fulfillment
> outcomes.

## Implementation invariant

> If it changes list or overdue, it must be state, not commentary.

---

## What this surface is

Before this membrane, `list` and `overdue` only knew two ways a
commitment could end its active life:

- `fulfillment.commitment_kept` — the commitment was kept.
- `fulfillment.commitment_broken` — the commitment was broken.

Every other ending — revocation, amendment, supersession — lived only
as prose (operator comments, audit notes, slack threads). A revoked
commitment still appeared in `list` as OPEN; still showed up in
`overdue`; still fired the constitutional-violation path. That made
`list` and `overdue` lie: a commitment that *the operator had ended*
still read as active.

The terminal-state membrane fixes that. It introduces one new event,
`commitment.terminated`, covering **only non-fulfillment terminal
endings** (revoked | superseded | amended), plus the projection /
summary / detector updates that make those endings machine-visible
state — not prose notes.

## Non-fulfillment terminal endings are state, not notes

A `commitment.terminated` event ends a commitment's active life with
one of three `terminal_reason` values:

- `revoked` — the commitment is withdrawn; no fulfillment, no
  replacement.
- `superseded` — the commitment is replaced by a different, newly
  registered commitment (via `replacement_commitment_id`).
- `amended` — the commitment is replaced by a revised version of
  itself. The old commitment is NOT edited in place; instead a new
  commitment is registered with `supersedes_commitment_id` pointing
  at the original, and the original receives a
  `commitment.terminated` with `terminal_reason=amended` and
  `amended_field` naming what changed.

None of these are fulfillment. The grammar is strict:

- **CLOSED** = closed by `fulfillment.commitment_kept` or
  `fulfillment.commitment_broken`. Fulfillment outcome.
- **TERMINATED** = closed by `commitment.terminated`. NOT a
  fulfillment outcome. The commitment ended its active life without a
  kept/broken judgement.
- **OPEN** = registered, no terminal event yet.

`commitment.terminated` does NOT absorb kept/broken. The existing
event types `fulfillment.commitment_kept` and
`fulfillment.commitment_broken` are untouched by this PR. No
`verified` / `breached` vocabulary has been introduced.

## Amendment terminates the original only by registering a replacement

Amendment is never an in-place mutation. The membrane refuses to
pretend a commitment can be edited after the fact. The shape is
always:

1. Original commitment receives:
   - `commitment.terminated`
   - `terminal_reason: amended`
   - `replacement_commitment_id: <new id>`
   - `amended_field: due_at | scope | owner | acceptance_terms`

2. A replacement commitment is registered separately with:
   - `commitment.registered`
   - `supersedes_commitment_id: <old id>`
   - optional `lineage_root_commitment_id` for convenience

The replacement is a new aggregate. It has its own registration seq,
its own lifecycle, its own terminal events. The original is
TERMINATED; the replacement starts OPEN. Until the replacement itself
closes or is terminated, it stays in the active list.

## Lineage is stored as immediate edges

Supersession forms a chain (A → B → C → ...). The membrane stores
ONLY immediate edges:

- The registration receipt for the successor may carry
  `supersedes_commitment_id` naming its direct predecessor.
- The termination receipt for the predecessor may carry
  `replacement_commitment_id` naming its direct successor.

Either edge is sufficient. If both are present they refer to the same
edge and the projection deduplicates. Chains are NEVER duplicated onto
each event. `lineage_root_commitment_id` is allowed as a convenience —
when the emitter knows the chain's root, it can record it — but
consumers must be able to reconstruct chains by walking edges. The
projection's `supersession_edges` list is the operator's view of the
lineage graph.

## First terminal wins

A commitment has at most ONE terminal event across all three types:

- `fulfillment.commitment_kept`
- `fulfillment.commitment_broken`
- `commitment.terminated`

The emit path enforces this. If a terminal event already exists for a
commitment_id, a second terminal event is refused:

- **Same `idempotency_key` on `commitment.terminated`** — treated as a
  replay. NO event is written; the emitter returns a no-op signal. Same
  key = same operation.
- **Different `idempotency_key`, or different terminal type** —
  `TerminalFulfillmentError` is raised at emission time. NO event is
  written. The first terminal keeps the commitment.

This rule is symmetric: kept cannot replace terminated, terminated
cannot replace broken, etc.

## Runtime authority

Four `authority_mode` values are schema-reserved:

- `self` — the author is terminating their own commitment. **Only this
  is accepted in the current probe.**
- `owner`, `policy`, `external` — reserved for future delegation work.
  The schema permits them; the emit path rejects them with
  `AuthorityModeUnsupportedError`. No event is written.

Values outside the enum fail schema validation before reaching the
emit-path runtime check. No event is written on schema failure.

## Identity and idempotency

The membrane distinguishes `commitment_id` (aggregate identity) from
`idempotency_key` (operation identity). They are stable on both sides
but derived independently.

**commitment_id** — prefer an emitter-authored stable id when
available. Otherwise derive:

```text
sha256(emitter_namespace || "\0" || actor || "\0" ||
       plan_slot_key || "\0" || normalized_first_authored_text)
```

**idempotency_key** — derive:

```text
sha256(emitter_namespace || "\0" || operation_id || "\0" ||
       commitment_id || "\0" || event_type)
```

Conflict rules:

- Same `idempotency_key` = no-op.
- Same `commitment_id` with materially different text = **conflict**,
  not silent replacement. The emitter must detect this and either
  allocate a new id or refuse.

### Normalization of `normalized_first_authored_text`

- Unicode NFC normalization.
- Trim leading and trailing whitespace.
- Collapse internal whitespace runs to a single space (any whitespace
  character collapses to one ASCII space).
- **No case folding.** "Ship the report" and "ship the report" are
  different commitments.

The normalization is applied ONLY to the id-derivation input. The
stored `text` field round-trips as authored.

## Projection / list / overdue behavior

The shared lifecycle projection
(`src/assay/commitment_projection.py`) now carries:

- `closures` — fulfillment closures (kept | broken), keyed by
  commitment_id.
- `terminations` — `commitment.terminated` events, keyed by
  commitment_id (first-wins).
- `supersession_edges` — immediate predecessor→successor edges across
  both registered-side and terminated-side declarations, deduplicated.

`list` summaries carry three states: OPEN, CLOSED, TERMINATED.
TERMINATED summaries also expose `terminal_reason`, `termination_seq`,
and `replacement_commitment_id`. `is_overdue` is always False for
TERMINATED (same rule as CLOSED — ended commitments are never
overdue).

`overdue` excludes TERMINATED commitments. The detector's filter is:

```text
registered AND not-closed AND not-terminated AND due_at < now
```

## Storage convention

`commitment.terminated` and the extended `commitment.registered`
fields write through the same `_store_seq` allocator and storage
envelope used by existing commitment events. There is no parallel
write path. Schema files live next to the existing commitment schemas
at `src/assay/schemas/`.

## Probe scope meta-receipt

`probe.scoped` is a meta-receipt that declares a probe's boundary.
Required fields: `probe_name`, `scope`, `owner_equals_author`,
`delegation_allowed`, `external_ingestion_allowed`,
`allowed_event_types`, `membrane_version`, `code_commit`,
`emitted_at`.

This PR does NOT wire the full claude-organism self-authored emitter;
it only makes the membrane + projection + probe schema real and
testable. Wiring the actual emitter is a next slice.

## What this membrane does NOT do

- No delegation. `authority_mode` values other than `self` are
  rejected until delegation work lands.
- No Jira/Linear ingestion.
- No manager assignment flows.
- No renaming of existing `commitment.registered` /
  `fulfillment.commitment_kept` / `fulfillment.commitment_broken`
  vocabulary.
- No full supersession-chain duplication — immediate edges only.
- No in-place mutation of a live commitment.
- No treating revocation as fulfillment.
- No buyer-demo copy change (`docs/demo/commitments_slice1_demo.md` is
  untouched).
