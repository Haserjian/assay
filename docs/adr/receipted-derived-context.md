# ADR: Receipted Derived Context

## Status

Proposed

## Decision

Loom/Assay will treat derived cognitive context as receipted artifacts.
Derived context includes chunks, summaries, embeddings, symbol edges, repo maps,
MemoryGraph projections, and retrieval index rows.

A derived artifact is trusted only when it can identify:

- source snapshot(s)
- input artifact(s), if any
- transform name/version
- transform code hash
- config hash
- model, prompt, or policy hash when applicable
- runtime/environment hash when applicable
- output hash
- receipt
- derivation verification level

## Trust Tier

The MVP derived-context receipt path is T0: structural-validation and
digest-locked self-attestation. Receipt IDs are recomputed from JCS canonical
payload bytes, output hashes are checked, and deterministic source chunks can be
recomputed, but these receipts are not independently signed or Sigstore
verified in this slice.

Downstream consumers must not treat `derived.*` receipts as T1 or CI-signed
evidence unless a later integration explicitly wraps them in a signed Assay
proof-pack or equivalent verifier path.

## Law

All derived context must be content-addressed, lineage-bearing, receipt-backed,
and reproducible or honestly marked non-reproducible from source snapshots plus
versioned transforms.

Caches accelerate. Receipts and committed state authorize.
Indexers propose. Guardian commits.

## Rationale

Fresh context is useful but dangerous if it is not explainable. The system must
be able to answer why an artifact exists, what produced it, whether it is stale,
and whether it can be reproduced.

## Authority

Caches are not authority. External indexers are not authority.
Receipts, source snapshots, and committed graph state are authority.

## Architecture

Derived context uses a staged flow:

scan -> plan -> derive -> receipt -> verify -> Guardian gate -> commit

The indexer proposes changes. Guardian controls commitment.

## Integration Status

`NativeAssayBackend` is pre-consumer foundation in this slice. The hidden
experimental CLI exercises the planner/store/verifier path, and tests assert
that the native backend satisfies the `DerivedBackend` protocol, but no
production caller outside `assay.derived` consumes that protocol yet.

The first non-test integration must name its caller before this work is claimed
as a wired backend integration.

## CocoIndex

CocoIndex and similar tools may be evaluated as replaceable backends for
incremental processing. They may not become constitutional infrastructure unless
they satisfy the Assay receipt and lineage contract.

## Consequences

This may be slower than direct indexing, but it preserves auditability,
rebuildability, and trust boundaries.

The first native implementation intentionally excludes CocoIndex, embeddings,
LLM summaries, provider calls, background daemons, live watchers, and MemoryGraph
writes.
