# Invariant Accounting v0

Status: Draft
Created: 2026-04-30

Invariant accounting is the first-class Assay layer for asking whether a
declared condition survived an episode strongly enough to inform downstream
consequence.

It is intentionally smaller than Guardian, proof packs, semantic delta, or
anchoring.

## Core Claim

Assay is not only a receipt packager. It is an invariant-accounting system.

An episode produces observations, claims, actions, receipts, and sometimes
refusals or promotions. Invariant accounting gives those artifacts a common
evaluation surface:

```text
InvariantSpec -> InvariantEvaluation -> GuardianDecision
```

In v0, this document defines the first two objects. Guardian integration remains
downstream.

## Why This Exists

Existing Assay code already has invariant-like checks in verifier registries,
decision receipts, proof packs, and Guardian helpers. Those checks are real, but
they are not yet represented by a common accounting object.

The missing bridge is a small object that can say:

- what invariant was evaluated
- what evidence was used
- what proof tier was available
- whether the invariant passed, failed, was unknown, or was not applicable
- what provisional consequence Guardian may need to consider

That bridge lets future Guardian authorization react to structured evaluations,
not prose or scattered one-off checks.

## Relationship To Guardian

Assay evaluates invariant survival.

Guardian authorizes consequence.

Invariant accounting does not decide whether to execute, refuse, route, promote
memory, or mutate policy. It produces structured `InvariantEvaluation` objects
that Guardian can later consume.

For v0, Guardian behavior is unchanged.

`guardian_action` values carried on v0 evaluations are provisional strings. They
are hints for future Guardian integration, not a runtime Guardian decision
object and not a new Guardian action vocabulary.

## Relationship To Proof Packs

Proof packs preserve evidence integrity and support offline verification of the
pack contract.

Invariant accounting interprets selected evidence against declared invariant
specs.

The two layers are complementary:

- proof packs answer whether the evidence bundle was preserved
- invariant evaluations answer whether a declared condition survived according
  to that evidence

Proof packs do not become a blanket verifier for every invariant by existing.
Invariant evaluations must name their evidence and scope.

## Proof Tier Continuity

This v0 intentionally reuses the existing Assay/Loom proof-tier vocabulary:

- `DRAFT`
- `CHECKED`
- `TOOL_VERIFIED`
- `ADVERSARIAL`
- `CONSTITUTIONAL`

It does not introduce a second runtime proof universe such as `T0` through `T5`.

If a broader authorization ladder is needed later, it should be introduced as a
separate `AuthorizationTier` or as an explicit documented mapping. It must not
silently replace existing proof-tier semantics.

## V0 Object Model

`InvariantSpec` says what should be evaluated.

`InvariantEvaluation` records the result of evaluating one spec against one
evidence surface.

`EvidenceRef` names the evidence used by an evaluation.

V0 statuses are:

- `PASS`
- `FAIL`
- `UNKNOWN`
- `NOT_APPLICABLE`

V0 severities are:

- `INFO`
- `WARN`
- `BLOCKING`

## First Evaluator

The first concrete evaluator is `evaluate_latency_budget`.

It evaluates:

```text
measurement.metric == "wall_clock_ms"
tolerance.max_ms is numeric
receipt.wall_clock_ms is numeric
```

Malformed inputs must not crash the evaluator. They produce structured
`UNKNOWN` or `NOT_APPLICABLE` evaluations.

This evaluator is intentionally boring. Latency is deterministic and lets the
accounting path become executable before semantic-delta or provider-routing
logic exists.

## Deferred Layers

Semantic delta is a downstream evidence modality. It should feed invariant
evaluation later, but it is not required for v0.

Anchoring is a downstream evidence-hardening layer. It may strengthen durability,
but it does not replace invariant evaluation or Guardian authorization.

Blockchain is not part of v0.

MemoryGraph and Quintet remain downstream consumers/evolvers of evaluated
consequence. They are not modified by this slice.
