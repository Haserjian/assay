# Decision Escrow

Prefer the styled public page: [decision-escrow.html](decision-escrow.html).

This document describes the protocol model underlying Assay. For the public product overview and the getting-started workflow shipping today, start with [the main page](index.html).

> **Current trust tier: T0 (self-signed)** | Next: T1 (time-anchored)

**Agent actions don't settle until they're verified.**

Decision Escrow is the protocol model behind Assay. It treats every consequential AI action as a transaction that moves through four phases before it settles: authorization, execution, verification, and downstream trust update.

## The four phases

1. **Preflight permit** — authorize the action before execution.
2. **Execution with evidence** — emit receipts while the action runs.
3. **Settlement** — verify integrity, claims, and completeness.
4. **Reputation update** — feed verified outcomes back into trust state.

## What exists today

Assay ships the execution-evidence and settlement layers today:

- `assay patch` + `assay run` emit signed receipts for supported LLM calls.
- `assay verify-pack` checks integrity and claims.
- `assay diff --gate` enforces regression and budget thresholds.

## What Assay proves

- Evidence was not altered after creation
- Contracted call sites emitted receipts under a completeness contract
- Declared checks passed or failed honestly against authentic evidence

## What it does not prove by itself

- That a dishonest operator could never fabricate a run
- That every possible call site was instrumented
- That local timestamps are externally anchored
