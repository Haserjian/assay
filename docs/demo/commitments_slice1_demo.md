# Commitments — Slice 1 Demo Packet

Buyer-facing packaging of the Slice 1 commitment wedge. Intended for a live
demo, a pilot conversation, or an outbound deck. No marketing exaggeration.
Claims that cannot be verified in the code today are labelled as such.

---

## 1. Product claim (one sentence)

> We record what was promised, what actually happened, and whether the
> promise was kept — as structured, order-enforced evidence that refuses
> to lie about closure.

---

## 2. What the commitment wedge does

Most audit logging systems tell you *what happened*. The commitment wedge
tells you *what was promised, what happened, and whether the promise was
kept* — and enforces the distinction in storage so a "closed" verdict
cannot be fabricated by a single unanchored terminal log entry.

Three things it refuses to do, by construction:

- It refuses to close a commitment on the strength of a nearby observation
  that didn't explicitly reference it.
- It refuses to close a commitment based on an observation appended *after*
  the closing receipt (no retroactive legitimization).
- It refuses to pretend a corrupt or mixed store is clean. Integrity
  failures surface; they do not become "no overdue items found."

---

## 3. The four-event lifecycle

```
commitment.registered          — "We promise X by Friday."
result.observed                — "This happened." (non-adjudicating)
fulfillment.commitment_kept    — "The commitment was kept."     (terminal)
fulfillment.commitment_broken  — "The commitment was broken."   (terminal)
```

Key doctrinal point: **`result.observed` never closes a commitment on its
own.** Only a terminal fulfillment receipt does — and only if, at its
encounter point in receipt order, the commitment is already registered
AND some prior `result.observed` explicitly referenced it.

This separation is what makes the packet legible to an auditor who is
skeptical of "we logged it, therefore it's true."

---

## 4. Three demo commands

```
assay commitments list                    # all commitments with state + OVERDUE marker
assay commitments overdue                 # filtered: OPEN past due_at
assay commitments explain <commitment-id> # single-commitment timeline + decision
```

All three:

- read-only (never mutate store state, never emit receipts)
- consume the same underlying projection (no drift between views)
- fail closed on corrupt stores (exit nonzero, surface the integrity error)
- support `--json` for structured output and `--base-dir PATH` for
  inspecting a specific store

---

## 5. 2-minute demo script

Prerequisites: an `AssayStore` directory with at least one committed-kept
chain and at least one open overdue commitment. (If you don't have one,
the script below builds one from scratch in ~15 lines of Python.)

**[0:00] Set the frame.**
> "I'll show you three commands. They all read the same receipt store.
> Their job isn't to be impressive individually — it's to prove that the
> store itself encodes the difference between 'we promised', 'we observed',
> and 'we can prove the promise was kept.'"

**[0:15] `assay commitments list`.**
Show a mixed store: a closed commitment, an open commitment past due, an
open commitment with future due date, one with no due date at all.

> "Four commitments. One closed — you can see the fulfillment receipt seq
> that closed it. One marked OVERDUE — past due, no closure. One open,
> not overdue. One perpetual, no due date, also open."

**[0:30] `assay commitments overdue`.**
Same store, filtered.

> "Same underlying scan. Filter to just the overdue ones. No other change
> in semantics. This is the view an auditor, an oncall rotation, or a
> pilot-readiness review would pull first."

**[0:45] `assay commitments explain <id>` on the closed one.**

> "For a single commitment, we produce a per-receipt timeline and a plain-
> text decision. Read this bottom-up: the registration, the observation
> that referenced the commitment, the terminal that closed it. The
> decision names the exact sequence numbers involved — not an
> interpretation, a citation."

**[1:15] Now the interesting one: `assay commitments explain <id>` on
an open overdue one with a deliberately forged terminal.**

Set this up beforehand: write a `fulfillment.commitment_kept` receipt via
direct append (bypassing the guarded emitter) before the matching
`result.observed` exists.

> "This commitment has what looks like a 'kept' receipt naming it. But
> the store refuses to count it as a closure. You can see why in the
> timeline — the terminal appears before any observation anchored it to
> this commitment. The system says: OPEN, and tells you exactly which
> anchor is missing."

**[1:45] Close.**

> "This is the core demo. Three commands, one store, one truth contract.
> What we haven't shown — cryptographic signatures on these receipts, a
> verification packet portable to a third party — is next planned work.
> We can walk through the roadmap for that next."

---

## 6. Pilot narrative

> **"Prove what was promised, what happened, and what slipped."**

Target pilot shape:

- A team making technical or policy commitments (delivery dates, SLA
  commitments, internal-review deadlines, release-readiness promises,
  compliance attestation commitments, etc.)
- One week of live use: emit `commitment.registered` when a promise is
  made, `result.observed` when work lands, and a terminal fulfillment
  when the commitment is resolved
- End-of-week report: `assay commitments list` + `assay commitments overdue`
- Honest conversation about what the tool caught that the team's existing
  processes didn't — and what it flagged that turned out to be noise

What the pilot proves (if it works):

- Structured promise-tracking with zero ambiguity between "we told someone
  this would happen" and "this happened"
- A single clever terminal receipt cannot close a commitment: the guarded
  emit path refuses it, and the readers refuse to count an unanchored
  terminal even when it is written directly to the store
- Overdue items surface by construction, not by process discipline

What the pilot does NOT prove:

- Cryptographic non-repudiation of the receipts outside the local store
  (see §7)
- Cross-organization verifiability
- Any legal / regulatory sufficiency claim

---

## 7. Current truth table

Brutally honest. Verified against `origin/main` at `31bddfc` before
writing this packet.

| Claim | Status in repo today |
|---|---|
| Commitments are registered as explicit first-class receipts | **shipped** (`commitment.registered` in `commitment_fulfillment.py`, JSON schema in `schemas/`) |
| Results are recorded separately, never as closures | **shipped** (`result.observed` is non-adjudicating; the dataclass strips `fulfills`/`closes` keys defensively) |
| Fulfillment is adjudicated separately from observation | **shipped** (`fulfillment.commitment_kept` / `commitment_broken`, each requires an explicit anchor edge) |
| CLI exposes `list` / `overdue` / `explain` | **shipped** (as of PR #85) |
| Closure semantics are anchor-edge-enforced at write time | **shipped** (emit path calls `_assert_commitment_exists` + `_assert_result_anchors_commitment`) |
| Closure semantics are order-aware (no retroactive legitimization) | **shipped** (Slice 1 review rounds R2–R7 closed this) |
| Fail-closed corruption behavior (malformed JSON / mixed / duplicate `_store_seq`) | **shipped** (`_iter_all_receipts` raises; all three readers honor the contract) |
| Commitment receipts are emitted to the append-only store | **shipped** (`store.append_dict` stamps `_store_seq` under cross-process `fcntl.flock`) |
| Commitment receipts have integrity-checked storage order | **shipped** (within-file `_store_seq` regression is an integrity error; not cryptographic signing) |
| Commitment receipts are cryptographically signed (ReceiptV2) | **not yet** — ReceiptV2 signing infrastructure exists at `src/assay/_receipts/v2_sign.py`, but none of the four commitment receipt types are wired to it today |
| Commitment receipts are externally verifiable (independent of the issuing store) | **not yet** — consequence of the previous row; signing is the prerequisite |
| Commitment receipts fit into a proof pack / witness bundle | **partially** — the proof-pack pipeline exists (`proof_pack.py`, witness-bundle schema); commitment receipt types are not currently included in pack generation by default |
| Hypothesis property tests lock terminal-closure invariants | **shipped** (PR #84: "no sequence of valid writes produces two valid terminal closures") |
| Adversarial closure tests (hostile order, wrong anchor, malformed due_at) | **shipped** (PR #85 + PR #87 + PR #89 parity suite) |
| Projection-level parity (detector / explainer / summarizer agree) | **shipped** (PR #87 + PR #89) |
| Slice 2 obligations (inherited duties, discharge/waiver/escalation) | **not yet** — blocked on the `src/assay/obligation.py` namespace collision, not on ordering doctrine (PR #86) |

---

## 8. Explicit caveats

These are things we should say out loud in any live conversation, not
footnote in a deck appendix:

- **"Signed" is not yet accurate for commitment receipts.** Say
  "structured, tamper-evident within the issuing store" instead. The
  ReceiptV2 signing path exists; wiring commitment receipt types to it
  is a scoped next-PR effort (small), but it has not happened.
- **"Externally verifiable" follows from signing.** Until signing lands,
  the evidence is tamper-evident *against someone modifying the store
  out-of-band after the fact* — not *against a counterparty who controls
  the store*. That is a real distinction and worth saying.
- **Slice 2 obligations are not started.** An obligation in this
  codebase is different from an obligation in the Loom/organism-level
  doctrine; the namespace is contested in `src/assay/obligation.py`
  (override-debt semantics already claim it). This is a naming decision
  before it is a code decision.
- **The "three commands" surface is narrow.** It does exactly what's
  described. It does not try to be a task manager, an issue tracker, a
  compliance dashboard, or a Guardian-grade governance engine. That
  narrowness is deliberate.
- **Pilot caveats:**
  - We do not yet offer external-witness anchoring (RFC 3161 or
    similar) for commitment receipts.
  - We do not yet offer counter-signing flows (multi-party attestation
    on a single commitment).
  - We do not yet offer key rotation tooling scoped to the commitment
    stream.
- **The storage primitive is local `fcntl.flock`.** This is correct for
  a single-host deployment. Multi-host deployments would need either
  single-writer discipline or a repair/reconciliation design we have
  not built yet. The ordering memo (`docs/doctrine/COMMITMENT_ORDERING.md`)
  is explicit about this boundary.

---

## 9. What's safe to say externally

Short version — direct quotes you can use without hedging.

- "Assay records what was promised, what happened, and whether the promise
  was kept, as structured receipts that refuse to collapse those three
  things into one."
- "Closure isn't something you can claim with a log entry — the store
  enforces it at write time and refuses retroactive edits."
- "If the evidence is corrupt, the tool tells you it's corrupt. It does
  not quietly serve 'clean' results from partial data."
- "Three operator commands: `list`, `overdue`, `explain`. All read-only,
  all on the same underlying truth."

Short version — direct quotes to **avoid** until signing lands:

- ~~"Cryptographically signed commitment receipts."~~
- ~~"Externally verifiable evidence packet."~~
- ~~"Non-repudiable third-party attestation."~~
- ~~"Tamper-proof audit trail." (substitute: "tamper-evident within the
  issuing store")~~
- ~~"We track obligations." (obligation scope is Slice 2 and the noun is
  contested internally)~~

---

## Appendix: what's in the commitment wedge on `origin/main`

As of `31bddfc`:

| PR | Title |
|---|---|
| #82 | feat: add commitment fulfillment receipts and store-order hardening |
| #83 | commitments: add `assay commitments explain <id>` read-only inspection CLI |
| #84 | test(commitments): lock terminal-closure invariants via Hypothesis property tests |
| #85 | feat(commitments): add list and overdue CLI commands |
| #86 | docs(commitments): decide global-vs-per-commitment ordering |
| #87 | refactor(commitments): extract shared lifecycle projection |
| #89 | chore(commitments): clean projection review nits |

Related doctrine:

- `docs/doctrine/COMMITMENT_ORDERING.md` — storage-order decision memo
- `src/assay/commitment_fulfillment.py` — the four event types and their emit guards
- `src/assay/commitment_projection.py` — single-pass lifecycle projection
- `src/assay/commitment_explain.py` — `assay commitments explain/list/overdue` CLI
- `src/assay/commitment_closure_detector.py` — `DOCTOR_COMMITMENT_001`
- `tests/assay/test_commitment_projection_parity.py` — cross-consumer drift guard
- `tests/assay/test_commitment_terminal_invariant.py` — Hypothesis invariant tests

Next build decision fork, per the strategic memo:

- **If outbound copy needs "signed/verifiable evidence packet" →** next PR is ReceiptV2 signing for the four commitment schemas
- **If outbound copy can honestly say "structured evidence packet, signing path next" →** next PR is the obligation namespace rename

Not "both" or "neither." One at a time. Pick after the first commercial pass produces signal.
