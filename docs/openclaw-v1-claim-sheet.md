# OpenClaw v1 Claim Sheet

**Status:** current public claim sheet
**Date:** 2026-04-09
**Purpose:** short external statement of what Assay does and does not claim at the OpenClaw boundary

---

## One-line claim

Assay records and packages a bounded subset of OpenClaw-relevant actions and
imported session evidence into a tamper-evident proof pack. It does not claim
full runtime completeness or hostile multi-tenant enforcement.

---

## What This Proves

At the current v1 boundary, Assay can prove:

- which selected request crossed the Assay boundary
- whether current policy allowed or denied it
- what Assay recorded about the resulting subprocess invocation or imported
  session-log event
- whether the recorded evidence came from membrane execution, live receipt
  adaptation, or imported session-log evidence
- whether the packaged evidence was tampered with after signing

---

## What This Does Not Prove

Assay does not currently prove:

- complete coverage of all OpenClaw runtime activity
- live OpenClaw Gateway or WebSocket interception
- full browser-runtime or CDP governance on every action
- OpenClaw planner correctness or browser-page semantic truth
- that an imported session log was complete or honest before Assay receipted it
- a hostile multi-tenant security boundary for shared operators

---

## Trust Assumptions

Use this surface only with these assumptions stated explicitly:

- the OpenClaw/Gateway side is still a single trusted operator boundary, not an
  adversarial shared-runtime boundary
- the proof pack is the trust root for exported evidence
- browser verification currently applies to proof packs, not higher-level
  wrappers
- imported session logs are evidence inputs, not automatically trusted truth
- the deterministic `assay try-openclaw` path is a reproducible synthetic demo,
  not a claim of live runtime interception
- pack verification proves integrity of admitted evidence after signing; it does
  not by itself prove independent attestation or semantic correctness

---

## Required Artifacts For A Credible v1 Claim

For the current OpenClaw claim to be externally reviewable, keep these artifacts
available:

- a proof pack directory that verifies with `assay verify-pack`
- the emitted `verify_report.json` or equivalent verification output
- explicit evidence-source distinction in the projected entries:
  - membrane execution
  - live receipt adaptation
  - imported session-log evidence
- when imported session evidence is present:
  - `clean` vs `partial` import state
  - imported vs skipped counts
  - skipped-row reasons
  - the exported session log itself when review requires source inspection
- when membrane execution or denials are material to the claim:
  - the raw bridge artifacts beside the pack

If those artifacts are missing, the surface may still be useful internally, but
the external claim is weaker.

---

## Explicit Non-Goals

OpenClaw v1 is not:

- a full browser-governance product
- a claim of complete runtime capture
- a multi-user or hostile-tenant containment story
- a compliance certification claim
- a Loom-first or organism-first public handshake

Lead with Assay as the trust surface. Treat OpenClaw as the forcing function
that makes the boundary legible.

---

## Release-Branch Gate Before Version Bump

Treat this claim as release-ready only when the exported review slice, not the
mixed source tree, satisfies all of the following:

Shortcut: run `python3 scripts/check_openclaw_release_branch_gate.py` inside
the exported review branch. That script should stay green before any OpenClaw
version bump work begins.

- export an isolated review slice first:
  `python3 scripts/export_openclaw_release_slice.py --output <dir> --branch <review-branch>`
- inside that exported slice, the executable branch gate stays green:
  `python3 scripts/check_openclaw_release_branch_gate.py --json`
- that gate must prove all of the following in one path:
  - branch-backed review slice
  - untouched `pyproject.toml`
  - isolated OpenClaw slice
  - passing package smoke
- the packaged CLI proves the current narrow surface:
  - `assay --help` exposes `try-openclaw`
  - `assay try-openclaw --json` returns `PASS`
  - `assay verify-pack ./assay_openclaw_demo/proof_pack` succeeds for the
    emitted pack
- the shipped docs still match the packaged behavior:
  - `README.md`
  - `docs/openclaw-support.md`
  - this claim sheet
- only after those checks are green may `pyproject.toml` change for an
  OpenClaw release bump

Hold release if any of the following becomes true in the review slice:

- the checker reports out-of-scope paths
- package smoke fails
- the docs imply broader runtime control than the shipped surface proves
- the packaged CLI diverges from the documented commands or artifacts

---

## Recommended Wording

Use this sentence for current external surfaces:

> Assay is a trust layer for agentic systems that turns risky tool use into policy-bound, offline-verifiable evidence.

If you need the OpenClaw-specific version:

> Assay can sit in front of OpenClaw as a narrow evidence membrane for selected tool actions and exported session activity, emitting tamper-evident receipts and proof packs another team can verify offline.

---

## See Also

- [OpenClaw Support](openclaw-support.md) — full support contract and boundary detail
- [OpenClaw Live Validation Runbook](openclaw-live-validation-runbook.md) — internal operator path for generating the first real exported session log and rerunning the live-fit harness
- [Start Here](START_HERE.md) — current first-run and documentation map
