# Proof Note: Cross-Platform Reviewer-Packet Smoke

Date: 2026-03-15

This note records a proof-surface ratchet in Assay's hosted CLI smoke workflow.

## What changed

- `CLI Smoke` now proves more than CLI entry.
- The workflow exercises a real reviewer-packet artifact path on Linux, macOS, and Windows.
- The workflow now:
  - runs `assay version`
  - runs `assay try`
  - compiles a reviewer packet from checked-in fixtures
  - asserts the expected packet files exist on disk
  - verifies the resulting reviewer packet

## What was fixed during hardening

- Windows console encoding failure in `assay try`
  - Cause: human-output strings used Unicode punctuation that failed under `cp1252` in GitHub Actions.
  - Fix: first-contact demo output was made ASCII-safe.
- Reviewer-packet wrapper drift
  - Cause: human-output reviewer commands expected stale result fields even though JSON paths still worked.
  - Fix: console output now derives coverage summaries from the current payload shape.
- Fixture byte instability on Windows
  - Cause: checked-in sample proof-pack files were rewritten on checkout, invalidating nested proof-pack verification.
  - Fix: `.gitattributes` now preserves exact bytes for `tests/fixtures/reviewer_packet/sample_proof_pack/**`.
- Workflow trigger blind spot
  - Cause: `CLI Smoke` did not rerun when `.gitattributes` or reviewer-packet fixture inputs changed.
  - Fix: workflow path filters now include those trust inputs.

## Current hosted proof claim

Hosted `CLI Smoke` now passes on:

- `ubuntu-latest`
- `macos-latest`
- `windows-latest`

That means Assay can honestly claim all of the following for the current smoke path:

- the first-contact CLI path runs cross-platform
- reviewer-packet compile works cross-platform
- expected reviewer-packet artifacts are written to disk
- reviewer-packet verification works cross-platform
- the checked-in reviewer-packet proof fixture is protected from newline drift across platforms

## Boundary

This note does not claim that every reviewer-packet mode or every signing mode is proven by hosted CI.
It records the exact smoke path currently covered by the workflow.
