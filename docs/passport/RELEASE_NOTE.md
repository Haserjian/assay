# Passport Release Note

This note describes the current public-safe passport surface in Assay.

## What Landed

The passport flow now includes:

- Signed, content-addressed passport artifacts
- Structural verification via `assay passport verify`
- Policy-sensitive reliance posture via `assay passport status`
- Signed lifecycle governance receipts for challenge, supersession, and revocation
- Passport diff and X-Ray diagnostic surfaces
- A seeded, reproducible referee gallery with inspectable artifacts

## Why This Matters

This moves the passport surface from a rendering/demo layer to a bounded trust
artifact layer:

- the object is signed
- lifecycle events are signed by default
- signed passports are immutable after signing
- public claims are bounded by explicit truth-surface language
- the seeded referee loop is enforced by tests

## What You Can Verify Today

You can verify a complete worked example today through:

1. `assay passport demo`
2. `docs/passport/gallery/`
3. `docs/passport/README.md`

The worked example demonstrates:

- mint
- sign
- verify
- status
- xray
- challenge
- supersede
- diff

## Truth Boundary

What this release proves today:

- Signed passport artifacts are real and inspectable
- Lifecycle governance is part of the artifact chain
- Verification and reliance posture are intentionally separate surfaces
- The seeded public referee loop is reproducible from source

What this release does not yet prove:

- Arbitrary external trust-surface scanning
- Minting from vendor PDFs or third-party trust pages
- Generalized trust analysis across messy external inputs
- A fully productized enterprise Trust Diff workflow

## Recommended Entry Points

- Main summary: [../../README.md](../../README.md)
- Passport guide: [README.md](README.md)
- Seeded gallery: [gallery/](gallery/)

## Short Public-Safe Description

Assay now includes a portable passport and governance flow with signed
artifacts, verified lifecycle receipts, and a reproducible seeded referee
gallery demonstrating verification, challenge, supersession, and trust diff on
inspectable example artifacts.