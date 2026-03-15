# Passports

Passports are portable, signed evidence artifacts for AI systems.

They are built from proof-pack evidence and turned into inspectable objects
that can be verified, challenged, superseded, and compared over time.

This is not a generic trust-score system. It is a bounded artifact layer with
explicit truth surfaces.

## What You Can Inspect Today

With the current passport flow, you can inspect and verify:

- A signed, content-addressed passport JSON artifact
- A rendered HTML view of the passport
- A structural `verify` result for artifact validity
- A policy-sensitive `status` result for reliance posture
- Signed lifecycle receipts for challenge, supersession, and revocation
- A diff between two passport versions
- A seeded, reproducible worked example showing the full lifecycle

The fastest place to start is the seeded referee gallery:

- [gallery/](gallery/)
- Regenerate it with `python3 docs/passport/generate_gallery.py`

If you are packaging this surface for a release, post, or customer demo,
use the commercial launch packet:

- [../commercial/PASSPORT_LAUNCH_PACKET.md](../commercial/PASSPORT_LAUNCH_PACKET.md)

## Core Commands

```bash
# Mint from a proof pack, then sign and verify
assay passport mint --pack ./proof_pack/ --subject-name "MyApp" \
  --system-id "my.app.v1" --owner "My Org" --output passport.json
assay passport sign passport.json
assay passport verify passport.json

# Inspect reliance posture under a policy mode
assay passport status passport.json --mode buyer-safe --json

# Diagnose structure and improvement path
assay passport xray passport.json --report xray.html

# Govern lifecycle
assay passport challenge passport.json --reason "Missing coverage"
assay passport supersede old.json new.json --reason "Addressed gap"
assay passport revoke passport.json --reason "Withdrawn"

# Compare versions
assay passport diff old.json new.json --report diff.html
```

## `verify` vs `status`

These are intentionally different surfaces.

- `verify` answers: is this artifact structurally valid?
- `status` answers: given verified evidence and policy mode, should I rely on it?

`verify` is about object truth:

- signature validity
- content-addressed identity
- lifecycle state derived from governance evidence

`status` is about reliance posture:

- freshness
- governance status
- lifecycle event integrity
- policy mode (`permissive`, `buyer-safe`, `strict`)

That separation matters. A passport can be structurally valid and still carry a
reliance warning or failure under policy.

## Seeded Referee Loop

The current public-safe loop is the seeded referee example.

It demonstrates:

1. mint v1
2. sign
3. render
4. X-Ray
5. challenge
6. verify challenged state
7. mint v2 to address the gap
8. sign v2
9. supersede v1 with v2
10. trust diff between v1 and v2

Run it directly:

```bash
assay passport demo
```

Expected output (timestamps and IDs will differ):

```text
Step 1: Mint passport draft
  → passport_v1.json
Step 2: Sign passport
  → ID: sha256:1d1c507f...
Step 3: Render HTML
  → passport_v1.html (28,685 bytes)
Step 4: X-Ray diagnostic
  → Grade: D (6 findings)
Step 5: Challenge passport (signed)
  → challenge_20260315_cb77f69d.json (signed)
Step 6: Verify (expect CHALLENGED)
  → Governance: challenged (integrity: all_valid, verified: 1/1)
Step 7: Mint v2 (address challenge)
  → passport_v2.json (added admin override coverage claim)
Step 8: Sign v2
  → ID: sha256:45b9500b...
Step 9: Supersede v1 → v2 (signed)
  → supersession_20260315_d19b17c8.json (signed)
Step 10: Trust Diff
  → trust_diff.html (regression: False)
```

The demo is deterministic enough to function as a worked reference flow, and
the gallery is regenerable from source.

For the clean-room public install path, use [VERIFICATION.md](VERIFICATION.md).
For the release-gate witness checklist, use
[../release/external_witness_ritual.md](../release/external_witness_ritual.md).

## How To Read The Demo

The demo is intentionally staged, which means the early output is not supposed
to look "finished."

What is happening conceptually:

1. v1 is created as the initial trust object.
2. X-Ray inspects that initial object before remediation.
3. A challenge receipt records what is missing.
4. v2 is minted to address the gap.
5. A signed supersession receipt links v1 to v2.
6. Trust Diff shows what improved.

That means the first X-Ray result is not a failure of the feature. It is part
of the worked lifecycle. The demo is showing how the object behaves under
challenge and improvement, not pretending the first draft is already perfect.

The semantic shortcuts:

- `verify` = is the object structurally valid?
- `status` = should I rely on it under a policy mode?
- `challenge` = record a governance objection
- `supersede` = link the older artifact to the improved one
- `trust diff` = show what changed between those versions

## What This Proves Today

- Signed, content-addressed passport artifacts with Ed25519 signatures
- Deterministic lifecycle governance with signed receipts by default
- Offline verification of the artifact and lifecycle chain
- Reproducible worked examples on seeded reference artifacts
- A bounded public referee surface built around inspectable artifacts

## What This Does Not Yet Prove

- Arbitrary external trust-surface scanning for URLs, PDFs, or vendor pages
- Minting passports from external vendor documents directly
- Generalized trust analysis across messy third-party inputs
- A broad enterprise Trust Diff product surface beyond the current primitive

Those remain future scope and should not be implied by the current passport
surface.

## Design Boundary

Passports are one layer in a larger stack.

- Proof packs remain the trust root for captured execution evidence.
- Passports are portable trust objects derived from that evidence.
- Lifecycle receipts govern challenge, supersession, and revocation.

Use the passport when you need a bounded, forwardable evidence artifact.
Use the underlying proof-pack surfaces when you need kernel-level execution
evidence.
