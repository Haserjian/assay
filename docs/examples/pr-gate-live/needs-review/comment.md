Assay PR Gate: NEEDS_REVIEW

Recommended action: require_human_approval
Reason: touched risk path docs/product/assay-pr-gate-*.md

Subject:
- repo: Haserjian/assay
- PR: #138
- head commit: 330f90c1e2616f4937c778bae3f6f197e1fdfa7d
- diff hash: sha256:8638a7f053588b12d63ca82a9abf0485d69dd041096005cf269bed60c5426bf1

Verdict channels:
- Integrity: PASS
- Claim: NOT_EVALUATED
- Replay: NOT_RUN
- Trust policy: NEEDS_REVIEW - touched docs/product/assay-pr-gate-dogfood-v0.md

Evidence:
- Evidence Box: proof-pack/pack_manifest.json
- Verification Report: signed-report/verify_report.json
- Signature Proof: signed-report/verify_report.sigstore.json

Do not infer:
- code is secure
- all possible tests passed
- AI made a good design decision
- replay was performed
- production approval was granted

Signed by expected workflow:
https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main

How to verify:
- Download `assay-pr-gate-report`, then run `assay pr-gate verify` against `proof-pack/` and `signed-report/`.

How to challenge:
- Comment with missing evidence, stale policy, signer trust, replay divergence, overbroad claim, or contradictory evidence.
