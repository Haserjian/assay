Assay PR Gate: BLOCK

Recommended action: block_required_check_failed
Reason: required check "tests" failed

Subject:
- repo: Haserjian/assay
- PR: #123
- head commit: head-block
- diff hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Verdict channels:
- Integrity: PASS
- Claim: NOT_EVALUATED
- Replay: NOT_RUN
- Trust policy: BLOCK - required check "tests" failed

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
