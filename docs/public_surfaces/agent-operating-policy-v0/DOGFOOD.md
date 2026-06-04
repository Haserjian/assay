# Agent Operating Policy v0 Dogfood Record

This record shows that the captured PR evidence for PR #152 passed Assay PR Gate under the checks listed here. It does not prove agent obedience, code safety, production approval, replay, or unsupported implementation claims.

## Subject

- PR: #152
- PR URL: https://github.com/Haserjian/assay/pull/152
- Branch: `docs/agent-operating-policy-v0`
- Base branch: `main`
- PR head commit: `0d7c367dee2e7885e715bc0cc2c08e243265f3c3`
- Merge commit: `967cdcdf278beeb873cc68698d3012f3f40c0407`
- Merged at: `2026-06-04T20:24:30Z`
- Diff hash: `sha256:127d663b92469c5eeaa8233f854cedec87f1c624aca6b5006b046e5010dd82b7`

## PR Gate Verdict

- Verdict: `PASS`
- Recommended action: `proceed`
- Reason: `none`

Verdict channels:

- Integrity: `PASS`
- Claim: `NOT_EVALUATED`
- Replay: `NOT_RUN`
- Trust policy: `PASS`

The gate returned `PASS` for this PR evidence. The signed review packet verified locally under the expected GitHub Actions workflow identity.

## Artifact

- Workflow run: https://github.com/Haserjian/assay/actions/runs/26977090264
- Artifact name: `assay-pr-gate-report`
- Artifact ID: `7422059065`
- Artifact size: `15681` bytes
- Artifact created at: `2026-06-04T20:17:46Z`
- Artifact expires at: `2026-09-02T20:17:21Z`
- Artifact expired at capture time: `false`

The artifact was downloaded to a local temporary directory for verification. The downloaded artifact itself is not checked in.

Downloaded artifact files:

```text
comment.md
decision.json
evidence.json
proof-pack/changed_files.json
proof-pack/observed_checks.json
proof-pack/pack_manifest.json
proof-pack/policy.yml
proof-pack/pr_gate_decision.json
proof-pack/pr_gate_evidence.json
proof-pack/verify_transcript.md
signed-report/verify_report.json
signed-report/verify_report.sigstore.json
```

Captured hashes:

```text
proof-pack/pack_manifest.json                  sha256:f2beaa793ea364072a6a085e3188046287c653dec26d5b688184262742e81b90
signed-report/verify_report.json               sha256:ba46bd7cb5cc6eeed9bccbeb018fd113c0876913c3daa4568f30276285378764
signed-report/verify_report.sigstore.json      sha256:aec4a7fa5c49f8843a2a4619595eedb3b1183fefcf3d96ef4576ba5cda7516bd
comment.md                                     sha256:5ed891ed75e0265fee00170c34d6873b4c2c0be1379f01f6c323f95435236e48
decision.json                                  sha256:926c0065a00eb56abfc276b60bb0b84e3233853ecced76a7a3d23626211ee2be
evidence.json                                  sha256:10b312e53c1619b9073598d925c04103c4600b7481e0a7d4b91ccf5e33377fc9
```

The Verification Report also recorded:

```text
pack_id: prgate_pack_f8667a8c8849dfb2
report_id: vr_aca99ffaec8e36d93f4b
pack_root_sha256: sha256:ad7bb0d7d2853f75a5bb88bfac4ef7e4787ec51395ffd820415607bed2c90dce
policy profile: coding_pr_v0
policy_sha256: sha256:f4c3d96a81252fe1c2c96127218b2e3c3828c7acc44f4b8e4a6f1d49459087c5
```

## Local Verification

Command shape recommended by the PR Gate comment:

```bash
.venv/bin/assay pr-gate verify \
  --pack /tmp/assay-pr152-gate.krs77W/proof-pack \
  --report /tmp/assay-pr152-gate.krs77W/signed-report/verify_report.json \
  --sigstore /tmp/assay-pr152-gate.krs77W/signed-report/verify_report.sigstore.json \
  --expected-identity https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main \
  --json
```

Result:

```json
{
  "command": "assay pr-gate verify",
  "status": "ok",
  "result": "ASSAY PR GATE VERIFIED",
  "pack_root_sha256": "sha256:ad7bb0d7d2853f75a5bb88bfac4ef7e4787ec51395ffd820415607bed2c90dce",
  "report_id": "vr_aca99ffaec8e36d93f4b",
  "decision": "PASS",
  "recommended_action": "proceed",
  "channels": {
    "integrity": "PASS",
    "claim": "NOT_EVALUATED",
    "replay": "NOT_RUN",
    "trust_policy": "PASS"
  },
  "expected_identity": "https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main",
  "certificate_oidc_issuer": "https://token.actions.githubusercontent.com"
}
```

## Tamper Check

A disposable copy of the downloaded artifact was modified by appending one byte to:

```text
proof-pack/pr_gate_decision.json
```

The same verification command failed closed:

```json
{
  "command": "assay pr-gate verify",
  "status": "failed",
  "error": "proof-pack file hash mismatch: pr_gate_decision.json"
}
```

The tamper check exited with code `2`.

## Do Not Infer

This record does not show that:

- the code is secure
- all possible tests passed
- AI made a good design decision
- replay was performed
- production approval was granted
- the agent fully followed `AGENTS.md`

It records only that the captured PR evidence for PR #152 satisfied the PR Gate policy and that the signed review packet verified under the expected workflow identity.
