# Source Artifact

This packet uses a real Assay PR Gate artifact as its source.

## Durable Source

- GitHub Actions run id: `27047357238`
- Workflow: `Assay PR Gate`
- Workflow event: `pull_request_target`
- Workflow conclusion: `success`
- Artifact name: `assay-pr-gate-report`
- PR: `#161`
- Head branch: `dogfood/live-claim-gate-needs-review-v0`
- Head commit: `87eb68c6f1e9afb16b380ba1d2ef9df90af9a758`
- Run URL: `https://github.com/Haserjian/assay/actions/runs/27047357238`

## Freshness Note

A later PR Gate artifact was available during implementation:

- GitHub Actions run id: `27047709710`
- PR: `#162`
- overall decision: `PASS`
- recommended action: `proceed`

This packet intentionally uses PR `#161` because this slice names
`pr_161_needs_review.observed.json` and exercises the review-card behavior that
matters most for the first public example: failure and absence are visible, not
hidden.

## Convenience Copy

The artifact was downloaded locally for derivation at:

```text
/tmp/assay-pr-review-proof-card-artifact.PfSInL
```

That local path is only a convenience copy. It is not the canonical source of
truth.

## Source Files Used

Source precedence:

1. `signed-report/verify_report.json` - canonical signed report source.
2. `decision.json` - local PR Gate decision object.
3. `proof-pack/pack_manifest.json` - evidence-pack structure.
4. `comment.md` - rendered review surface, not authority.

Expected downloaded artifact files:

```text
claim_gate_report.json
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

## Canonical Report Fields

From `signed-report/verify_report.json`:

- report id: `vr_292c223cecdf60f2cd31`
- report schema: `assay.pr_gate.verify_report.v0.1`
- pack id: `prgate_pack_0659bcbd9ca2cdb7`
- subject repo: `Haserjian/assay`
- subject PR: `#161`
- base commit: `21aa7b8c8cfbd2d04ad8e1560b111a9ed9b45ed2`
- head commit: `87eb68c6f1e9afb16b380ba1d2ef9df90af9a758`
- diff hash: `sha256:d64768533af7e6742ccbceae35064d7f84980e62f05b2d7a91c3cb257c506cea`
- overall decision: `NEEDS_REVIEW`
- recommended action: `require_human_approval`
- channels: Integrity `PASS`, Claim `FAIL`, Replay `NOT_RUN`, Trust policy
  `PASS`

## Canonical Source Of Truth

The signed Verification Report is canonical. This packet is only an observed
projection for a reader at the PR review moment.
