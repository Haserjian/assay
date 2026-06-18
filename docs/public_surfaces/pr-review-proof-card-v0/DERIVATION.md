# Derivation

`examples/pr_161_needs_review.observed.json` is generated from the downloaded
`assay-pr-gate-report` artifact for GitHub Actions run `27047357238`.

The card is an observed projection. It is not an independent authority, a
schema, a verifier output, or canonical evidence. The signed Verification
Report remains canonical.

## Source Paths

Assuming:

```bash
ARTIFACT_DIR=/tmp/assay-pr-review-proof-card-artifact.PfSInL
```

The derivation reads:

- `$ARTIFACT_DIR/signed-report/verify_report.json`
- `$ARTIFACT_DIR/decision.json`
- `$ARTIFACT_DIR/proof-pack/pack_manifest.json`

`$ARTIFACT_DIR/comment.md` is kept as rendered-output comparison only.

## Field Mapping

| Card field | Source field |
|---|---|
| `source_artifact.github_actions_run_id` | `verify_report.capture.run_id` |
| `canonical_source_of_truth.report_id` | `verify_report.report_id` |
| `canonical_source_of_truth.schema_version` | `verify_report.schema_version` |
| `subject` | `verify_report.subject` |
| `capture` | `verify_report.capture` |
| `policy` | `verify_report.policy` |
| `signature_policy` | `verify_report.signature_policy` |
| `decision.overall_decision` | `verify_report.overall_decision` |
| `decision.recommended_action` | `verify_report.recommended_action` |
| `decision.reasons` | `verify_report.reasons` |
| `verdict_channels` | `verify_report.channels` |
| `failures.claim_gate_blocks` | `verify_report.reasons` |
| `checks.check_observations` | `verify_report.check_observations` |
| `evidence.pack_id` | `verify_report.pack_id` |
| `evidence.pack_manifest_sha256` | `verify_report.pack_manifest_sha256` |
| `evidence.pack_root_sha256` | `verify_report.pack_root_sha256` |
| `evidence.evidence_refs` | `verify_report.evidence_refs` |
| `evidence.pack_manifest.files` | `proof-pack/pack_manifest.json.files` |
| `do_not_infer` | `verify_report.do_not_infer` |

## Absence Handling

Absence is represented directly:

- `checks.check_observations` is an empty array, so the card records
  `check_observations_status: NONE_RECORDED`.
- `channels.replay` is `NOT_RUN`, so the card records replay as not run.
- `evidence_refs[Verification Report].sha256` is `null` in the signed report,
  so the card records it under `unavailable_or_not_derived`.
- `evidence_refs[Signature Proof].sha256` is `null` in the signed report, so
  the card records it under `unavailable_or_not_derived`.

## Generation Command

The observed JSON was generated with:

```bash
ARTIFACT_DIR=/tmp/assay-pr-review-proof-card-artifact.PfSInL
mkdir -p docs/public_surfaces/pr-review-proof-card-v0/examples

jq -n \
  --slurpfile report "$ARTIFACT_DIR/signed-report/verify_report.json" \
  --slurpfile decision "$ARTIFACT_DIR/decision.json" \
  --slurpfile manifest "$ARTIFACT_DIR/proof-pack/pack_manifest.json" '
  ($report[0]) as $r |
  ($decision[0]) as $d |
  ($manifest[0]) as $m |
  {
    card_version: "assay.pr_review_proof_card.observed.v0",
    projection_status: "observed_projection",
    consumer: {
      role: "maintainer_or_tech_lead",
      call_site: "github_pr_comment_or_pr_gate_artifact",
      decision_supported: ["proceed_to_review", "require_more_evidence", "block"]
    },
    invariant: [
      "A Proof Card displays which checks ran and where the evidence stops.",
      "It does not assert truth, correctness, safety, security, or merge-readiness.",
      "Absence of a check is shown, never hidden."
    ],
    non_authority: [
      "This observed card is not canonical evidence.",
      "The signed Verification Report remains canonical.",
      "This card is a reader projection over PR Gate output, not a new proof substrate."
    ],
    source_artifact: {
      github_actions_run_id: $r.capture.run_id,
      artifact_name: "assay-pr-gate-report",
      workflow_name: "Assay PR Gate",
      artifact_files_used: [
        "signed-report/verify_report.json",
        "decision.json",
        "proof-pack/pack_manifest.json",
        "comment.md"
      ],
      source_precedence: [
        {rank: 1, path: "signed-report/verify_report.json", role: "canonical_signed_report_source"},
        {rank: 2, path: "decision.json", role: "local_pr_gate_decision_object"},
        {rank: 3, path: "proof-pack/pack_manifest.json", role: "evidence_pack_structure"},
        {rank: 4, path: "comment.md", role: "rendered_review_surface_not_authority"}
      ]
    },
    canonical_source_of_truth: {
      path: "signed-report/verify_report.json",
      schema_version: $r.schema_version,
      report_id: $r.report_id,
      signed_by_expected_workflow: $r.signature_policy.expected_certificate_identity
    },
    rendered_surface_comparison: {
      path: "comment.md",
      role: "rendered review surface; not used as authority for this card"
    },
    subject: $r.subject,
    capture: $r.capture,
    policy: $r.policy,
    signature_policy: $r.signature_policy,
    decision: {
      overall_decision: $r.overall_decision,
      recommended_action: $r.recommended_action,
      reasons: $r.reasons
    },
    verdict_channels: $r.channels,
    failures: {
      claim_channel_status: $r.channels.claim,
      claim_gate_blocks: $r.reasons
    },
    checks: {
      check_observations_status: (if ($r.check_observations | length) == 0 then "NONE_RECORDED" else "RECORDED" end),
      check_observations: $r.check_observations,
      absence_visibility: [
        {
          field: "check_observations",
          observed_value: $r.check_observations,
          meaning: "No required-check observations were recorded in this artifact."
        },
        {
          field: "channels.replay",
          observed_value: $r.channels.replay,
          meaning: "Replay was not run for this PR Gate artifact."
        }
      ]
    },
    evidence: {
      pack_id: $r.pack_id,
      pack_manifest_sha256: $r.pack_manifest_sha256,
      pack_root_sha256: $r.pack_root_sha256,
      evidence_refs: $r.evidence_refs,
      pack_manifest: {
        schema_version: $m.schema_version,
        files: $m.files
      }
    },
    do_not_infer: $r.do_not_infer,
    unavailable_or_not_derived: [
      {
        field: "evidence_refs[Verification Report].sha256",
        observed_value: null,
        reason: "The signed report evidence reference in the source report records this value as null."
      },
      {
        field: "evidence_refs[Signature Proof].sha256",
        observed_value: null,
        reason: "The signature proof evidence reference in the source report records this value as null."
      },
      {
        field: "proof-pack/pack_manifest.json.root_sha256",
        observed_value: $m.root_sha256,
        reason: "The manifest field is null; the report-level pack_root_sha256 is preserved separately."
      }
    ],
    derivation_checks: {
      decision_overall_matches_report: ($d.overall_decision == $r.overall_decision),
      decision_recommended_action_matches_report: ($d.recommended_action == $r.recommended_action),
      decision_channels_match_report: ($d.channels == $r.channels),
      manifest_pack_root_matches_report: ($m.pack_root_sha256 == $r.pack_root_sha256)
    }
  }
' > docs/public_surfaces/pr-review-proof-card-v0/examples/pr_161_needs_review.observed.json
```

## Derivation Checks

The generated example records four consistency checks:

- `decision_overall_matches_report: true`
- `decision_recommended_action_matches_report: true`
- `decision_channels_match_report: true`
- `manifest_pack_root_matches_report: true`
