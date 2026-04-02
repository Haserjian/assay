# Reviewer Packets

Reviewer Packets are the buyer-facing artifact built on top of an Assay proof
pack. The proof pack remains the trust root. The Reviewer Packet makes that
proof usable across an organizational boundary by packaging:

Recent proof note:

- [release/2026-03-15-cli-smoke-proof-note.md](release/2026-03-15-cli-smoke-proof-note.md)

- settlement
- scope
- coverage
- challenge path
- the nested proof pack

Use the proof pack when you need kernel-level verification.
Use the Reviewer Packet when you need a bounded artifact another team can
inspect, forward, and challenge.

## End-to-end flow

```text
proof pack -> reviewer packet -> assay reviewer verify -> browser verify
```

## Build a sample reviewer packet

From the repo root:

```bash
assay vendorq export-reviewer \
  --proof-pack tests/fixtures/reviewer_packet/sample_proof_pack \
  --boundary tests/fixtures/reviewer_packet/sample_boundary.json \
  --mapping tests/fixtures/reviewer_packet/sample_mapping.json \
  --out reviewer_packet_demo
```

This uses the checked-in sample proof pack and packet inputs that back the
reviewer-packet tests.

To cryptographically attest the packet layer as well, add packet-manifest signing:

```bash
assay vendorq export-reviewer \
  --proof-pack tests/fixtures/reviewer_packet/sample_proof_pack \
  --boundary tests/fixtures/reviewer_packet/sample_boundary.json \
  --mapping tests/fixtures/reviewer_packet/sample_mapping.json \
  --out reviewer_packet_demo \
  --sign-packet
```

This writes `PACKET_SIGNATURE.sig` beside `PACKET_MANIFEST.json`. If no active
local signer exists yet, Assay creates one and signs the packet manifest with
its embedded public key so `assay reviewer verify` can validate it offline.

## Verify in the CLI

```bash
assay reviewer verify reviewer_packet_demo
assay reviewer verify reviewer_packet_demo --json
```

The CLI recomputes settlement from the nested proof pack and packet inputs.
It does not trust hand-edited packet metadata.

The JSON output includes:

- `settlement_state`
- `settlement_reason`
- `packet_manifest` signing / verification status
- `failure_reasons`
- `settlement_verification` recomputation details

## Generate a Decision Census

Once a reviewer packet has been compiled, the next step is to generate a
Decision Census report from that packet surface:

```bash
assay reviewer census reviewer_packet_demo
assay reviewer census reviewer_packet_demo --json
```

The census is a workflow-wide coverage artifact built from the compiled
reviewer packet. It emits:

- `DECISION_CENSUS.json`
- `DECISION_CENSUS.md`
- `COVERAGE_MATRIX.md`

The report makes expected vs observed decision points explicit and keeps
degraded mode honest. If `PACKET_INPUTS.json` or `PACKET_MANIFEST.json` are
absent, the census still runs and states that the inventory was inferred from
the coverage matrix alone.

Example output shape:

- `coverage_summary.expected_count`
- `coverage_summary.observed_count`
- `coverage_summary.missing_count`
- `coverage_summary.coverage_state`
- `unsupported_surfaces`
- `inventory.basis`

Example summary snippet:

```json
{
  "coverage_summary": {
    "expected_count": 2,
    "observed_count": 2,
    "missing_count": 0,
    "coverage_state": "degraded"
  }
}
```

## CI artifact bundle

The advisory GitHub Actions workflow also runs this path automatically and
uploads the bundle as `decision-census-advisory`.

Inspect the workflow run in GitHub Actions, then open the artifact download for:

- `.assay/reviewer-packet`
- `.assay/decision-census`

Those directories contain the generated reviewer packet, `DECISION_CENSUS.json`,
`DECISION_GAPS.json`, and the matching Markdown summaries.

## Checkpoint Packet Profile

Reviewer Packets also support a checkpoint-specific profile for resolved
`outbound_action.send_email` attempts:

```bash
assay checkpoint export-reviewer <checkpoint_attempt_id> \
  --proof-pack path/to/proof_pack \
  --out checkpoint_packet_demo \
  --decision-receipt path/to/decision.json
```

This does not create a new packet format. It emits the same reviewer-packet
directory contract:

- `SETTLEMENT.json`
- `SCOPE_MANIFEST.json`
- `COVERAGE_MATRIX.md`
- `PACKET_INPUTS.json`
- `PACKET_MANIFEST.json`
- nested `proof_pack/`
- optional `decision_receipts/`

The trust root remains the nested proof pack. The checkpoint lifecycle becomes
the packet's subject matter.

Checkpoint packets use
`packet_profile = checkpoint.outbound_action.send_email.v0.1` and a fixed
four-row coverage model:

1. attempted crossing
2. eligible posture carried into resolution
3. authority decision layer
4. actual outcome

Authority evidence is explicit about how it was obtained:

- `canonical_decision_receipts`
- `trace_wrappers_only`
- `missing`
- `not_required`

This means the packet can degrade honestly:

- canonical Decision Receipts packaged -> authority row can be `EVIDENCED`
- only `checkpoint.decision_recorded` trace wrappers available -> authority row is `PARTIAL`
- missing authority linkage for a decision-required outcome -> settlement becomes `INCOMPLETE_EVIDENCE`
- legacy resolutions missing `final_evaluation_id` stay readable but downgrade the posture row to `PARTIAL`

`assay reviewer verify` recomputes checkpoint settlement from the nested proof
pack and any packaged canonical Decision Receipts. It does not trust the
packet's `SETTLEMENT.json` or coverage rows.

## Verify in the browser

Open the browser verifier and drop in the compiled packet directory:

- [Browser verifier](https://haserjian.github.io/assay-proof-gallery/verify.html)

The browser verifier uses the same reviewer-packet contract as
`assay reviewer verify` and checks:

- packet-layer file integrity
- detached packet-signature parity when the packet manifest is signed
- nested proof-pack integrity
- derived settlement, freshness, regression, and coverage

## Buyer verdicts vs CLI exit codes

Do not blur reviewer verdicts with CLI exit codes.

Reviewer verdicts are buyer-facing packet states:

- `VERIFIED`
- `VERIFIED_WITH_GAPS`
- `INCOMPLETE_EVIDENCE`
- `EVIDENCE_REGRESSION`
- `TAMPERED`
- `OUT_OF_SCOPE`

CLI exit codes are process results:

- `0` PASS
- `1` HONEST_FAIL
- `2` TAMPERED
- `3` bad input

The buyer sees a settlement. The CLI returns a process code.

## Challenge flow

Use the packet as the readable wrapper and the proof pack as the trust root:

```bash
assay reviewer verify reviewer_packet_demo
assay verify-pack reviewer_packet_demo/proof_pack
```

If you tamper with the packet layer or the nested proof pack, reviewer
verification will surface that as `TAMPERED`.
