# Reviewer Packets

Reviewer Packets are the buyer-facing artifact built on top of an Assay proof
pack. The proof pack remains the trust root. The Reviewer Packet makes that
proof usable across an organizational boundary by packaging:

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
