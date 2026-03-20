# Checkpoint Packet Canary

This runbook operationalizes the `checkpoint.outbound_action.send_email.v0.1` reviewer-packet path without changing checkpoint lifecycle semantics, reviewer-packet schema semantics, or Decision Receipt semantics.

The proof pack is the trust root. The reviewer packet is the bounded disclosure wrapper built from that proof pack plus packaged canonical Decision Receipt evidence.

## Run

From the repo root:

```bash
.venv/bin/python scripts/run_checkpoint_packet_canary.py \
  --out .assay/canary/checkpoint-packet-released
```

Optional HTML render:

```bash
.venv/bin/python scripts/run_checkpoint_packet_canary.py \
  --out .assay/canary/checkpoint-packet-released \
  --render-html
```

## Expected Output

The output directory contains:

```text
.assay/canary/checkpoint-packet-released/
  RUN_CONTEXT.json
  trace_id.txt
  decision_receipt.json
  checkpoint_export.json
  proof_pack/
  reviewer_packet/
  reviewer_verify.json
  reviewer_packet.html        # only when --render-html is used
```

Expected green-path result:

- reviewer packet settlement is `VERIFIED`
- authority evidence mode is `canonical_decision_receipts`
- coverage is `4/4 EVIDENCED`
- the same `checkpoint_attempt_id` is preserved across request, evaluation, resolution, and packet outputs

## Inspect

Compare these four files side by side:

- `decision_receipt.json`
- `proof_pack/verify_report.json`
- `reviewer_packet/SETTLEMENT.json`
- `reviewer_verify.json`

What “good” looks like:

- `reviewer_verify.json.packet_verified == true`
- `reviewer_verify.json.settlement_state == "VERIFIED"`
- `reviewer_verify.json.coverage_summary.EVIDENCED == 4`
- `reviewer_packet/SETTLEMENT.json.packet_profile == "checkpoint.outbound_action.send_email.v0.1"`
- `reviewer_packet/SCOPE_MANIFEST.json.decision_layer_mode == "canonical_decision_receipts"`
- `reviewer_packet/SETTLEMENT.json.pack_manifest_sha256` matches `proof_pack/pack_manifest.json`
- `RUN_CONTEXT.json` records the git SHA, ref, Python version, Assay version, command args, timestamp, packet profile, and checkpoint type used to produce the artifacts
