# Vendor Questionnaire Workflow

Assay can compile verifiable answers to vendor security questionnaires directly from your proof packs
and verify every claim against evidence. This is a use-case workflow within Assay, not a separate product.

The CLI surface uses the `assay vendorq` subcommand. The output is a Reviewer Packet with a settlement
verdict (VERIFIED / VERIFIED_WITH_GAPS) that procurement teams and auditors can check independently.

## 1) Ingest questionnaire

```bash
assay vendorq ingest --in questionnaire.csv --out .assay/vendorq/questions.json
```

## 2) Compile answers from packs

```bash
assay vendorq compile \
  --questions .assay/vendorq/questions.json \
  --pack ./proof_pack_20260301T120000_abcd1234 \
  --policy conservative \
  --out .assay/vendorq/answers.json
```

## 3) Pin lockfile

```bash
assay vendorq lock write \
  --answers .assay/vendorq/answers.json \
  --pack ./proof_pack_20260301T120000_abcd1234 \
  --out vendorq.lock
```

## 4) Verify

```bash
assay vendorq verify \
  --answers .assay/vendorq/answers.json \
  --pack ./proof_pack_20260301T120000_abcd1234 \
  --lock vendorq.lock \
  --strict \
  --report-out .assay/vendorq/verify_report.json
```

## 5) Export working packet draft

```bash
assay vendorq export \
  --answers .assay/vendorq/answers.json \
  --verify-report .assay/vendorq/verify_report.json \
  --format md \
  --out vendor_packet.md
```

The Markdown export includes an evidence navigation chain with replay command hints.

If you need the buyer-facing artifact another team can inspect, forward, and verify, continue with the reviewer-packet flow described in [reviewer-packets.md](./reviewer-packets.md) and use `assay vendorq export-reviewer`.

## Notes

- `vendorq verify` validates references against all packs provided via `--pack`.
- `vendorq compile` v1 uses a primary-pack heuristic for default drafting in non-metric categories.
- Use `--source-label` on ingest to avoid embedding local filesystem paths in shared packets.
