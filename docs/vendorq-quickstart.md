# VendorQ Quickstart

Verifiable Vendor Packet compiles questionnaire responses from Assay proof packs and verifies every claim against evidence.

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

## 5) Export packet

```bash
assay vendorq export \
  --answers .assay/vendorq/answers.json \
  --verify-report .assay/vendorq/verify_report.json \
  --format md \
  --out vendor_packet.md
```

The Markdown export includes an evidence navigation chain with replay command hints.

## Notes

- `vendorq verify` validates references against all packs provided via `--pack`.
- `vendorq compile` v1 uses a primary-pack heuristic for default drafting in non-metric categories.
- Use `--source-label` on ingest to avoid embedding local filesystem paths in shared packets.
