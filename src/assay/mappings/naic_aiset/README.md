# NAIC AISET Mapping Pack

Mapping payloads for the NAIC AI Systems Evaluation Tool (AISET), a 4-part
questionnaire being piloted for insurance market conduct examinations in 2026.

## Structure

- `question_mapping.json` — Maps AISET question categories to proof-pack evidence
- `boundary_template.json` — Template boundary for insurance AI workflows

## AISET Parts

1. **AI Use** — Quantifying AI adoption and deployment scope
2. **Governance & Risk** — Governance structure, risk management, oversight
3. **High-Risk Model Details** — Model documentation for high-risk use cases
4. **Model & Data Details** — Data provenance, training, validation

## Usage

```bash
assay vendorq export-reviewer \
  --proof-pack ./proof_pack \
  --boundary ./naic_aiset_boundary.json \
  --mapping src/assay/mappings/naic_aiset/question_mapping.json \
  --out ./naic_aiset_reviewer_packet
```

## What Assay can prove vs. what it cannot

Assay proof packs provide tamper-evident receipts of AI execution: model calls,
guardian verdicts, capability uses, and claim checks. This maps well to AISET
questions about runtime governance, model monitoring, and audit trails.

AISET questions about organizational policy, board governance, training data
provenance, and legal compliance are marked `HUMAN_ATTESTED` or `OUT_OF_SCOPE`.
The mapping is honest about this boundary.
