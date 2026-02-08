# Assay

Receipt-native AI safety toolkit. Build, sign, and verify Proof Packs
that prove what your AI system actually did.

## Install

```bash
pip install assay-ai
```

## 60-Second Demo

```bash
assay demo-pack
```

Creates synthetic receipts, builds signed Proof Packs, and verifies them.
No API key, no configuration required.

## Core Flow

```bash
# 1. Scan your project for uninstrumented LLM calls
assay scan .

# 2. Instrument your code (one line)
#    from assay.integrations.openai import patch; patch()

# 3. Run your code through Assay
assay run -c receipt_completeness -c guardian_enforcement -- python my_agent.py

# 4. Verify the output
assay verify-pack ./proof_pack_*/

# 5. Gate in CI
assay verify-pack ./proof_pack_*/ --require-claim-pass
```

## What Assay Does

Assay is a verification layer for AI systems. It does two jobs:

- **Courthouse job**: prove structural integrity of evidence (signatures, hashes, required files)
- **Laboratory job**: test behavioral claims against that evidence (RunCards)

These are deliberately orthogonal: integrity can pass while claims fail.
That's the honesty property.

## Commands

| Command | Purpose |
|---------|---------|
| `assay demo-pack` | Generate demo packs (no config needed) |
| `assay scan` | Find uninstrumented LLM call sites |
| `assay run` | Wrap command, collect receipts, build signed pack |
| `assay verify-pack` | Verify a Proof Pack (integrity + claims) |
| `assay lock write` | Freeze verification contract to lockfile |
| `assay lock check` | Validate lockfile against current card definitions |
| `assay doctor` | Preflight check: is Assay ready here? |

## Exit Codes

- **0** -- integrity PASS and claims PASS
- **1** -- integrity PASS, claims FAIL
- **2** -- integrity FAIL or lock mismatch

## Documentation

- [Quickstart](docs/README_quickstart.md)
- [Deep Dive](docs/ASSAY_DEEP_DIVE_2026Q1.md)
- [Decision Log](docs/ASSAY_DECISION_LOG.md)

## Related Repos

| Repo | Purpose |
|------|---------|
| [assay](https://github.com/Haserjian/assay) | Core CLI, SDK, conformance corpus (this repo) |
| [assay-verify-action](https://github.com/Haserjian/assay-verify-action) | GitHub Action for CI verification |
| [assay-ledger](https://github.com/Haserjian/assay-ledger) | Public transparency ledger |

## License

Apache-2.0
