# Assay

Stop filling out the AI compliance spreadsheet. Add one CI step. Every
merge produces portable, signed evidence that anyone can verify.

When someone asks "prove what your AI did," you need more than logs.
Logs live on your infrastructure, under your control. Assay produces
**signed evidence bundles** they can verify independently -- no access
to your systems required.

## Install

```bash
pip install assay-ai
```

## 2-Minute Demo

```bash
pip install assay-ai
assay demo-incident
```

This runs a two-act scenario with synthetic data (no API key needed):

- **Act 1**: Agent uses gpt-4 with a guardian check. Result: integrity PASS, claims PASS.
- **Act 2**: Someone swaps the model and drops the guardian. Result: integrity PASS, claims FAIL.

That second result is an **honest failure** -- authentic evidence proving the
run violated its declared standards. Not a cover-up. Not theater. Exit code 1.

```bash
assay demo-challenge    # CTF-style: spot the tampered pack
assay demo-pack         # build + verify from scratch
```

## The Golden Path

```bash
# 0. Guided path (recommended)
assay onboard .

# 1. Find uninstrumented LLM calls
assay scan .

# 2. Instrument (one line)
#    from assay.integrations.openai import patch; patch()

# 3. Produce a signed proof pack
assay run -c receipt_completeness -c guardian_enforcement -- python my_app.py

# 4. Verify + explain
assay verify-pack ./proof_pack_*/
assay explain ./proof_pack_*/

# 5. Lock the verification contract
assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
```

## How It Works

Assay separates two questions on purpose:

- **Integrity**: "Were these bytes tampered with after creation?"
  (signatures, hashes, required files)
- **Claims**: "Does this evidence satisfy our declared governance checks?"
  (receipt types, counts, field values)

| Integrity | Claims | Exit Code | Meaning |
|-----------|--------|-----------|---------|
| PASS | PASS | 0 | Evidence checks out, behavior meets standards |
| PASS | FAIL | 1 | Honest failure: authentic evidence of standards violation |
| FAIL | -- | 2 | Evidence has been tampered with |

The split is the point. Systems that can prove they failed honestly are
more trustworthy than systems that always claim to pass.

## Commands

| Command | Purpose |
|---------|---------|
| `assay demo-pack` | Generate demo packs (no config needed) |
| `assay demo-incident` | Two-act scenario: passing run vs failing run |
| `assay demo-challenge` | CTF-style good + tampered pack pair |
| `assay onboard` | Guided setup: doctor -> scan -> first run plan |
| `assay scan` | Find uninstrumented LLM call sites |
| `assay run` | Wrap command, collect receipts, build signed pack |
| `assay verify-pack` | Verify a Proof Pack (integrity + claims) |
| `assay explain` | Plain-English summary of a proof pack |
| `assay ci init github` | Generate a GitHub Actions workflow |
| `assay lock write` | Freeze verification contract to lockfile |
| `assay lock check` | Validate lockfile against current card definitions |
| `assay doctor` | Preflight check: is Assay ready here? |

## Documentation

- [Quickstart](docs/README_quickstart.md) -- install, golden path, command reference
- [Deep Dive](docs/ASSAY_DEEP_DIVE_2026Q1.md) -- architecture, trust model, honest failure
- [Decision Log](docs/ASSAY_DECISION_LOG.md) -- every locked decision and why
- [Semantic Simulation Matrix](docs/SEMANTIC_SIMULATION_MATRIX.md) -- 7 drills for UX and comprehension

## Related Repos

| Repo | Purpose |
|------|---------|
| [assay](https://github.com/Haserjian/assay) | Core CLI, SDK, conformance corpus (this repo) |
| [assay-verify-action](https://github.com/Haserjian/assay-verify-action) | GitHub Action for CI verification |
| [assay-ledger](https://github.com/Haserjian/assay-ledger) | Public transparency ledger |

## License

Apache-2.0
