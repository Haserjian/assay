# Assay

Tamper-evident audit trails for AI systems. When someone asks "prove
what your AI did," logs are not enough: whoever controls the server
controls the story. Assay gives you a signed evidence bundle that
anyone can verify independently, including someone who does not trust
you. Integrity PASS + claims FAIL is an **honest failure**: authentic
evidence that controls were violated. Assay does not prove model
correctness; it proves evidence integrity and control conformance.
Easier than a spreadsheet, harder to bullshit.

```bash
pip install assay-ai && assay demo-incident
```

## 60-Second Demo

No API key needed. This runs a two-act scenario with synthetic data:

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
assay scan . --report   # generates a self-contained HTML gap report

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
| `assay scan` | Find uninstrumented LLM call sites (`--report` for HTML) |
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

## Scan Study

We scanned 30 popular open-source AI projects for tamper-evident audit
trails. Found 202 high-confidence LLM SDK call sites across 21 projects.
Zero had evidence emission at any call site.
[Full results](scripts/scan_study/results/report.md).

## Get Involved

- **Try it**: `pip install assay-ai && assay demo-incident`
- **Questions / feedback**: [GitHub Discussions](https://github.com/Haserjian/assay/discussions)
- **Bug reports**: [Issues](https://github.com/Haserjian/assay/issues)
- **Pilot integration**: Want help instrumenting your AI stack?
  [Open a pilot inquiry](https://github.com/Haserjian/assay/issues/new?template=pilot-inquiry.md)

## Related Repos

| Repo | Purpose |
|------|---------|
| [assay](https://github.com/Haserjian/assay) | Core CLI, SDK, conformance corpus (this repo) |
| [assay-verify-action](https://github.com/Haserjian/assay-verify-action) | GitHub Action for CI verification |
| [assay-ledger](https://github.com/Haserjian/assay-ledger) | Public transparency ledger |

## License

Apache-2.0
