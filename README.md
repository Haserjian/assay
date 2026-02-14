# Assay

Tamper-evident audit trails for AI systems. Logs record what you say
happened. Assay makes the record tamper-evident, completeness-checkable,
and independently verifiable -- including by someone who does not trust
you. Integrity PASS + claims FAIL is an **honest failure**: authentic
evidence that controls were violated. Assay does not prove external truth;
it proves evidence integrity and makes omission detectable.
Easier than a spreadsheet, harder to bullshit.

```bash
pip install assay-ai && assay quickstart
```

## 60-Second Demo

No API key needed. This runs a two-act scenario with synthetic data:

- **Act 1**: Agent uses gpt-4 with a guardian check. Result: integrity PASS, claims PASS.
- **Act 2**: Someone swaps the model and drops the guardian. Result: integrity PASS, claims FAIL.

That second result is an **honest failure** -- authentic evidence proving the
run violated its declared standards. Not a cover-up. Not theater. Exit code 1.

```bash
assay demo-incident     # two-act scenario: honest PASS vs honest FAIL
assay demo-challenge    # optional CTF: spot the tampered pack
assay demo-pack         # optional: build + verify from scratch
```

## The Golden Path

```bash
# 0. See Assay in action (recommended first step)
assay quickstart
# Or: assay onboard .  (guided project setup with doctor + CI guidance)

# 1. Find uninstrumented LLM calls
assay scan . --report   # generates a self-contained HTML gap report

# 2. Instrument (one line per SDK, or auto-patch)
assay patch .
#    from assay.integrations.openai import patch; patch()

# 3. Produce a signed proof pack
assay run -c receipt_completeness -- python my_app.py
# Add -c guardian_enforcement when you have a policy gate

# 4. Verify + explain
assay verify-pack ./proof_pack_*/
assay explain ./proof_pack_*/

# 5. Lock the verification contract
assay lock write --cards receipt_completeness -o assay.lock
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
```

### CI Gate (three commands, three exit codes)

```bash
assay run -c receipt_completeness -- python my_app.py
assay verify-pack ./proof_pack_*/ --lock assay.lock
assay diff ./baseline_pack/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0 --gate-strict
```

The lockfile catches config drift. Verify-pack catches tampering. Diff
catches regressions and budget overruns. See
[Decision Escrow](docs/decision-escrow.md) for the protocol model behind
this workflow.

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
| -- | -- | 3 | Bad input (invalid arguments, missing files) |

The split is the point. Systems that can prove they failed honestly are
more trustworthy than systems that always claim to pass.

## Commands

| Command | Purpose |
|---------|---------|
| `assay quickstart` | One command: demo + scan + next steps |
| `assay demo-incident` | Two-act scenario: passing run vs failing run |
| `assay demo-challenge` | CTF-style good + tampered pack pair |
| `assay demo-pack` | Generate demo packs (no config needed) |
| `assay onboard` | Guided setup: doctor -> scan -> first run plan |
| `assay scan` | Find uninstrumented LLM call sites (`--report` for HTML) |
| `assay patch` | Auto-insert SDK integration patches into your entrypoint |
| `assay run` | Wrap command, collect receipts, build signed pack |
| `assay verify-pack` | Verify a Proof Pack (integrity + claims) |
| `assay explain` | Plain-English summary of a proof pack |
| `assay ci init github` | Generate a GitHub Actions workflow |
| `assay lock write` | Freeze verification contract to lockfile |
| `assay lock check` | Validate lockfile against current card definitions |
| `assay cards list` | List built-in run cards and their claims |
| `assay cards show` | Show card details, claims, and parameters |
| `assay diff` | Compare two packs: claims, cost, latency, model churn (`--gate-*`, `--against-previous`, `--why`) |
| `assay key list` | List local signing keys and active signer |
| `assay key rotate` | Generate a new signer key and switch active signer |
| `assay key set-active` | Set active signing key for future runs |
| `assay analyze` | Receipt-level time-series analysis |
| `assay doctor` | Preflight check: is Assay ready here? |

## Documentation

- [Quickstart](docs/README_quickstart.md) -- install, golden path, command reference
- [Decision Escrow](docs/decision-escrow.md) -- protocol model: agent actions don't settle until verified
- [For Compliance Teams](docs/for-compliance.md) -- what auditors see, evidence artifacts, framework alignment
- [Repo Map](docs/REPO_MAP.md) -- what lives where across the Assay ecosystem
- [Pilot Program](docs/PILOT_PROGRAM.md) -- early adopter program details

## Scan Study

We scanned 30 popular open-source AI projects for tamper-evident audit
trails. Found 202 high-confidence LLM SDK call sites across 21 projects.
Zero had evidence emission at any call site.
[Full results](scripts/scan_study/results/report.md).

## Common Issues

- **"No receipts emitted" after `assay run`**: First, check whether your code
  has call sites: `assay scan .` -- if scan finds 0 sites, you may not be
  using a supported SDK yet. If scan finds sites, check: (1) Is `# assay:patched`
  in the file? Run `assay scan . --report` to see patch status per file.
  (2) Did you install the SDK extra (`pip install assay-ai[openai]`)?
  (3) Did you use `--` before your command (`assay run -- python app.py`)?
  Run `assay doctor` for a full diagnostic.

- **LangChain projects**: `assay patch` auto-instruments OpenAI and Anthropic
  SDKs but not LangChain (which uses callbacks, not monkey-patching). For
  LangChain, add `AssayCallbackHandler()` to your chain's `callbacks` parameter
  manually. See `src/assay/integrations/langchain.py` for the handler.

- **`assay run python app.py` gives "No command provided"**: You need the `--`
  separator: `assay run -c receipt_completeness -- python app.py`. Everything
  after `--` is passed to the subprocess.

- **Quickstart blocked on large directories**: `assay quickstart` guards against
  scanning system directories (>10K Python files). Use `--force` to bypass:
  `assay quickstart --force`.

## Get Involved

- **Try it**: `pip install assay-ai && assay quickstart`
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
