# Assay

Verifiable evidence for AI systems. Independently verifiable, offline,
without server access.

Logs record what you say happened. Assay makes the record tamper-evident,
completeness-checkable, and independently verifiable -- including by
someone who does not trust you. Two lines of code. Four exit codes.

```bash
pip install assay-ai && assay quickstart
```

> **Not this:** Assay is not a logging framework, an observability dashboard,
> or a monitoring tool. It produces signed evidence bundles that a third party
> can verify offline. If you need Datadog, this isn't it.

## See It -- Then Understand It

No API key needed. Runs on synthetic data:

```bash
assay demo-incident     # two-act scenario: honest PASS vs honest FAIL
```

**Act 1**: Agent uses gpt-4 with a guardian check. Integrity PASS, claims PASS.
**Act 2**: Someone swaps the model and drops the guardian. Integrity PASS, claims FAIL.

That second result is an **honest failure** -- authentic evidence proving the
run violated its declared standards. Not a cover-up. Exit code 1.

### How that works

Assay separates two questions on purpose:

- **Integrity**: "Were these bytes tampered with after creation?" (signatures, hashes, required files)
- **Claims**: "Does this evidence satisfy our declared governance checks?" (receipt types, counts, field values)

| Integrity | Claims | Exit | Meaning |
|-----------|--------|------|---------|
| PASS | PASS | 0 | Evidence checks out, behavior meets standards |
| PASS | FAIL | 1 | Honest failure: authentic evidence of a standards violation |
| FAIL | -- | 2 | Tampered evidence |
| -- | -- | 3 | Bad input (missing files, invalid arguments) |

The split is the point. Systems that can prove they failed honestly are
more trustworthy than systems that always claim to pass.

## Add to Your Project

```bash
# 1. Find uninstrumented LLM calls
assay scan . --report

# 2. Patch (one line per SDK, or auto-patch all)
assay patch .

# 3. Run + build a signed proof pack
assay run -c receipt_completeness -- python my_app.py

# 4. Verify
assay verify-pack ./proof_pack_*/
```

`assay scan . --report` finds every LLM call site (OpenAI, Anthropic, LangChain)
and generates a self-contained HTML gap report. `assay patch` inserts the
two-line integration. `assay run` wraps your command, collects receipts, and
produces a signed 5-file proof pack. `assay verify-pack` checks integrity +
claims and exits with one of the four codes above. Then run `assay explain`
on any pack for a plain-English summary.

> **Why now**: EU AI Act Articles 12 and 19 require logging and traceability
> for high-risk AI systems. SOC 2 CC7.2 requires evidence of monitoring.
> "We have logs on our server" is not independently verifiable evidence.
> Assay produces evidence that is.

## CI Gate

Three commands, three exit codes, one lockfile:

```bash
assay run -c receipt_completeness -- python my_app.py
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
assay diff ./baseline_pack/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0 --gate-strict
```

The lockfile catches config drift. Verify-pack catches tampering. Diff
catches regressions and budget overruns. See
[Decision Escrow](docs/decision-escrow.md) for the protocol model.

```bash
# Lock your verification contract
assay lock write --cards receipt_completeness -o assay.lock
```

### Daily use after CI is green

**Regression forensics**:

```bash
assay diff ./proof_pack_*/ --against-previous --why
```

`--against-previous` auto-discovers the baseline pack.
`--why` traces receipt chains to explain what regressed and which call sites caused it.

**Cost/latency drift (from receipts)**:

```bash
assay analyze --history --since 7
```

Shows cost, latency percentiles, error rates, and per-model breakdowns
from your local trace history.

## Trust Model

What Assay proves, what it doesn't, and how to strengthen guarantees.

**Assay detects:**
- Retroactive tampering (edit one byte, verification fails)
- Selective omission under a completeness contract
- Claiming checks that were never run
- Policy drift from a locked baseline

**Assay does not prevent:**
- A fully fabricated false run (attacker controls the machine)
- Dishonest receipt content (receipts are self-attested)
- Timestamp fraud without an external time anchor

**To strengthen guarantees:**
- [Transparency ledger](https://github.com/Haserjian/assay-ledger) (independent witness)
- CI-held org key + branch protection (separation of signer and committer)
- External timestamping (RFC 3161)

The cost of cheating scales with the complexity of the lie. Assay doesn't
make fraud impossible -- it makes fraud expensive.

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
| `assay analyze` | Cost, latency, error breakdown from pack or `--history` |
| `assay diff` | Compare packs: claims, cost, latency (`--against-previous`, `--why`, `--gate-*`) |
| `assay key list` | List local signing keys and active signer |
| `assay key rotate` | Generate a new signer key and switch active signer |
| `assay key set-active` | Set active signing key for future runs |
| `assay ci init github` | Generate a GitHub Actions workflow |
| `assay lock write` | Freeze verification contract to lockfile |
| `assay lock check` | Validate lockfile against current card definitions |
| `assay cards list` | List built-in run cards and their claims |
| `assay cards show` | Show card details, claims, and parameters |
| `assay status` | One-screen operational dashboard: am I set up? |
| `assay start demo` | See Assay in action (quickstart flow) |
| `assay start ci` | Guided CI evidence gate setup (5 steps) |
| `assay start mcp` | Guided MCP tool call auditing setup (4 steps) |
| `assay mcp policy init` | Generate a starter MCP policy YAML file |
| `assay mcp-proxy` | Transparent MCP proxy: intercept tool calls, emit receipts |
| `assay doctor` | Preflight check: is Assay ready here? |

## Documentation

- [Quickstart](docs/README_quickstart.md) -- install, golden path, command reference
- [Roadmap](docs/ROADMAP.md) -- phases, product boundary, execution stack
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
- **Want this in your stack in 2 weeks?** [Pilot program](docs/PILOT_PROGRAM.md) --
  we instrument your AI workflows, set up CI gates, and hand you a working
  evidence pipeline. [Open a pilot inquiry](https://github.com/Haserjian/assay/issues/new?template=pilot-inquiry.md).

## Related Repos

| Repo | Purpose |
|------|---------|
| [assay](https://github.com/Haserjian/assay) | Core CLI, SDK, conformance corpus (this repo) |
| [assay-verify-action](https://github.com/Haserjian/assay-verify-action) | GitHub Action for CI verification |
| [assay-ledger](https://github.com/Haserjian/assay-ledger) | Public transparency ledger |

## License

Apache-2.0
