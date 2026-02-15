# Assay

Tamper-evident audit trails for AI systems.

We scanned 30 popular AI projects and found 202 high-confidence LLM call
sites. Zero had tamper-evident audit trails.
[Full results](scripts/scan_study/results/report.md).

Assay adds independently verifiable execution evidence to AI systems:
cryptographically signed receipt bundles that a third party can verify
offline without trusting your server logs. Two lines of code. Four exit codes.

```bash
pip install assay-ai && assay quickstart
```

> **Boundary:** Assay proves tamper-evident internal consistency and
> completeness relative to scanned call sites. It does not prevent a fully
> compromised machine from fabricating a consistent story. That's what
> [trust tiers](docs/FULL_PICTURE.md#trust-tiers) are for.

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

Exit 1 is **audit gold**: authentic evidence that a control failed, with no
ability to edit history. Auditors love "controls can fail, but failure is
detectable and retained."

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

# 3. Run + build a signed evidence pack
assay run -c receipt_completeness -- python my_app.py

# 4. Verify
assay verify-pack ./proof_pack_*/
```

`assay scan . --report` finds every LLM call site (OpenAI, Anthropic, LangChain)
and generates a self-contained HTML gap report. `assay patch` inserts the
two-line integration. `assay run` wraps your command, collects receipts, and
produces a signed 5-file evidence pack. `assay verify-pack` checks integrity +
claims and exits with one of the four codes above. Then run `assay explain`
on any pack for a plain-English summary.

> **Why now**: EU AI Act Article 12 requires automatic logging for high-risk
> AI systems; Article 19 requires providers to retain automatically generated
> logs for at least 6 months. High-risk obligations apply from 2 Aug 2026
> (Annex III) and 2 Aug 2027 (regulated products). SOC 2 CC7.2 requires
> monitoring of system components and analysis of anomalies as security events.
> "We have logs on our server" is not independently verifiable evidence.
> Assay produces evidence that is.
> See [compliance citations](docs/compliance-citations.md) for exact references.

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

What Assay detects, what it doesn't, and how to strengthen guarantees.

**Assay detects:**
- Retroactive tampering (edit one byte, verification fails)
- Selective omission under a completeness contract
- Claiming checks that were never run
- Policy drift from a locked baseline

**Assay does not prevent:**
- A fully fabricated false run (attacker controls the machine)
- Dishonest receipt content (receipts are self-attested)
- Timestamp fraud without an external time anchor

Completeness is enforced relative to the call sites enumerated by the scanner
and/or declared by policy. Undetected call sites are a known residual risk,
reduced via multi-detector scanning and CI gating.

**To strengthen guarantees:**
- [Transparency ledger](https://github.com/Haserjian/assay-ledger) (independent witness)
- CI-held org key + branch protection (separation of signer and committer)
- External timestamping (RFC 3161)

The cost of cheating scales with the complexity of the lie. Assay doesn't
make fraud impossible -- it makes fraud expensive.

## The Evidence Compiler

Assay is an **evidence compiler** for AI execution. If you've used a build
system, you already know the mental model:

| Concept | Build System | Assay |
|---------|-------------|-------|
| Source | `.c` / `.ts` files | Receipts (one per LLM call) |
| Artifact | Binary / bundle | Evidence pack (5 files, 1 signature) |
| Tests | Unit / integration tests | Verification (integrity + claims) |
| Lock | `package-lock.json` | `assay.lock` |
| Gate | CI deploy check | CI evidence gate |

## Commands

The core path is 6 commands:

```
assay quickstart          # discover
assay scan / assay patch  # instrument
assay run                 # produce evidence
assay verify-pack         # verify evidence
assay diff                # catch regressions
assay mcp-proxy           # audit MCP tool calls
```

Full command reference:

| Command | Purpose |
|---------|---------|
| `assay quickstart` | One command: demo + scan + next steps |
| `assay status` | One-screen operational dashboard: am I set up? |
| `assay start demo` | See Assay in action (quickstart flow) |
| `assay start ci` | Guided CI evidence gate setup (5 steps) |
| `assay start mcp` | Guided MCP tool call auditing setup (4 steps) |
| `assay scan` | Find uninstrumented LLM call sites (`--report` for HTML) |
| `assay patch` | Auto-insert SDK integration patches into your entrypoint |
| `assay run` | Wrap command, collect receipts, build signed evidence pack |
| `assay verify-pack` | Verify an evidence pack (integrity + claims) |
| `assay explain` | Plain-English summary of an evidence pack |
| `assay analyze` | Cost, latency, error breakdown from pack or `--history` |
| `assay diff` | Compare packs: claims, cost, latency (`--against-previous`, `--why`, `--gate-*`) |
| `assay doctor` | Preflight check: is Assay ready here? |
| `assay mcp-proxy` | Transparent MCP proxy: intercept tool calls, emit receipts |
| `assay mcp policy init` | Generate a starter MCP policy YAML file |
| `assay ci init github` | Generate a GitHub Actions workflow |
| `assay lock write` | Freeze verification contract to lockfile |
| `assay lock check` | Validate lockfile against current card definitions |
| `assay key list` | List local signing keys and active signer |
| `assay key rotate` | Generate a new signer key and switch active signer |
| `assay key set-active` | Set active signing key for future runs |
| `assay cards list` | List built-in run cards and their claims |
| `assay cards show` | Show card details, claims, and parameters |
| `assay demo-incident` | Two-act scenario: passing run vs failing run |
| `assay demo-challenge` | CTF-style good + tampered pack pair |
| `assay demo-pack` | Generate demo packs (no config needed) |
| `assay onboard` | Guided setup: doctor -> scan -> first run plan |

## Documentation

- [Full Picture](docs/FULL_PICTURE.md) -- architecture, trust tiers, repo boundaries, release history
- [Quickstart](docs/README_quickstart.md) -- install, golden path, command reference
- [For Compliance Teams](docs/for-compliance.md) -- what auditors see, evidence artifacts, framework alignment
- [Compliance Citations](docs/compliance-citations.md) -- exact regulatory references (EU AI Act, SOC 2, ISO 42001)
- [Decision Escrow](docs/decision-escrow.md) -- protocol model: agent actions don't settle until verified
- [Roadmap](docs/ROADMAP.md) -- phases, product boundary, execution stack
- [Repo Map](docs/REPO_MAP.md) -- what lives where across the Assay ecosystem
- [Pilot Program](docs/PILOT_PROGRAM.md) -- early adopter program details

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
