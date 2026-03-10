# Start Here

Six steps from install to evidence in CI.

## 1. Install

```bash
# macOS / Linux
python3 -m pip install assay-ai
```

```powershell
# Windows
py -m pip install assay-ai
```

Requires Python 3.9+. Installs the `assay` CLI with zero runtime dependencies on your production code.
Verify it's on PATH: `assay version`

Installing Assay gives you the CLI and receipt runtime. It does **not**
record anything until your app is instrumented and run through Assay.

## 2. See your score

```bash
assay scan .
assay score .
```

`scan` finds every LLM call site (OpenAI, Anthropic, Gemini, LiteLLM, LangChain). `score` gives you an Evidence Readiness Score (0--100, A--F). This is your starting point.

Think of the flow as:

```text
install Assay -> instrument the runtime -> run with a trace id -> build proof pack
```

## 3. Generate a report

```bash
assay report . -o evidence_report.html --sarif
```

Opens a self-verifying HTML report with a what-if score simulator. The `--sarif` flag also produces a SARIF file for GitHub Code Scanning. Share the HTML with your team -- it includes a built-in integrity check.

## 4. Set a baseline

```bash
assay gate save-baseline
```

Saves your current score as the CI floor. Future PRs that drop below this score will fail the gate.

This creates `.assay/score-baseline.json`, which should be committed so CI can enforce regression checks.

## 5. Generate the CI workflow

```bash
assay ci init github --run-command "python your_app.py"
```

This writes `.github/workflows/assay-verify.yml` with three jobs:

- **assay-gate** -- score-based enforcement (fails PRs that regress)
- **assay-verify** -- proof pack generation + cryptographic verification
- **assay-report** -- HTML report artifact + SARIF upload to Code Scanning

To set a minimum score threshold:

```bash
assay ci init github --run-command "python your_app.py" --min-score 60
```

## 6. Push

```bash
git add .github/workflows/assay-verify.yml
git add .assay/score-baseline.json
git commit -m "Add Assay evidence pipeline"
git push
```

Open a PR and you'll see all three checks in your GitHub status checks.

## What's next

- `assay explain ./proof_pack_*/` -- plain-English summary of any evidence pack
- `assay diff` -- compare packs for cost/latency regressions
- [CI integration](ci-integration.md) -- why CI matters and how to enforce evidence discipline
- [Quickstart reference](README_quickstart.md) -- full command reference
- [Order of operations](ORDER_OF_OPERATIONS.md) -- detailed workflow guide
- [Pilot program](PILOT_PROGRAM.md) -- get hands-on help setting this up
