# External Witness Ritual

Purpose: prove the published artifact survives contact with reality
outside the producer's machine. Not a vibe check — a constitutional
proof step with receipts.

## Why this matters

Internal evidence proves the package can be built, tests pass, and the
dev install works. External witness proves the published artifact is the
thing that works, the docs are sufficient, and there are no hidden local
dependencies.

## Witness tiers

| Tier | What | Proves |
|------|------|--------|
| 1. Mechanical | Fresh venv, public install, basic CLI | Artifact viability |
| 2. Operator | Real human follows README with no coaching | Doc sufficiency |
| 3. Adversarial | Different Python version, missing deps, edge cases | Resilience |
| 4. Ecosystem | Different OS or CI runner | Portability |

Tier 1 is the release gate. Higher tiers are strengthening evidence.

## Tier 1: Mechanical witness script

Run this in a clean environment with no repo context:

```bash
# Environment
python3 -m venv /tmp/assay-witness
source /tmp/assay-witness/bin/activate
python -m pip install --upgrade pip

# Install from public index only
pip install assay-ai==1.17.0

# Version check
python -c "import assay; print(assay.__version__)"
# Expected: 1.17.0

# CLI entrypoints
assay --help
assay passport --help

# Canonical proof corridor
assay passport demo --output-dir /tmp/assay-witness-demo
```

## Expected outputs

### Version
```
1.17.0
```

### passport --help
12 commands: show, verify, sign, render, status, xray, mint,
challenge, supersede, revoke, diff, demo.

### passport demo
10 steps complete. 6 artifacts in output directory:
- `passport_v1.json` — signed, has `passport_id` and `signature`
- `passport_v1.html` — self-contained HTML (~28KB)
- `passport_v2.json` — signed, different `passport_id` from v1
- `challenge_*.json` — signed receipt with `event_id`
- `supersession_*.json` — signed receipt linking v1 to v2
- `trust_diff.html` — diff report

## Pass/fail criteria

| Check | Pass | Fail |
|-------|------|------|
| Install | No errors | Any install error |
| Version | Reports target version | Wrong version or 0.0.0-dev |
| passport --help | Shows 12 commands | Missing commands or import error |
| Demo | Exits 0, 10 steps complete | Any step fails |
| v1 signed | Has `signature` and `passport_id` | Missing fields |
| v1 != v2 | Different `passport_id` values | Identical IDs |

## Receipt format

The witness should capture and return:

```
OS: <e.g., macOS 14.3, Ubuntu 22.04>
Python: <e.g., 3.11.7>
Date: <ISO 8601>
Package version resolved: <from pip show assay-ai>
Commands run: <exact commands>
Terminal output: <full or relevant excerpts>
Deviations from docs: <any steps where they had to improvise>
Warnings: <any unexpected warnings>
Pass/fail: <per criteria above>
```

## Known acceptable warnings

- `pip` version upgrade notice — cosmetic
- `UserWarning: Protocol field ... not mapped` — MCP conformance, unrelated

## If it fails

1. Record the exact failure point and output
2. Do not retry with workarounds — the failure is the data
3. File as a release issue with the witness receipt attached
4. The failure determines whether this is a packaging bug, a docs bug,
   or a hidden dependency

## Escalation

If Tier 1 fails, do not promote to Tier 2. Fix the artifact first.
If Tier 2 fails (docs insufficient), fix docs and re-run Tier 2.
Tier 3 and 4 failures are strengthening data, not release blockers.
