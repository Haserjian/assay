# Gate Report Spec

**Status**: Design spec (not yet implemented)
**Feature**: `assay diff --gate --report FILE`
**Audience**: Developers triaging CI failures, engineering managers reviewing PRs, compliance teams auditing runs

---

## Problem

When `assay diff --gate` fails in CI, the developer sees an exit code
and a few lines of text in the build log. They need to open the JSON
output, parse it, and figure out what went wrong. Engineering managers
and compliance reviewers can't access build logs at all.

A shareable HTML report makes gate failures (and passes) visible to
everyone who needs to see them, without requiring CLI access.

## Interface

```bash
# Generate report alongside normal output
assay diff ./baseline/ ./current/ \
  --gate-cost-pct 20 --gate-errors 0 --gate-strict \
  --report gate_report.html

# JSON + report (both)
assay diff ./baseline/ ./current/ \
  --gate-cost-pct 20 --json \
  --report gate_report.html
```

- `--report FILE` generates an HTML file. Does not change exit code or
  stdout behavior.
- If FILE ends in `.json`, emit structured JSON instead of HTML.
- Report is always generated, even when gates pass (evidence of clean run
  is also valuable).

## Report Contents

### Header

| Field | Source |
|-------|--------|
| Report title | "Assay Diff Gate Report" |
| Generated at | ISO 8601 timestamp |
| Assay version | `assay.__version__` |
| Pack A path | `DiffResult.pack_a.path` |
| Pack B path | `DiffResult.pack_b.path` |
| Pack A timestamp | `pack_a.timestamp_start` |
| Pack B timestamp | `pack_b.timestamp_start` |
| Overall verdict | PASS / FAIL (from exit code) |

### Section 1: Integrity

- Status: PASS or FAIL
- If FAIL: list of integrity errors
- Pack A and Pack B signer IDs and fingerprints
- Signer changed: yes/no
- Verifier version changed: yes/no

### Section 2: Claims

Table with one row per claim:

| Claim ID | Pack A | Pack B | Status |
|----------|--------|--------|--------|
| receipt_completeness | PASS | PASS | unchanged |
| guardian_enforcement | PASS | FAIL | **REGRESSED** |

- Row background: green (pass/improved), red (regressed), yellow (new/removed), gray (unchanged)
- Regression count in section header

### Section 3: Gates

Table with one row per gate:

| Gate | Threshold | Actual | Verdict |
|------|-----------|--------|---------|
| cost_pct | 20% | 15.2% | PASS |
| p95_pct | -- | -- | skipped |
| errors | 0 | 3 | **FAIL** |

- Strict mode indicator (if `--gate-strict` was used)
- Summary line: "2 passed, 1 failed, 0 skipped"
- Failed gates highlighted red
- Skipped gates:
  - Default mode: gray, "skipped (no data)"
  - Strict mode: red, "FAIL (missing data, strict mode)"

### Section 4: Summary Deltas

Side-by-side comparison (same data as CLI table output):

| Metric | Pack A | Pack B | Delta |
|--------|--------|--------|-------|
| Model calls | 47 | 52 | +5 (+11%) |
| Total tokens | 125,000 | 142,000 | +17,000 (+14%) |
| Est. cost | $1.2500 | $1.4375 | +$0.1875 (+15%) |
| Errors | 0 | 3 | +3 |
| Latency p50 | 450ms | 480ms | +30ms (+7%) |
| Latency p95 | 1200ms | 1350ms | +150ms (+13%) |

- Delta column: green for decrease, red for increase (cost/errors/latency)

### Section 5: Model Churn

| Model | A Calls | B Calls | Delta | Status |
|-------|---------|---------|-------|--------|
| gpt-4o | 40 | 35 | -5 | changed |
| claude-sonnet-4 | 0 | 12 | +12 | **new** |
| gpt-3.5-turbo | 7 | 0 | -7 | removed |

### Footer

- Pack A manifest hash
- Pack B manifest hash
- Exit code and its meaning
- Link: "Verified with Assay -- https://github.com/Haserjian/assay"

## Design Constraints

1. **Self-contained HTML**. Single file, no external CSS/JS dependencies.
   Inline all styles. Must render in any browser and in GitHub PR comments
   when attached as an artifact link.

2. **Deterministic output**. Same inputs produce identical HTML (no random
   IDs, no current-time in body -- use pack timestamps only, generation
   timestamp in header is the one exception).

3. **Consistent with existing reports**. Follow the same visual style as
   the evidence gap report (`reporting/evidence_gap.py`) -- CSS variables,
   color scheme, layout patterns.

4. **No new dependencies**. HTML is generated with string formatting or
   the existing report infrastructure. No Jinja2, no template engine.

## Implementation Notes

- New file: `src/assay/reporting/gate_report.py`
- Function: `generate_gate_report(result: DiffResult, gate_eval: GateEvaluation | None, path: Path) -> None`
- Wire into `diff_cmd()`: if `--report` is set, call after diff completes
- CSS from `reporting/evidence_gap.py` can be extracted into a shared
  `reporting/_styles.py` if duplication is excessive

## CI Integration

```yaml
- name: Run with receipts
  run: assay run -c receipt_completeness -- python your_app.py

- name: Verify integrity + contract
  run: assay verify-pack ./proof_pack_*/ --lock assay.lock

- name: Diff with gates
  run: |
    assay diff ./baseline_pack/ ./proof_pack_*/ \
      --gate-cost-pct 25 --gate-errors 0 --gate-strict \
      --report gate_report.html

- name: Upload gate report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: gate-report
    path: gate_report.html
```

The `if: always()` ensures the report uploads even when the diff fails.
This is the key UX win: the developer clicks the artifact link in the
failed check and sees exactly why it failed, with all the context in
one page.
