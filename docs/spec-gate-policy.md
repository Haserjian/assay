# Gate Policy Spec

**Status**: Implementation spec
**Feature**: `assay.gates.yaml` + `diff --gate` hardening
**Prerequisite for**: Gate HTML report, MCP receipt layer CI integration

---

## Problem

Gate thresholds are CLI flags today. This means:
- Gates aren't version-controlled alongside the codebase
- Every CI workflow duplicates the same flags
- No absolute budgets (only percentage-relative)
- Cost isn't deterministic (no pricing hash or receipt-level cost field)
- No way to express compound policies ("cost AND errors AND latency")

## Changes

### 1. Gate policy file: `assay.gates.yaml`

```yaml
# assay.gates.yaml -- version-controlled gate policy
version: "1"

gates:
  cost_pct:
    threshold: 25
    unit: pct
    description: "Max cost increase vs baseline"

  cost_abs:
    threshold: 5.00
    unit: usd
    description: "Max absolute cost for pack B"

  p95_pct:
    threshold: 30
    unit: pct
    description: "Max p95 latency increase vs baseline"

  p95_abs:
    threshold: 3000
    unit: ms
    description: "Max absolute p95 latency for pack B"

  errors:
    threshold: 0
    unit: count
    description: "Max error count in pack B"

strict: true  # missing data = FAIL (not skip)
```

**Semantics:**
- `version: "1"` -- file format version for forward compatibility
- Each gate has `threshold`, `unit`, and optional `description`
- `strict` at top level sets default; can be overridden per gate
- CLI flags override file values (explicit flag wins)
- File is optional. CLI-only workflows continue to work unchanged.

### 2. New CLI flags

```
assay diff ./baseline/ ./current/ \
  --gates assay.gates.yaml         # load policy file
  --gate-cost-abs 5.00             # NEW: absolute cost ceiling (USD)
  --gate-p95-abs 3000              # NEW: absolute p95 ceiling (ms)
  --gate-cost-pct 25               # existing
  --gate-p95-pct 30                # existing
  --gate-errors 0                  # existing
  --gate-strict                    # existing
  --report gate_report.html        # existing (from gate-report-spec.md)
```

**Resolution order:**
1. Load `--gates FILE` if provided
2. Apply CLI flag overrides (any explicit flag replaces file value)
3. `--gate-strict` overrides file `strict` field

### 3. New gate types in `diff.py`

Add to `evaluate_gates()`:

**cost_abs**: Absolute cost ceiling
```python
if cost_abs is not None:
    b_cost = result.b_analysis.total_cost if result.b_analysis else None
    if b_cost is not None:
        passed = b_cost <= cost_abs
        results.append(GateResult(
            name="cost_abs", threshold=cost_abs, actual=b_cost,
            passed=passed, unit="usd"
        ))
    elif strict:
        results.append(GateResult(
            name="cost_abs", threshold=cost_abs, actual=None,
            passed=False, unit="usd", skipped=True
        ))
```

**p95_abs**: Absolute p95 latency ceiling
```python
if p95_abs is not None:
    b_p95 = result.b_analysis.p95_latency_ms if result.b_analysis else None
    if b_p95 is not None:
        passed = b_p95 <= p95_abs
        results.append(GateResult(
            name="p95_abs", threshold=p95_abs, actual=b_p95,
            passed=passed, unit="ms"
        ))
    elif strict:
        results.append(GateResult(
            name="p95_abs", threshold=p95_abs, actual=None,
            passed=False, unit="ms", skipped=True
        ))
```

### 4. Time-deterministic cost

Today, cost is computed in `analyze.py` from token counts + a hardcoded pricing table. This is fragile: if the pricing table updates, old
runs retroactively change cost, breaking gate comparisons.

**Solution:** Record cost AND pricing snapshot at emit time.

**Receipt field additions:**
```python
data["cost_usd"] = _compute_cost(model, input_tokens, output_tokens)
data["pricing_snapshot_id"] = _PRICING_SNAPSHOT_ID  # e.g. "2026-02-15"
```

**Pricing snapshot design:**
- Vendored pricing table lives in `src/assay/pricing.py`
- Table has an immutable `PRICING_SNAPSHOT_ID` (date string, e.g. `"2026-02-15"`)
- `_compute_cost(model, in_tokens, out_tokens)` uses the vendored table
- Receipt stores both `cost_usd` and `pricing_snapshot_id`
- `analyze` sums receipt-level `cost_usd` instead of recomputing
- If `cost_usd` is absent (legacy receipts), fall back to pricing table lookup
- Pricing table hash (`sha256(sorted(table))`) goes into manifest as `pricing_table_hash`

**Why this matters:** A gate that says "cost must not increase >25%" is
meaningless if the pricing table changed between baseline and current.
With `pricing_snapshot_id` in both packs, diff can warn when snapshots
differ and the comparison may be unreliable.

**Diff warning when snapshots differ:**
```
Warning: Pack A used pricing snapshot 2026-01-15, Pack B used 2026-02-15.
Cost comparison may reflect pricing changes, not usage changes.
```

### 5. Gate config hash in lockfile

Gate policy should be detectable for drift, just like claim cards and
signer policy.

**When `assay.gates.yaml` exists alongside `assay.lock`:**
- `assay lock write` computes `sha256(canonical(gates_config))` and
  stores it as `gates_config_hash` in the lockfile
- `assay verify-pack --lock` checks that the gates config hash matches
- If gates config changed since lock was written: mismatch warning

**Lockfile field addition:**
```yaml
# In assay.lock
gates_config_hash: "sha256:abc123..."   # Hash of assay.gates.yaml
```

This makes policy drift detectable: if someone loosens gates without
updating the lock, CI catches it.

### 5. JSON output structure update

Current JSON output from `--json`:
```json
{
  "pack_a": {...},
  "pack_b": {...},
  "claims": [...],
  "gates": {"all_passed": true, "results": [...]}
}
```

Add explicit booleans for programmatic consumption:
```json
{
  "integrity_failed": false,
  "claims_regressed": false,
  "gates_failed": false,
  "exit_code": 0,
  ...
}
```

### 6. `assay gate init`

New subcommand that generates a starter `assay.gates.yaml`:

```bash
assay gate init                    # writes assay.gates.yaml with sensible defaults
assay gate init -o custom.yaml     # custom output path
```

Default file has all gates commented out except `errors: 0` and `cost_pct: 25`.

---

## Implementation Plan

### Files to modify

| File | Change |
|------|--------|
| `src/assay/diff.py` | Add `cost_abs`, `p95_abs` gate types. Add `load_gate_policy()`. |
| `src/assay/commands.py` | Add `--gates`, `--gate-cost-abs`, `--gate-p95-abs` flags. Add `gate init` subcommand. Add JSON booleans. |
| `src/assay/integrations/openai.py` | Add `cost_usd` field to receipts. |
| `src/assay/integrations/anthropic.py` | Add `cost_usd` field to receipts. |
| `src/assay/integrations/langchain.py` | Add `cost_usd` field to receipts. |
| `tests/assay/test_diff.py` | Tests for new gate types, policy file loading, JSON booleans. |

### New files

| File | Purpose |
|------|---------|
| `src/assay/gate_policy.py` | YAML parsing, validation, merge with CLI flags. |
| `tests/assay/test_gate_policy.py` | Gate policy file tests. |

### Test cases

1. `cost_abs` gate passes when under threshold
2. `cost_abs` gate fails when over threshold
3. `cost_abs` gate skips when no data (non-strict)
4. `cost_abs` gate fails when no data (strict)
5. Same 4 tests for `p95_abs`
6. Policy file loads and applies all gates
7. CLI flags override policy file values
8. `--gate-strict` overrides file `strict` field
9. Missing policy file raises clean error
10. Invalid policy file raises clean error with field name
11. `gate init` creates valid YAML
12. JSON output includes `integrity_failed`, `claims_regressed`, `gates_failed`
13. `cost_usd` in receipt is summed correctly by analyze
14. Legacy receipts without `cost_usd` fall back to pricing table
15. `pricing_snapshot_id` recorded in receipt alongside `cost_usd`
16. Diff warns when pricing snapshots differ between pack A and pack B
17. `gates_config_hash` written to lockfile by `lock write`
18. `verify-pack --lock` detects gates config drift

---

## Exit criteria

- [ ] `assay diff --gates assay.gates.yaml` loads and evaluates all gate types
- [ ] Absolute gates (`cost_abs`, `p95_abs`) work alongside percentage gates
- [ ] CLI flags override file values
- [ ] JSON output has `integrity_failed`, `claims_regressed`, `gates_failed` booleans
- [ ] `cost_usd` and `pricing_snapshot_id` emitted in new receipts
- [ ] `analyze` sums receipt-level `cost_usd`, falls back for legacy receipts
- [ ] Diff warns when pricing snapshots differ between packs
- [ ] `gates_config_hash` in lockfile, verified by `verify-pack --lock`
- [ ] `assay gate init` produces valid starter file
- [ ] All existing diff tests still pass
- [ ] 18+ new tests for gate policy features
