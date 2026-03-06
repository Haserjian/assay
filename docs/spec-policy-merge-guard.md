# Policy Merge Guard Spec

**Status**: Implementation spec
**Feature**: `assay policy impact` + `PolicyImpactReceipt` + CI gate
**Depends on**: `time_machine.py` (shipped v1.9.0), `mcp_policy.py`, `store.py`

---

## Problem

Policy changes (MCP allow/deny lists, budget limits, mode switches) affect
every future tool call. Today there is no gate for policy PRs:

- Developers change `assay.mcp-policy.yaml` and merge without impact analysis
- Compliance teams can't prove they reviewed the blast radius
- No signed evidence that impact was assessed before deployment
- The Time Machine (`assay incident replay`) analyzes one pack; operators need
  multi-pack aggregate analysis with pass/fail thresholds

## Solution

A new top-level command `assay policy impact` that:

1. Replays N historical packs against a candidate policy
2. Computes aggregate impact (newly denied / newly allowed / risk delta)
3. Emits a signed `PolicyImpactReceipt` into the trace
4. Exits with CI-friendly codes based on configurable thresholds

Combined with `assay diff --gate`, this creates a **two-gate CI**:
- `diff --gate` gates **code behavior** changes
- `policy impact` gates **policy** changes

---

## CLI

```
assay policy impact \
  --policy-new candidate.yaml \
  --policy-old current.yaml \          # optional; defaults to "no policy"
  --packs ./proof_packs/ \             # directory of pack dirs, or glob
  --fail-if-newly-denied 0 \           # CI threshold (default: no limit)
  --fail-if-risk-delta 0.1 \           # fractional threshold (default: no limit)
  --emit-receipt \                     # write PolicyImpactReceipt to trace
  --format text|md|json \
  --json
```

### Arguments

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--policy-new` | Path | required | Candidate policy YAML |
| `--policy-old` | Path | None | Current/baseline policy YAML |
| `--packs` | Path | required | Directory containing pack dirs |
| `--fail-if-newly-denied` | int | None | Fail if total newly denied > N |
| `--fail-if-risk-delta` | float | None | Fail if risk delta fraction > X |
| `--emit-receipt` | bool | False | Emit PolicyImpactReceipt to trace |
| `--format` | str | "text" | Output format: text, md, json |
| `--json` | bool | False | Alias for --format json |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Impact assessed, thresholds passed (or no thresholds set) |
| 1 | Threshold breached (CI should block merge) |
| 3 | Bad input (missing files, invalid policy) |

---

## PolicyImpactReceipt schema

```json
{
  "receipt_id": "r_<uuid>",
  "type": "policy_impact",
  "schema_version": "3.0",
  "timestamp": "2026-02-22T10:00:00+00:00",

  "policy_old_hash": "sha256:<hex>",
  "policy_new_hash": "sha256:<hex>",
  "policy_old_path": "current.yaml",
  "policy_new_path": "candidate.yaml",

  "packs_examined": 5,
  "mcp_calls_examined": 127,
  "model_calls_examined": 340,

  "newly_denied_count": 3,
  "newly_allowed_count": 0,
  "risk_delta": 0.024,

  "severity_breakdown": {
    "deny_list": 2,
    "not_in_allow": 1,
    "budget_exceeded": 0,
    "argument_denied": 0
  },

  "top_changed_tools": [
    {"tool_name": "exec_command", "newly_denied": 2, "reason": "deny_list"},
    {"tool_name": "write_file",  "newly_denied": 1, "reason": "not_in_allow"}
  ],

  "thresholds": {
    "fail_if_newly_denied": 0,
    "fail_if_risk_delta": null
  },

  "ci_verdict": "fail",
  "ci_verdict_reason": "newly_denied_count (3) exceeds threshold (0)"
}
```

### Field definitions

| Field | Type | Description |
|-------|------|-------------|
| `policy_old_hash` | string | SHA-256 of baseline policy (null if no baseline) |
| `policy_new_hash` | string | SHA-256 of candidate policy |
| `packs_examined` | int | Number of packs replayed |
| `mcp_calls_examined` | int | Total MCP tool call receipts replayed |
| `model_calls_examined` | int | Total model call receipts in packs |
| `newly_denied_count` | int | Tool calls that would be newly denied |
| `newly_allowed_count` | int | Previously denied calls now allowed |
| `risk_delta` | float | `newly_denied_count / mcp_calls_examined` (0.0 if none) |
| `severity_breakdown` | object | Counts by denial reason category |
| `top_changed_tools` | array | Tools most affected, sorted by impact |
| `thresholds` | object | Configured CI thresholds (null = no limit) |
| `ci_verdict` | string | "pass" or "fail" |
| `ci_verdict_reason` | string | Human-readable explanation of verdict |

---

## Replay semantics (deterministic boundaries)

The replay is a **deterministic re-judgment of receipt fields only**.

What IS replayed:
- Each `mcp_tool_call` receipt's `tool_name` is evaluated against the candidate policy
- Deny/allow verdicts are compared to the original `policy_verdict` field
- Per-tool call counts and session budgets are tracked across the pack

What is NOT replayed:
- Model outputs are not re-generated
- Tool call arguments are not re-fetched (argument deny patterns use receipt fields)
- Timestamps are not re-evaluated (wall-time budgets use receipt `duration_ms`)
- No API calls, no nondeterminism, no cost

This means the replay is:
- **Reproducible**: same inputs always produce same output
- **Offline**: no network access required
- **Free**: no API costs
- **Fast**: processes thousands of receipts per second

---

## Risk delta computation

```
risk_delta = newly_denied_count / mcp_calls_examined
```

- If `mcp_calls_examined == 0`: risk_delta = 0.0 (no tool calls to affect)
- The denominator is total MCP calls across all packs, not just affected calls
- This gives a "blast radius" fraction: 0.024 means 2.4% of historical tool calls
  would be blocked by the new policy

---

## Multi-pack aggregation

When `--packs` points to a directory:

1. Discover all pack subdirectories (contain `pack_manifest.json`)
2. Replay each pack independently against the candidate policy
3. Aggregate: sum counts, union top_changed_tools, compute overall risk_delta
4. Apply thresholds to the aggregate, not per-pack

This means one pack with 100 denied calls and 9 packs with 0 denied calls
will produce `newly_denied_count = 100` and the threshold applies to 100.

---

## Implementation plan

### New module: `src/assay/policy_guard.py`

```python
@dataclass
class AggregateImpact:
    """Aggregated impact across multiple packs."""
    policy_old_hash: Optional[str]
    policy_new_hash: str
    policy_old_path: Optional[str]
    policy_new_path: str
    packs_examined: int
    mcp_calls_examined: int
    model_calls_examined: int
    newly_denied_count: int
    newly_allowed_count: int
    risk_delta: float
    severity_breakdown: Dict[str, int]
    top_changed_tools: List[Dict[str, Any]]
    per_pack_impacts: List[PolicyImpact]  # from time_machine

def aggregate_policy_impact(
    packs_dir: Path,
    policy_new: Path,
    policy_old: Optional[Path] = None,
) -> AggregateImpact:
    """Replay all packs in a directory against a candidate policy."""

def evaluate_thresholds(
    impact: AggregateImpact,
    fail_if_newly_denied: Optional[int] = None,
    fail_if_risk_delta: Optional[float] = None,
) -> Tuple[str, str]:
    """Returns (verdict, reason). verdict is 'pass' or 'fail'."""

def emit_policy_impact_receipt(
    impact: AggregateImpact,
    verdict: str,
    verdict_reason: str,
    thresholds: Dict[str, Any],
) -> Dict[str, Any]:
    """Emit a PolicyImpactReceipt to the current trace."""
```

### CLI: `src/assay/commands.py`

```python
policy_app = typer.Typer(name="policy", help="Policy management and impact analysis")
assay_app.add_typer(policy_app, name="policy")

@policy_app.command("impact")
def policy_impact_cmd(...)
```

### Tests: `tests/assay/test_policy_guard.py`

Target: ~25 tests

- Aggregation: single pack, multi-pack, empty packs, no MCP receipts
- Thresholds: pass, fail-denied, fail-risk-delta, no thresholds
- Receipt emission: fields present, JSON-serializable, schema_version
- CLI: basic, json, md, bad-input, exit codes 0/1/3
- Severity breakdown: deny_list, not_in_allow, budget_exceeded
- Top changed tools: sorted by impact, capped at 10
- Edge cases: zero MCP calls (risk_delta = 0), all calls denied

---

## CI usage example

```yaml
# .github/workflows/policy-gate.yml
name: Policy Gate
on:
  pull_request:
    paths:
      - 'assay.mcp-policy.yaml'

jobs:
  policy-impact:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Assay
        run: python -m pip install assay-ai

      - name: Collect evidence packs
        run: |
          # Use packs from artifact storage or generate fresh
          assay run -- python test_suite.py
          assay verify-pack ./proof_pack_*/

      - name: Check policy impact
        run: |
          assay policy impact \
            --policy-new assay.mcp-policy.yaml \
            --policy-old <(git show HEAD~1:assay.mcp-policy.yaml) \
            --packs ./proof_packs/ \
            --fail-if-newly-denied 0 \
            --emit-receipt \
            --json > policy_impact.json

      - name: Upload impact report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: policy-impact
          path: policy_impact.json
```

---

## Two-gate governance story

| Gate | Command | Guards against | Exit 1 means |
|------|---------|----------------|--------------|
| Code gate | `assay diff --gate-*` | Behavioral regression | Claims regressed or thresholds exceeded |
| Policy gate | `assay policy impact --fail-if-*` | Policy blast radius | Too many calls would be denied |

Both produce signed receipts. Both are offline and deterministic.
Together they prove: "We checked the code AND the policy before shipping."
