# Theory-to-Feature Atlas

How Assay's design principles map to concrete product features.

If you want to understand *why* Assay operates the way it does, start here. For the full concept explanations, see the [Assay Protocol concept docs](https://github.com/Haserjian/assay-protocol/tree/main/concepts).

## Feature Map

| Design Principle | Product Consequence | Assay Feature | Protocol Reference | CI Enforcement | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Receipts as evidence** | Every agent action produces cryptographically signed proof | Proof Packs (receipt schema v3.0) | Receipt envelope, `receipt_id`, `signature` | `assay-verify-action` | Shipped |
| **Constitutional governance** | Agents operate within bounded, enforceable rules | `assay gate check`, governance profiles | CONTROL_MAP (9 controls), MCP Minimum Profile | Gate enforcement in CI | Shipped |
| **Non-compensatory safety** | Critical failures cannot be offset by high scores elsewhere | Anti-gaming caps (no receipts = max grade D) | Gate `reasons[]` | Branch protection via gate | Shipped |
| **Honest observability** | Explicitly tracking what the system *cannot* prove | `assay scan` coverage ratio, drift monitoring | `coverage_ratio`, `uninstrumented_paths[]` | Enforcement monitor workflow | Shipped |
| **Causal lineage** | State transitions are ordered and tamper-evident | `parent_receipt_id`, `_trace_id` chaining | `transition_seq`, hash chains | Lineage verification in CI | Shipped |
| **Anti-gaming scoring** | Multiple independent signals prevent metric optimization | 5 weighted score components with hard caps | `score_estimators[]` | Score thresholds in gate | Shipped |
| **Structured gate decisions** | Pass/fail with machine-readable explanations | `reasons[]` in gate output | `policy_rationale` | Gate check exit codes | Shipped |

## Gate Decision Output

```json
{
  "result": "PASS | FAIL",
  "current_score": 72.5,
  "current_grade": "C",
  "baseline_score": 68.0,
  "min_score": 50.0,
  "regression_detected": false,
  "reasons": [],
  "timestamp": "2026-02-25T...",
  "command": "assay gate"
}
```

## Score Components

| Component | Weight | What it measures |
| :--- | :--- | :--- |
| `coverage` | 35% | Instrumented call sites / total call sites |
| `ci_gate` | 20% | Gate enforcement in CI pipeline |
| `receipts` | 20% | Evidence production and integrity |
| `lockfile` | 15% | Dependency pinning and reproducibility |
| `key_setup` | 10% | Cryptographic key configuration |

Anti-gaming: missing `receipts` component caps grade at D regardless of total score.

## Concept Docs

For the research foundations behind these features:

| Concept | Summary |
| :--- | :--- |
| [Constitutional Computing](https://github.com/Haserjian/assay-protocol/blob/main/concepts/constitutional-computing.md) | Why enforceable rules beat behavioral suggestions |
| [Coherence Triangulation](https://github.com/Haserjian/assay-protocol/blob/main/concepts/coherence-triangulation.md) | Why multiple independent estimators prevent gaming |
| [Dignity Floor](https://github.com/Haserjian/assay-protocol/blob/main/concepts/dignity-floor-and-non-compensation.md) | Why critical failures are non-compensatory |
| [Semantic Time](https://github.com/Haserjian/assay-protocol/blob/main/concepts/semantic-time-and-lineage.md) | Why causal ordering beats chronological logs |
| [Coverage Boundaries](https://github.com/Haserjian/assay-protocol/blob/main/concepts/coverage-boundaries-and-observability.md) | Why honest gaps build more trust than false certainty |
| [CRIF](https://github.com/Haserjian/assay-protocol/blob/main/concepts/crif-contradictions-and-policy-evolution.md) | Why policy conflicts need structured handling |

---

*Living document. Updated with each release.*
