# Posture Warning Taxonomy and Gate Consequences

**Status:** Open — next semantic frontier after posture-gate landing
**Created:** 2026-03-21
**Depends on:** `proof_posture.posture_from_pack()`, `gate.evaluate_posture_gate()`

---

## Problem

`posture_from_pack()` surfaces warnings for damaged, missing, or partial evidence inputs. Currently all warnings are advisory — none change disposition or gate behavior.

This is correct for the first landing but insufficient long-term. Some input damage should cap disposition. Some should fail the gate closed. The boundary between advisory and consequential warnings needs to be defined.

---

## Questions to settle

1. Which warnings are advisory only?
2. Which warnings should cap disposition (prevent `verified`)?
3. Which warnings should force `incomplete`?
4. Which warnings should fail closed (gate exit 1)?
5. How should multiple warnings combine?
6. Should `--strict-posture` exist as a CLI flag?

---

## Current warning sources

| Warning | Current behavior | Proposed consequence |
|---------|-----------------|---------------------|
| `receipt_pack.jsonl not found` | advisory | **cap to `supported_but_capped`** — no receipts means no evidence |
| `N malformed receipt line(s) skipped` | advisory | advisory if N < 10% of lines; **cap** if N >= 50% |
| `pack_manifest.json not found` | advisory | advisory — no claims just means nothing to verify |
| `pack_manifest.json unreadable` | advisory | **cap to `supported_but_capped`** — manifest exists but can't be parsed |

---

## Proposed warning severity levels

| Level | Meaning | Gate consequence |
|-------|---------|-----------------|
| `info` | Normal operational note | none |
| `degraded` | Evidence is partial but evaluation proceeded | caps `verified` → `supported_but_capped` |
| `structural` | Evidence structure is damaged | forces `incomplete` |

---

## Invariant (already encoded in tests)

> Damaged or unreadable posture inputs can never yield `verified` without warnings. If warnings exist, the consumer must be able to see them.

---

## Implementation sketch

```python
@dataclass
class PostureWarning:
    message: str
    level: str  # "info" | "degraded" | "structural"
    source: str  # e.g. "receipt_pack", "manifest", "claim_verifier"
```

The disposition computation would then check:
- any `structural` warning → cap at `incomplete`
- any `degraded` warning → cap at `supported_but_capped`
- `info` warnings → no disposition effect

---

## Not now

- `--strict-posture` flag (fail on any warning)
- warning-based gate exit codes beyond pass/fail
- per-warning override configuration

These wait until real operator feedback shows which warnings matter most.

---

## Provisional invariant notes

Two invariants in `TestPostureInvariants` are provisional tolerance, not final doctrine:

1. **Corrupt manifest → verified + warnings**: Currently permitted because no claims exist to fail. Future decision: should manifest corruption always cap at `incomplete`? Provisional tolerance is the safer starting point — but "verified with warnings" may become psychologically "good enough" and resist future tightening.

2. **Missing both files → 2+ warnings**: Currently checks warning count only, not disposition. Future decision: should missing both files force `incomplete` regardless of claim count? Warnings are necessary but may not be sufficient as the long-term invariant.

Both are recognized as provisional. Neither should be hardened into final doctrine without real operator feedback.

---

## Revisit triggers

- After the first 3 external uses of `assay gate check --posture-pack`
- Earlier if any warning class creates operator confusion
- Earlier if a demo or external use exposes ambiguity about what "verified with warnings" means
