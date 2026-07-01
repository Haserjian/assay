---
name: assay-openclaw-evidence-check
description: >-
  Turn a selected OpenClaw session-log trace into offline-verifiable Assay
  evidence. Reports which rows imported, which were skipped (with reasons), and
  which tool calls were surfaced, then fails closed when there is nothing real to
  import. Read-only. Not a dashboard. For live telemetry, use ClawMetry.
metadata:
  openclaw:
    requires:
      bins:
        - assay
    homepage: https://github.com/Haserjian/assay
---

# Assay OpenClaw Evidence Check

Assay is an **evidence membrane**, not an observability dashboard. For live
cost/token/health telemetry and event-flow visualization, use
[ClawMetry](https://clawhub.ai/vivekchand/clawmetry) — OpenClaw keeps that kind
of ingestion in plugin/community territory
([#7783](https://github.com/openclaw/openclaw/issues/7783), closed *not planned*).

Use Assay for the narrower, complementary job: when someone needs to **review or
prove** what a *selected* agent action did — to a reviewer who does not trust the
operator — with evidence that can be verified offline and cannot be quietly
edited after the fact.

## When to use this skill

- You have an exported OpenClaw session log (`~/.openclaw/agents/<id>/sessions/*.jsonl`)
  and you want a scoped, honest record of what it contains.
- You want imported-vs-skipped accounting and surfaced tool calls, not a live dashboard.
- You want a signed, offline-verifiable proof pack for the deterministic demo path.

## Two modes

### Real OpenClaw session check

Use this for an existing OpenClaw `sessions/*.jsonl` file:

```bash
pip install assay-ai
assay openclaw verify /path/to/session.jsonl
```

This performs import, attribution, skipped-row accounting, and fail-closed
validation, reporting per log:

- imported vs skipped rows, with skip reasons (invalid JSON, unsupported tool, invalid row)
- a `clean` vs `partial` import status
- recognized entry types and message roles
- which tool calls were surfaced and attributed

If the file is missing or nothing importable is found, it exits non-zero and
reports a blocked result instead of inventing confidence (add `--json` for
machine-readable output). **It does not mint a signed proof pack from arbitrary
session logs yet** — for that, use the deterministic demo below.

### Deterministic proof-pack demo

Use this to see Assay's signed proof-pack path:

```bash
assay try-openclaw
assay verify-pack ./assay_openclaw_demo/proof_pack
```

`try-openclaw` builds a signed proof pack from a deterministic, synthetic
OpenClaw path (no live OpenClaw process required); `verify-pack` verifies it
offline. A failed underlying run still yields an honest, verifiable receipt;
only broken or tampered evidence counts as a real failure.

## What this does NOT prove

- complete runtime capture of all OpenClaw activity
- live OpenClaw Gateway or WebSocket interception
- planner correctness or browser-page semantic truth
- that the imported session log was complete or honest before Assay read it
- a hostile multi-tenant security boundary

`assay openclaw verify` reports import + attribution over the session log you
give it; it does not itself mint a signed proof pack from an arbitrary session.
The signed proof-pack path is the deterministic `try-openclaw` demo above.

## Safety

This skill runs only two things: `pip install assay-ai` and the `assay` CLI. No
install scripts, no piped shell, no network fetch of code. That boringness is the
point — it is the anti-chaos layer.
