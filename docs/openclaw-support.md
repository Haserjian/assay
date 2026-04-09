# OpenClaw Support

**Status:** current public support contract
**Date:** 2026-04-08
**Scope:** supported integration posture and trust boundary, not a frozen Python API

---

## One-line contract

Assay can sit in front of OpenClaw as a subprocess membrane for selected tool
actions and exported session activity. It enforces a narrow policy boundary,
emits tamper-evident receipts for allowed and denied actions, and packages
those receipts into proof artifacts another team can verify offline.

For a shorter external-facing summary of proofs, non-proofs, trust assumptions,
and required artifacts, see [OpenClaw v1 Claim Sheet](openclaw-v1-claim-sheet.md).

---

## Supported posture today

Two shipped code surfaces define the current OpenClaw support boundary:

- `src/assay/bridge.py` is the enforcement membrane.
- `src/assay/openclaw_bridge.py` is the OpenClaw-specific receipt adapter.

Together they support:

- tool-policy checks before invocation
- default deny for unknown or dangerous tools
- SSRF/private-network denial for `web_fetch`
- deterministic subprocess invocation with captured output
- receipt emission for allow and deny outcomes
- domain allowlist checks for browser operations
- explicit approval requirements for sensitive browser actions
- parsing exported OpenClaw session logs into Assay web-tool receipts

This behavior is covered by `tests/assay/test_bridge.py` and
`tests/assay/test_openclaw_bridge.py`.

---

## Supported artifact flow

```text
OpenClaw tool request or exported session log
-> Assay policy check
-> allow/deny receipt or web-tool receipt
-> optional proof pack build
-> assay verify-pack
```

Browser verification remains proof-pack-only today. If you want a browser
check in an OpenClaw workflow, verify the proof pack, not a higher-level
wrapper.

## Deterministic demo

Run:

```bash
assay try-openclaw
assay verify-pack ./assay_openclaw_demo/proof_pack
```

The demo produces one deterministic artifact set behind this contract:

- one allowed public web fetch through the subprocess membrane
- one denied localhost web fetch blocked by policy
- one imported OpenClaw session-log event
- one blocked sensitive browser action through the receipt adapter
- one signed proof pack built from lower-case proof-pack entries projected from
  that emitted evidence

The subprocess invocation in this demo is deterministic and synthetic. It does
not require a live OpenClaw install. That keeps the proof path reproducible on
clean machines while still exercising the supported membrane and receipt-adapter
surfaces.

The raw bridge JSON artifacts and the exported session log stay beside the demo
pack for inspection. The proof pack remains the trust root for offline
verification.

## Current session-log import semantics

Exported session logs are treated as evidence inputs, not as automatically
trusted truth.

Today the importer:

- emits receipts only for rows it can parse and validate against the supported
  `web_search`, `web_fetch`, and `browser` shapes
- surfaces malformed JSON, unsupported tools, and invalid supported-tool rows
  as explicit skipped entries in the import report
- keeps imported vs skipped counts plus a `clean` vs `partial` import status
  visible in the deterministic demo summary and JSON output
- keeps projected proof-pack entries explicit about whether they came from
  membrane execution, live receipt adaptation, or imported session-log evidence

Those skipped-entry diagnostics improve hostile-reading honesty, but they do not
change the core proof boundary: Assay still does not prove that an imported
session log was complete or honest before import.

---

## What Assay proves at this boundary

At the current OpenClaw boundary, Assay proves:

- which request crossed the Assay boundary
- whether Assay policy allowed or denied it
- what Assay recorded about the resulting subprocess invocation or imported
  session-log event
- whether the recorded evidence came from membrane execution, live receipt
  adaptation, or imported session-log evidence
- whether the emitted evidence was tampered with after it was packaged into a
  proof pack

The proof-pack verifier proves the proof-pack contract and the bytes admitted
into the pack. It does not become a blanket verifier for the whole OpenClaw
runtime.

---

## What Assay does not prove at this boundary

Assay does not currently prove:

- live OpenClaw Gateway or WebSocket interception
- full CDP or browser governance on every action
- OpenClaw internal planner truth or browser-page semantic truth
- that every OpenClaw action was faithfully exported unless it crossed the
  Assay boundary or appeared in the imported session log
- that an imported session log was complete or honest before Assay receipted it
- a multi-tenant security boundary for hostile shared users

---

## Authority split

- `bridge.py`: enforcement membrane for subprocess invocation and deny paths
- `openclaw_bridge.py`: OpenClaw-specific receipt adapter and session-log parser
- proof packs: trust root for exported evidence
- reviewer and compiled packets: higher-order packaging layers, not the
  OpenClaw bridge itself

---

## API posture

The current public promise is behavioral and documentary:

- the supported boundary claim in this document
- the emitted receipt and proof-pack posture
- the verification path for emitted evidence

The shipped Python modules are currently classified in `docs/catalog.yaml` as
bridge/internal surfaces, so import-level compatibility is not yet the public
contract.

---

## Not current

Do not describe current Assay support as:

- live Gateway or WebSocket interception
- gatebook-backed OpenClaw runtime governance
- constitutional control of every browser action in real time

Those are roadmap directions, not shipped support claims.

---

## Recommended wording

Use this wording for current public surfaces:

> Assay can sit in front of OpenClaw as a subprocess membrane for selected tool actions and exported session activity. It enforces a narrow policy boundary, emits tamper-evident receipts for allowed and denied actions, and packages those receipts into proof artifacts another team can verify offline.
