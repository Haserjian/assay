# Semantic Simulation Matrix

Use this matrix to test real-world understanding, not just code correctness.
Each drill should be run by someone new to Assay and scored pass/fail.

## Scoring Rule

- `PASS`: user reaches the expected outcome without external help.
- `FAIL`: user stalls, misinterprets output, or requires intervention.

## Drill 1: Stranger Install

- Goal: validate first 90-second comprehension.
- Commands:
```bash
pip install assay-ai
assay demo-incident
assay demo-challenge
```
- Pass criteria:
  - User can explain `PASS/PASS` vs `PASS/FAIL`.
  - User understands "honest failure" as authentic noncompliance evidence.

## Drill 2: Scan -> First Action

- Goal: verify scanner output leads to a concrete next step.
- Commands:
```bash
assay scan .
```
- Pass criteria:
  - User knows where to add instrumentation.
  - User can name the next command they should run.

## Drill 3: First Proof Pack in <10 Minutes

- Goal: convert interest into first artifact.
- Commands:
```bash
assay run -c receipt_completeness -c guardian_enforcement -- python <entrypoint>.py
assay verify-pack ./proof_pack_*/
assay explain ./proof_pack_*/ --format md
```
- Pass criteria:
  - A pack is generated.
  - User can share the explanation output in Slack/email.

## Drill 4: Honest Failure Comprehension

- Goal: ensure `integrity PASS + claims FAIL` is understood correctly.
- Setup: run with missing guardian receipt.
- Pass criteria:
  - User says "authentic evidence of policy violation."
  - User does not say "the tool is broken."

## Drill 5: Tamper Detection

- Goal: validate trust chain behavior under mutation.
- Setup: alter one byte in `receipt_pack.jsonl`.
- Command:
```bash
assay verify-pack ./proof_pack_tampered/
```
- Pass criteria:
  - Verification fails with exit code `2`.
  - User can explain tampering vs claim failure.

## Drill 6: Wrapper-Heavy Repo

- Goal: test usefulness when direct SDK calls are not obvious.
- Setup: repository routes model calls through custom wrappers.
- Command:
```bash
assay scan .
```
- Pass criteria:
  - User gets a useful manual instrumentation path.
  - User can still produce a first pack.

## Drill 7: CI Operator

- Goal: move from local proof to enforced workflow.
- Commands:
```bash
assay ci init github --run-command "python <entrypoint>.py"
```
- Pass criteria:
  - Workflow file is generated and committed.
  - PR checks report verification result and upload pack artifact.

## Triage Labels

When a drill fails, file an issue with one label:

- `activation`: unclear first-step conversion
- `scanner`: low-signal findings or bad fix suggestions
- `copy`: phrasing causes semantic misunderstanding
- `ci`: workflow generation or enforcement friction

