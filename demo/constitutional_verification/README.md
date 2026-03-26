# Constitutional Verification Demo

Three AI agents independently verify an AI-generated SOC2 readiness assessment.

## Run

    cd ~/assay-toolkit/demo/constitutional_verification
    pip install anthropic
    export ANTHROPIC_API_KEY=your-key
    python3 run.py

Output: `demo_output/proof_summary.md`

If the API key is missing, the script exits immediately with a clear message.

## Interpreting results

A successful demo may produce either a passing or blocking verdict.

- **BLOCKED** is the correct result when evidence contradicts or fails to support the AI's claims. This is the target behavior — honest constitutional verification, not forced approval.
- **CONFIRMED** means evidence directly supports a claim. Not all claims will confirm, and that is the point.

The demo proves the system catches over-confident AI output and explains exactly what the evidence does and does not support.
