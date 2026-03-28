#!/usr/bin/env bash
# LLM-as-Judge Governance Demo: The Claim That Shouldn't Have Shipped
#
# Three acts:
#   Act 1: The comparison looks great (11.1% improvement!)
#   Act 2: The denial (DENIED — model version + prompt drifted)
#   Act 3: The fix (SATISFIED — real improvement is 4.7%)
#
# Usage:
#   cd assay/
#   bash examples/llm_judge/run_demo.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONTRACT="$REPO_DIR/contracts/judge-comparability-v1.yaml"

echo ""
echo "================================================================"
echo "  Assay LLM-as-Judge Governance Demo"
echo "  The Claim That Shouldn't Have Shipped"
echo "================================================================"
echo ""

# --- Act 1: The comparison looks great ---
echo "--- ACT 1: The comparison looks great ---"
echo ""
echo "  Baseline (Tuesday):  gpt-4o-2024-08-06, prompt v2.3"
echo "  Candidate (today):   gpt-4o-2024-11-20, prompt v2.4"
echo ""
echo "  mean_helpfulness_score:"
echo "    baseline:  3.79"
echo "    candidate: 4.21"
echo "    delta:     +0.42 (+11.1%)"
echo ""
echo "  Looks like a win. Team is about to ship a blog post."
echo ""
echo "  Press Enter to run the denial engine..."
read -r

# --- Act 2: The denial ---
echo ""
echo "--- ACT 2: The denial ---"
echo ""
echo '  $ assay compare dirty/baseline.json dirty/candidate.json \'
echo '      -c contracts/judge-comparability-v1.yaml \'
echo '      --claim "candidate scores 11.1% higher on helpfulness"'
echo ""

assay compare \
    "$SCRIPT_DIR/dirty/baseline.json" \
    "$SCRIPT_DIR/dirty/candidate.json" \
    -c "$CONTRACT" \
    --claim "candidate scores 11.1% higher on helpfulness" \
    --metric mean_helpfulness_score \
    --delta 0.42 || true

echo ""
echo "  The blog post cannot ship. The 11.1% number is structurally invalid."
echo "  The team must rerun with pinned judge config."
echo ""
echo "  Press Enter to see the fix..."
read -r

# --- Act 3: The fix ---
echo ""
echo "--- ACT 3: The fix ---"
echo ""
echo "  Reran candidate eval with pinned config:"
echo "    judge_model_version: gpt-4o-2024-08-06"
echo "    judge_prompt: prompts/helpfulness_v2.3.txt"
echo ""
echo '  $ assay compare clean/baseline.json clean/candidate.json \'
echo '      -c contracts/judge-comparability-v1.yaml \'
echo '      --claim "candidate scores 4.7% higher on helpfulness"'
echo ""

assay compare \
    "$SCRIPT_DIR/clean/baseline.json" \
    "$SCRIPT_DIR/clean/candidate.json" \
    -c "$CONTRACT" \
    --claim "candidate scores 4.7% higher on helpfulness" \
    --metric mean_helpfulness_score \
    --delta 0.18

echo ""
echo "================================================================"
echo "  The real improvement is 4.7%, not 11.1%."
echo "  The other 6.4% was judge drift."
echo "  The blog post gets rewritten. The real number ships."
echo "================================================================"
echo ""
