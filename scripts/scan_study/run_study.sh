#!/usr/bin/env bash
# run_study.sh -- Clone repos and run assay scan on each.
#
# Usage:
#   cd ~/assay/scripts/scan_study
#   ./run_study.sh
#
# Requires: assay (pip install assay-ai), git, jq, gh
# Output:  results/ directory with per-repo JSON + aggregated CSV + report

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPOS_FILE="${SCRIPT_DIR}/repos.txt"
WORK_DIR="${SCRIPT_DIR}/clones"
RESULTS_DIR="${SCRIPT_DIR}/results"
SUMMARY_CSV="${RESULTS_DIR}/results.csv"
SUMMARY_JSON="${RESULTS_DIR}/summary.json"

# Shallow clone depth (saves bandwidth, we only need source files)
CLONE_DEPTH=1

mkdir -p "${WORK_DIR}" "${RESULTS_DIR}"

# Verify assay is available
if ! command -v assay &>/dev/null; then
    echo "ERROR: assay not found. Install with: pip install assay-ai"
    exit 1
fi

# Get assay version via Python importlib (assay --version doesn't exist)
ASSAY_VERSION=$(python3 -c "from importlib.metadata import version; print(version('assay-ai'))" 2>/dev/null || echo "unknown")

# CSV header (includes commit_sha for provenance)
echo "repo,stars,language,commit_sha,sites_total,instrumented,uninstrumented,high,medium,low,status,scan_time_s" > "${SUMMARY_CSV}"

# Track aggregate stats
total_repos=0
total_sites=0
total_instrumented=0
total_uninstrumented=0
repos_with_findings=0

echo "=== Assay Scan Study ==="
echo "Tool:    assay-ai v${ASSAY_VERSION}"
echo "Repos:   $(wc -l < "${REPOS_FILE}" | tr -d ' ')"
echo "Output:  ${RESULTS_DIR}"
echo ""

while IFS= read -r repo || [[ -n "$repo" ]]; do
    # Skip empty lines and comments
    [[ -z "$repo" || "$repo" == \#* ]] && continue

    repo_name=$(basename "$repo")
    owner=$(dirname "$repo")
    clone_path="${WORK_DIR}/${owner}__${repo_name}"
    result_file="${RESULTS_DIR}/${owner}__${repo_name}.json"

    total_repos=$((total_repos + 1))
    printf "[%2d] %-45s " "${total_repos}" "${repo}"

    # Clone if not already present
    if [[ ! -d "${clone_path}" ]]; then
        if ! git clone --depth "${CLONE_DEPTH}" --quiet "https://github.com/${repo}.git" "${clone_path}" 2>/dev/null; then
            echo "CLONE_FAILED"
            echo "${repo},0,,,0,0,0,0,0,0,clone_failed,0" >> "${SUMMARY_CSV}"
            continue
        fi
    fi

    # Record commit SHA for reproducibility
    commit_sha=$(git -C "${clone_path}" rev-parse HEAD 2>/dev/null || echo "unknown")

    # Get star count from GitHub API
    stars=$(gh api "repos/${repo}" --jq '.stargazers_count' 2>/dev/null || echo "0")
    lang=$(gh api "repos/${repo}" --jq '.language // "unknown"' 2>/dev/null || echo "unknown")

    # Run assay scan
    scan_start=$(date +%s)
    if assay scan "${clone_path}" --json --exclude "tests/**,test/**,**/test_*,docs/**,examples/**,node_modules/**,.venv/**,venv/**" > "${result_file}" 2>/dev/null; then
        scan_end=$(date +%s)
        scan_time=$((scan_end - scan_start))

        # Extract metrics from JSON
        sites=$(jq -r '.summary.sites_total' "${result_file}")
        instr=$(jq -r '.summary.instrumented' "${result_file}")
        uninstr=$(jq -r '.summary.uninstrumented' "${result_file}")
        high=$(jq -r '.summary.high' "${result_file}")
        med=$(jq -r '.summary.medium' "${result_file}")
        low=$(jq -r '.summary.low' "${result_file}")
        status=$(jq -r '.status' "${result_file}")

        total_sites=$((total_sites + sites))
        total_instrumented=$((total_instrumented + instr))
        total_uninstrumented=$((total_uninstrumented + uninstr))
        [[ "$sites" -gt 0 ]] && repos_with_findings=$((repos_with_findings + 1))

        printf "%-6s  sites=%d  uninstr=%d  high=%d  (%ds)\n" "${status}" "${sites}" "${uninstr}" "${high}" "${scan_time}"
        echo "${repo},${stars},${lang},${commit_sha},${sites},${instr},${uninstr},${high},${med},${low},${status},${scan_time}" >> "${SUMMARY_CSV}"
    else
        scan_end=$(date +%s)
        scan_time=$((scan_end - scan_start))
        echo "SCAN_FAILED (${scan_time}s)"
        echo "${repo},${stars},${lang},${commit_sha},0,0,0,0,0,0,scan_failed,${scan_time}" >> "${SUMMARY_CSV}"
    fi

done < "${REPOS_FILE}"

# Write aggregate summary
cat > "${SUMMARY_JSON}" <<ENDJSON
{
  "study": "assay-scan-30-repos",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "assay_version": "${ASSAY_VERSION}",
  "repos_scanned": ${total_repos},
  "repos_with_llm_calls": ${repos_with_findings},
  "total_llm_call_sites": ${total_sites},
  "total_instrumented": ${total_instrumented},
  "total_uninstrumented": ${total_uninstrumented}
}
ENDJSON

echo ""
echo "=== Summary ==="
echo "Repos scanned:        ${total_repos}"
echo "With LLM call sites:  ${repos_with_findings}"
echo "Total call sites:     ${total_sites}"
echo "Instrumented:         ${total_instrumented}"
echo "Uninstrumented:       ${total_uninstrumented}"
if [[ ${total_sites} -gt 0 ]]; then
    pct=$(echo "scale=1; ${total_uninstrumented} * 100 / ${total_sites}" | bc 2>/dev/null || echo "?")
    echo "Gap:                  ${pct}%"
fi
echo ""
echo "CSV:     ${SUMMARY_CSV}"
echo "JSON:    ${SUMMARY_JSON}"
echo "Details: ${RESULTS_DIR}/*.json"
