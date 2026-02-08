# HN Post

## Title (pick one)

1. Show HN: I scanned 30 popular AI projects for tamper-evident audit trails. None had one
2. 202 direct LLM SDK call sites across 21 repos, and none emitted tamper-evident evidence

## Body

I built a static AST scanner that finds LLM call sites (OpenAI, Anthropic SDK calls + framework patterns) and checks whether each one has tamper-evident evidence emission -- signed receipts that prove what went in and came out of each call.

I ran it on 30 popular open-source AI projects (LangChain, LlamaIndex, CrewAI, Browser-Use, Aider, etc.).

Results:

- 202 high-confidence direct SDK call sites across 21 repos (things like `client.chat.completions.create`)
- 903 total findings including framework heuristics
- 0 repos with tamper-evident evidence emission at any call site

Important limitation: this is static AST analysis scoped to tamper-evident evidence (signed receipts / proof packs). It does NOT measure logging, OpenTelemetry, LangSmith, or other observability. Many of these projects have extensive logging. What they don't have is cryptographically signed evidence that an auditor or regulator could independently verify.

Full report with per-repo breakdown + method limits: https://github.com/Haserjian/assay/blob/9641c7c/scripts/scan_study/results/report.md

Dataset (CSV with commit SHAs): https://github.com/Haserjian/assay/blob/9641c7c/scripts/scan_study/results/results.csv

One-command check on your repo:

    pip install assay-ai && assay scan .

If you think your project does have tamper-evident evidence emission and I missed it, drop a commit link and the instrumentation approach and I'll update the dataset.

Source: https://github.com/Haserjian/assay
