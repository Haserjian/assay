# HN Post

## Title

Show HN: I scanned 30 popular AI projects for tamper-evident LLM evidence. 0 had it.

## Body

Assay produces tamper-evident audit trails for AI systems. Whoever controls the server controls the story -- logs aren't proof. Try it on your own repo:

    pip install assay-ai && assay scan .

I scanned 30 popular open-source AI projects for tamper-evident evidence emission at LLM call sites -- signed receipts that prove what went in and came out of each call, verifiable without access to the project's infrastructure.

Results: 202 high-confidence direct SDK call sites (`client.chat.completions.create`, `anthropic.messages.create`) across 21 repos. 903 total findings including framework heuristics. 0 repos with tamper-evident evidence emission at any call site.

**Why this matters:** Most of these projects have extensive logging -- callbacks, OpenTelemetry, LangSmith. That's observability: "we can see what happened." What none of them have is verifiability: "we can cryptographically prove what happened, and you can independently check it." When a regulator or auditor asks "prove your AI system did what you said it did," logs under your control aren't sufficient. Signed receipts bundled into a portable proof pack are.

**Method:** Static AST analysis. High-confidence = direct SDK calls. Medium = framework calls gated behind import evidence (e.g., `.invoke()` only counts if the file imports LangChain/LlamaIndex/LiteLLM). Low = heuristic name matches. This does NOT measure logging, dashboards, or other observability -- only Assay-detectable tamper-evident evidence emission. Instrumentation detection is file-scoped.

**Data:**

- Full report: https://github.com/Haserjian/assay/blob/9641c7c/scripts/scan_study/results/report.md
- Dataset (CSV with commit SHAs): https://github.com/Haserjian/assay/blob/9641c7c/scripts/scan_study/results/results.csv
- Rerun script: https://github.com/Haserjian/assay/blob/9641c7c/scripts/scan_study/run_study.sh

If you think your project does have tamper-evident evidence emission and this scan missed it, drop a commit link and the instrumentation approach and I'll update the dataset. The goal is accuracy, not a gotcha.

Source: https://github.com/Haserjian/assay
