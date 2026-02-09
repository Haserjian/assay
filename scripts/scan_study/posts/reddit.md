# Reddit Post

## Title

I scanned 30 popular AI projects for tamper-evident audit evidence. None had it.

## Body

I built a scanner that finds LLM call sites (OpenAI/Anthropic SDK + LangChain/LiteLLM framework patterns) and checks for tamper-evident evidence emission -- signed receipts that can be independently verified without access to the project's infrastructure.

Ran it on 30 popular repos: LangChain, LlamaIndex, CrewAI, Browser-Use, Aider, pydantic-ai, DSPy, LiteLLM, and others.

**Results:**

| Metric | Value |
|--------|-------|
| High-confidence SDK call sites | 202 |
| Total (incl. framework heuristics) | 903 |
| Repos with tamper-evident evidence | 0 |

**What this is not:** a claim that these projects have no logging. Many have extensive observability (callbacks, OpenTelemetry, LangSmith). This specifically measures cryptographically signed, independently verifiable evidence -- the difference between "we can see what happened" and "we can prove what happened."

**Check your repo:**

```bash
pip install assay-ai && assay scan .
```

Full report with per-repo breakdown and method limits:
https://github.com/Haserjian/assay/blob/9641c7c/scripts/scan_study/results/report.md

If I missed your instrumentation or if a finding is a false positive, post a commit link and I'll update the dataset.

Source: https://github.com/Haserjian/assay

---

## Subreddit targets

- r/MachineLearning (frame as research/discussion)
- r/LocalLLaMA (tool-focused, more receptive)
- r/LangChain (directly relevant)
