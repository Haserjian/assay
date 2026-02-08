# Reddit Post

## Title

I scanned 30 popular AI projects for tamper-evident audit evidence. None had it.

## Body

I built a scanner that finds LLM call sites (OpenAI/Anthropic SDK + LangChain/LiteLLM framework patterns) and checks for tamper-evident evidence emission -- i.e., signed receipts / proof packs that can be independently verified.

Ran it on 30 popular repos: LangChain, LlamaIndex, CrewAI, Browser-Use, Aider, pydantic-ai, DSPy, LiteLLM, and others.

**Results:**

| Metric | Value |
|--------|-------|
| High-confidence SDK call sites | 202 |
| Total (incl. framework heuristics) | 903 |
| Repos with tamper-evident evidence | 0 |

**Limitations:** Static AST analysis, specifically about tamper-evident evidence (not dashboards/logging). Many of these projects have extensive observability. The gap is between "we can see what happened" and "we can cryptographically prove what happened."

**Check your repo:**

```bash
pip install assay-ai && assay scan .
```

Full report with per-repo breakdown, method limits, and reproducibility instructions:
https://github.com/Haserjian/assay/blob/main/scripts/scan_study/results/report.md

If I missed your instrumentation or if a finding is a false positive, post a commit link and I'll update the dataset.

---

## Subreddit targets

- r/MachineLearning (frame as research/discussion, not self-promotion)
- r/LocalLLaMA (tool-focused, more receptive)
- r/LangChain (directly relevant, many of their users would benefit)
