# Discord Post

## Channels

- LangChain Discord (general or showcase)
- AI/ML focused Discords

## Message

I scanned 30 popular AI repos for **tamper-evident evidence emission** (signed receipts / proof packs that prove what went into and came out of each LLM call).

Found:
- **202** high-confidence direct SDK call sites (OpenAI/Anthropic)
- **903** total findings incl. framework heuristics
- **0** repos emitting tamper-evident evidence

Limitation: this is static AST analysis, not runtime. It doesn't measure logging/monitoring -- just cryptographic evidence.

One command to check your repo:
```
pip install assay-ai && assay scan .
```

Full report + dataset: https://github.com/Haserjian/assay/blob/main/scripts/scan_study/results/report.md

If I missed your setup, drop a commit link and I'll update the dataset.
