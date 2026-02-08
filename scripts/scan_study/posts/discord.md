# Discord Post

## Channels

- LangChain Discord (general or showcase)
- AI/ML focused Discords

## Message

I scanned 30 popular AI repos for **tamper-evident evidence emission** (signed receipts that prove what went into and came out of each LLM call, verifiable without your infra).

Found **202** high-confidence direct SDK call sites, **903** total including framework heuristics, **0** with tamper-evident evidence.

This doesn't measure logging/monitoring -- just cryptographic evidence. Many of these projects have great observability. The gap is between "we can see" and "we can prove."

One command to check your repo:
```
pip install assay-ai && assay scan .
```

Full report + dataset: https://github.com/Haserjian/assay/blob/9641c7c/scripts/scan_study/results/report.md

If I missed your setup, drop a commit link and I'll update the dataset.
