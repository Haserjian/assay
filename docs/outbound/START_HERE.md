# Assay

Assay denies invalid AI claims caused by drift, then turns
surviving runs into auditable evidence.

---

## Choose your path

### Engineering lead / VP Eng

Watch the 60-second demo. It shows an apparent +11.1% gain get denied because the
judge drifted, then a rerun under pinned config reveals the real improvement is +4.7%.

```bash
pip install assay-ai
git clone https://github.com/Haserjian/assay.git && cd assay
bash examples/llm_judge/run_demo.sh --non-interactive
```

**Next:** [Try it on your own eval data](TRY_YOUR_DATA.md)

### Compliance / audit / risk

See what a governed evidence packet looks like, including gaps, scope boundaries,
and settlement status.

- [Reviewer packet with coverage gaps](https://github.com/Haserjian/assay-proof-gallery/tree/main/gallery/05-reviewer-packet-gaps) — buyer-facing
- [NAIC AISET compliance mapping](https://github.com/Haserjian/assay-proof-gallery/tree/main/gallery/06-naic-aiset-mapping) — 14 questions across 4 categories
- [Verify any proof pack in your browser](https://haserjian.github.io/assay-proof-gallery/verify.html) — no install needed

### Eval infrastructure

The core tool is `assay compare`. It checks whether two evaluation runs are
structurally comparable before anyone makes claims about the delta.

```bash
pip install assay-ai
assay compare baseline.json candidate.json \
  -c contracts/judge-comparability-v1.yaml \
  --claim "candidate scores higher on helpfulness"
```

The comparability contract defines what must match (judge model, prompt, rubric,
dataset) and at what severity. You can write contracts for your domain.

**Next:** [Try it on your own eval data](TRY_YOUR_DATA.md)

---

## What to do next

1. **See the demo** — 60 seconds, one command, shows the denial arc
2. **Try your own data** — bring two eval runs, get a verdict ([quickstart](TRY_YOUR_DATA.md))
3. **Inspect the evidence** — browse proof packs and reviewer packets in the [gallery](https://github.com/Haserjian/assay-proof-gallery)
4. **Verify without installing** — use the [browser verifier](https://haserjian.github.io/assay-proof-gallery/verify.html) on any proof pack

---

## Want us to install it?

**Comparability Diagnostic (free):** We run `assay compare` on your
last two eval runs and show you whether the comparison was structurally valid.
Takes 30 minutes. You learn whether your benchmark claims survive scrutiny.

**Evidence Gate Pilot ($10-25K):** We wire Assay into your eval pipeline,
author your comparability contract, set up CI gating, and hand off the
whole system. 1-2 weeks. You own everything we build.
[Full pilot details](../PILOT_PROGRAM.md)

---

## What Assay does not claim

- It does not prove AI systems are safe, aligned, or correct
- It does not replace evaluation methodology or rubric design
- It does not verify that judges are well-calibrated
- It does not guarantee the evaluated system is actually better

It proves that a comparison is structurally valid — or it denies it with
reasons, consequences, and a remediation path.
