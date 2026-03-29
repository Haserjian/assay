# Canonical Real Shape — Lane Gate Fixtures

These fixtures test whether the eval-governance lane works on
realistic, messy input — not handcrafted demo-friendly shapes.

## What makes these "real shape"

- Multi-line prompts with formatting (not one-liners)
- Field sources declared (config files, API responses, git tags)
- One candidate has realistic drift: model auto-upgraded, prompt tweaked, field missing
- One candidate is pinned: identical instrument, all 15 fields present
- Neither is a perfect textbook example

## The fixtures

| File | What it represents | Expected verdict |
|---|---|---|
| `baseline.json` | Production eval run from March 10 | N/A (reference) |
| `candidate_messy.json` | Candidate with 3 problems: model version bumped (OpenAI auto-upgrade), system prompt tweaked (+1 word), eval_dataset_version missing | **DENIED** (2 INVALIDATING mismatches + 1 missing required field) |
| `candidate_clean.json` | Same candidate, rerun with pinned judge config | **SATISFIED** (15/15 match) |

## Run them

```bash
# Messy candidate → DENIED
assay compare baseline.json candidate_messy.json \
  -c ../../contracts/judge-comparability-v1.yaml \
  --claim "new system improved helpfulness by 12%"

# Clean candidate → SATISFIED
assay compare baseline.json candidate_clean.json \
  -c ../../contracts/judge-comparability-v1.yaml \
  --claim "new system improved helpfulness by 5%"
```

## Lane gate criteria

A technically serious outsider (knows evals/CI/JSON, no Assay internals)
should be able to:

1. Read TRY_YOUR_DATA.md (one doc)
2. Look at these fixtures (one example)
3. Run the commands above
4. Understand and trust the verdict
5. Without help beyond one correction loop

If that fails, the lane is not ready.
