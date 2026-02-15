# Repo Charter: assay

## Purpose

Canonical source for the Assay CLI, Python SDK, and conformance corpus.
Everything a user needs to produce, verify, and explain tamper-evident
AI evidence lives here.

## Trust Boundary

**Public.** This repo is the open-source distribution channel. All code,
tests, docs, and schemas are intended for public consumption. No secrets,
internal tooling, or proprietary logic belongs here.

## What Lives Here

- CLI entrypoint (`src/assay/cli.py`, `src/assay/commands.py`)
- Core library (`src/assay/` -- store, receipts, proof packs, scanner, doctor, diff, explain, MCP proxy)
- SDK integrations (`src/assay/integrations/` -- OpenAI, Anthropic, LangChain)
- Conformance corpus (`conformance/`)
- Schemas (`src/assay/schemas/`)
- Tests (`tests/assay/` -- 887+ tests)
- Docs (`docs/` -- landing page, quickstart, roadmap, compliance, pilot program)
- Scan study (`scripts/scan_study/`)

## What Does Not Live Here

- Private monorepo internals (CCIO, Loom, Quintet)
- Cloud services or hosted infrastructure
- Secrets, API keys, or credentials
- GitHub Action implementation (see `assay-verify-action`)
- Ledger data or witness infrastructure (see `assay-ledger`)

## Versioning Contract

- Follows [SemVer](https://semver.org/): `MAJOR.MINOR.PATCH`
- Version source: `pyproject.toml` (canonical) + `src/assay/__init__.py` (runtime)
- Published to PyPI as `assay-ai`
- CLI exit codes are part of the public API: `0/1/2/3`
- Receipt schema version tracked in `src/assay/schema.py`
- Lockfile format is versioned (`lock_version` field)

## Consumer Workflow

```bash
pip install assay-ai          # install
assay quickstart              # first-value in 2 minutes
assay scan . --report         # find uninstrumented call sites
assay patch .                 # auto-instrument
assay run -c receipt_completeness -- python app.py  # collect evidence
assay verify-pack ./proof_pack_*/                   # verify
assay diff ./proof_pack_*/ --against-previous --why # regression forensics
```

## Related Repos

| Repo | Role |
|------|------|
| [assay-verify-action](https://github.com/Haserjian/assay-verify-action) | GitHub Action for CI verification |
| [assay-ledger](https://github.com/Haserjian/assay-ledger) | Public transparency ledger |
