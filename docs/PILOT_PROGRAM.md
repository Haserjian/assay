# Assay Pilot Program

Get tamper-evident evidence infrastructure running in your stack in 2 weeks.
You own everything we build. No ongoing dependency.

## Who This Is For

- Teams shipping AI agents, RAG pipelines, or autonomous workflows in production
- Companies preparing for SOC 2, HIPAA, EU AI Act, or ISO 42001 audits
- Engineering orgs that got "prove what your AI did" from security/legal and don't have an answer

## What You Get

### Week 1: Instrument + Gate

| Day | Deliverable |
|-----|-------------|
| 1 | Kickoff call + `assay scan --report` across your codebase. You see every uninstrumented LLM call site. |
| 2-3 | SDK instrumentation (`assay patch` or manual). Every LLM call emits receipts. |
| 4 | CI gate: `assay run` + `verify-pack --lock` + `diff --gate` in your pipeline. PRs blocked on evidence failure. |
| 5 | Lockfile baseline + custom RunCard suite mapped to your compliance needs. |

### Week 2: Harden + Hand Off

| Day | Deliverable |
|-----|-------------|
| 6-7 | Gate threshold tuning (cost %, error count, regression sensitivity). Eliminate false positives. |
| 8-9 | Key rotation setup. Signer allowlist in lockfile. Separation of dev and CI signing keys. |
| 10 | Documentation handoff: how to maintain, extend, and explain the setup to auditors. |

### What You Walk Away With

- `assay.lock` -- frozen governance contract for your verification standards
- CI pipeline producing signed proof packs on every merge
- Baseline pack for regression comparison
- Custom claim cards for your specific policies
- "What This Evidence Means" doc for your security/compliance reviewers
- Key rotation runbook

## What It Costs

| Scope | Duration | Price |
|-------|----------|-------|
| Single service (1-5 LLM call sites) | 1 week | $10,000 |
| Multi-service (5-20 call sites) | 2 weeks | $25,000 |
| Enterprise (20+ call sites, multiple repos) | Custom | Contact us |

## Pilot Success Criteria

We define success before we start. Typical criteria:

- **Coverage**: X% of LLM call sites instrumented (measured by `assay scan`)
- **CI gate active**: PRs require evidence verification to merge
- **Evidence portable**: proof pack verifies on a machine that has never seen your code
- **Time-to-evidence**: under 5 minutes from "incident reported" to "proof pack in hand"

At closeout we deliver a before/after report showing:
- Call sites found vs. instrumented
- CI gate catches during pilot
- Time to produce verifiable evidence (before vs. after)

## After the Pilot

You own everything. The CI gate runs on your infrastructure. The proof
packs live in your artifact store. The lockfile prevents drift.

If you want ongoing support:

| Tier | What you get | Price |
|------|-------------|-------|
| Advisory retainer | Priority support + quarterly lockfile/card review | $3-5K/month |
| Design partner | Early access to new features + direct roadmap input | Custom |

## What We Need From You

- Repository access (read-only is fine for the scan phase)
- 1-hour kickoff call to scope requirements and define success criteria
- A point of contact for questions during the engagement
- CI/CD access for the gate setup

## Start

Three ways to start:

1. **Try it yourself first**: `pip install assay-ai && assay quickstart`
2. **Open a pilot inquiry**: [GitHub Issue](https://github.com/Haserjian/assay/issues/new?template=pilot-inquiry.md)
3. **Email directly**: tim2208@gmail.com

If you've already run `assay scan` on your repo, include the output in your
inquiry -- it helps us scope faster.
