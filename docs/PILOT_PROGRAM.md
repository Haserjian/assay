# Assay Compliance Audit Sprint

A 1-week engagement to instrument your AI system with tamper-evident
evidence and lock it into CI.

## What You Get

**Week 1 Deliverables:**
1. **Codebase scan** -- full report of every LLM call site, instrumented vs. not
2. **Instrumentation** -- patch your SDK calls to emit structured receipts
3. **RunCard suite** -- custom claim verifiers mapped to your compliance needs
4. **Proof Pack pipeline** -- `assay run` wired into your existing test/deploy flow
5. **CI gate** -- GitHub Action (or equivalent) that blocks merges on verification failure
6. **Lockfile** -- frozen verification contract preventing silent claim weakening
7. **Documentation** -- how to maintain, extend, and explain the setup to auditors

## What It Costs

| Scope | Duration | Price |
|-------|----------|-------|
| Single service (1-5 LLM call sites) | 1 week | $10,000 |
| Multi-service (5-20 call sites) | 2 weeks | $25,000 |
| Enterprise (20+ call sites, multiple repos) | Custom | $25,000+ |

## Who It's For

- Engineering teams with AI in production that need audit trails
- Companies preparing for SOC 2, HIPAA, EU AI Act, or ISO 42001
- Teams that got the compliance question and don't have an answer yet

## What We Need From You

- Repository access (read-only is fine for the scan phase)
- 1 hour kickoff call to scope requirements
- A point of contact for questions during the week
- CI/CD access for the gate setup

## Timeline

```
Day 1:  Kickoff + scan + findings review
Day 2-3: Instrumentation + RunCard authoring
Day 4:  CI gate + lockfile + verification pipeline
Day 5:  Documentation + handoff + Q&A
```

## After the Sprint

You own everything. No ongoing dependency on us. The CI gate runs on
your infrastructure. The proof packs live in your repo. The lockfile
prevents drift. If you want ongoing support, we offer advisory retainers
at $3-5K/month.

## Start

[Open a pilot inquiry](https://github.com/Haserjian/assay/issues/new?template=pilot-inquiry.md)
or email directly.
