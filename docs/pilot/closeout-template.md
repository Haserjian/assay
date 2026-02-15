# Pilot Closeout Report

**Client**: [Company / Project Name]
**Pilot dates**: [Start] -- [End]
**Scope**: [X repos, Y LLM call sites, Z compliance frameworks]
**Pilot tier**: [Single service / Multi-service / Enterprise]

---

## Executive Summary

<!-- 2-3 sentences: what was done, what the outcome is, one key metric. -->

---

## Before / After

### Call Site Coverage

| Metric | Before | After |
|--------|--------|-------|
| Total LLM call sites found (`assay scan`) | | |
| Call sites instrumented | 0 | |
| Coverage % | 0% | |
| Frameworks detected | | |

### Evidence Pipeline

| Capability | Before | After |
|------------|--------|-------|
| Signed proof packs on merge | No | Yes |
| CI gate blocking unverified PRs | No | Yes |
| Offline verification possible | No | Yes |
| Lockfile preventing config drift | No | Yes |
| Key separation (dev vs CI) | No | Yes |
| Time to produce verifiable evidence | N/A | [X min] |

### CI Gate Activity (during pilot)

| Event | Count |
|-------|-------|
| Gate runs (total) | |
| Integrity PASS + Claims PASS (exit 0) | |
| Integrity PASS + Claims FAIL (exit 1) -- honest failures caught | |
| Integrity FAIL (exit 2) -- tampering detected | |
| Bad input (exit 3) | |

<!-- Highlight the most interesting gate catch: what would have shipped without the gate? -->

### Regression Detection

| Metric | Baseline | Current | Gate threshold |
|--------|----------|---------|----------------|
| Cost per run | | | --gate-cost-pct [X]% |
| Error count | | | --gate-errors [X] |
| Receipt count | | | |

---

## Deliverables Checklist

- [ ] `assay.lock` committed to repo(s)
- [ ] CI pipeline step producing signed proof packs
- [ ] Baseline proof pack saved as regression reference
- [ ] Custom RunCards for [compliance framework(s)]
- [ ] Signer allowlist configured (CI key vs dev keys)
- [ ] Key rotation runbook delivered
- [ ] "What This Evidence Means" doc for security/compliance reviewers
- [ ] HTML gap report (before instrumentation, for audit records)
- [ ] HTML gap report (after instrumentation, showing coverage)

---

## Success Criteria Evaluation

| Criterion | Target | Actual | Met? |
|-----------|--------|--------|------|
| Coverage (% of call sites instrumented) | | | |
| CI gate active on merge-to-main | Yes | | |
| Evidence portable (verifies offline) | Yes | | |
| Time-to-evidence | < 5 min | | |
| [Custom criterion] | | | |

---

## Maintenance Guide

### Adding new call sites
1. Run `assay scan . --report` to find new uninstrumented sites
2. Run `assay patch .` or instrument manually
3. Verify receipts are emitted: `assay run -- python test_script.py`
4. Update lockfile if card configuration changed: `assay lock write ...`

### Updating SDK versions
1. Update the SDK package
2. Run `assay doctor` to verify compatibility
3. Run the CI gate on a test PR to confirm pack generation still works

### Rotating signing keys
1. `assay key rotate` (generates new key, does not delete old)
2. `assay key list` to confirm new key is active
3. Update lockfile signer allowlist if applicable
4. Old keys remain valid for verifying historical packs

### Responding to gate failures
- **Exit 0**: All good. Evidence checks out, behavior meets standards.
- **Exit 1**: Honest failure. Evidence is authentic but standards are violated. Investigate the claims that failed: `assay explain ./proof_pack_*/`
- **Exit 2**: Tampering detected. Evidence integrity broken. This is serious -- investigate the build environment.
- **Exit 3**: Bad input. Check arguments, file paths, lockfile format.

---

## Recommendations

### Immediate (no cost)

<!-- What they should do in the next 2 weeks to maintain the setup -->

### Next Quarter

<!-- What would strengthen their evidence posture: more coverage, stricter gates, compliance-specific cards -->

### If Audit Is Coming

<!-- Specific prep: which packs to archive, how to present evidence to auditors, pointer to for-compliance.md -->

---

## Next Steps

### Self-Service (included)

Everything delivered during this pilot is yours. The CI gate runs on your
infrastructure. The proof packs live in your artifact store. The lockfile
prevents drift. Assay itself is open source (`pip install assay-ai`).

Useful commands for ongoing ops:
```bash
assay analyze --history --since 7    # weekly cost/latency/error trends
assay diff ./proof_pack_*/ --against-previous --why    # regression forensics
assay doctor                         # preflight check after environment changes
```

### Advisory Retainer ($3-5K/month)

- Priority support (< 4 hour response time)
- Quarterly lockfile and card review
- Gate threshold tuning as your system evolves
- Key rotation assistance
- Early access to new Assay features

### Design Partner (custom)

- Direct roadmap input
- Early access to pre-release features (MCP proxy, regime detection, drift analysis)
- Custom card development for your compliance frameworks
- Joint case study (with your approval)

### Contact

- Email: tim2208@gmail.com
- GitHub: [github.com/Haserjian/assay](https://github.com/Haserjian/assay)
- Pilot inquiries: [Open an issue](https://github.com/Haserjian/assay/issues/new?template=pilot-inquiry.md)
