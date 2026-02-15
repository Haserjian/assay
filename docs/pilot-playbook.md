# Pilot Execution Playbook

Internal runbook for executing Assay pilot engagements.
For the customer-facing overview, see [PILOT_PROGRAM.md](PILOT_PROGRAM.md).

---

## Qualification

Before accepting a pilot, verify:

| Criterion | Minimum | Ideal |
|-----------|---------|-------|
| LLM call sites | 1+ | 5-20 |
| SDK providers | OpenAI, Anthropic, or LangChain | Multiple |
| CI/CD | Any automated pipeline | GitHub Actions |
| Python version | 3.9+ | 3.10+ |
| Decision maker available | Yes | On kickoff call |
| Timeline driver | Exists (audit, compliance, incident) | Urgent (< 3 months) |

**Disqualify if:**
- No LLM calls in production (nothing to instrument)
- No CI/CD pipeline and no plan to add one (can't gate)
- Only needs logging/monitoring (Assay is evidence, not observability)
- Team expects Assay to prevent attacks (Assay detects tampering, not intrusions)

## Pre-Pilot

### Before kickoff call

1. Send [intake template](pilot/intake-template.md) -- collect before the call, not during
2. If they've run `assay scan .`, review their output to estimate scope
3. Determine pricing tier:
   - 1-5 call sites, single repo: **$10K / 1 week**
   - 5-20 call sites, 1-3 repos: **$25K / 2 weeks**
   - 20+ call sites, multiple repos: **custom quote**
4. Prepare a scope doc with: repos in scope, SDKs detected, compliance frameworks, exit criteria

### Kickoff call (1 hour)

Agenda:
1. **10 min**: What problem they're solving (audit response? proactive? incident?)
2. **15 min**: Walk through `assay scan --report` on their repo (screen share)
3. **15 min**: Define success criteria together (use [PILOT_PROGRAM.md](PILOT_PROGRAM.md) defaults, customize)
4. **10 min**: Agree on day-by-day plan (adjust standard 2-week schedule to their constraints)
5. **10 min**: Access requirements, point of contact, communication channel

**Must leave the call with:**
- Written success criteria (email confirmation)
- Repo access (read-only minimum)
- CI/CD access (for gate setup)
- Named point of contact + async channel (Slack/email)

## Week 1: Instrument + Gate

### Day 1: Scan + Scope

```bash
# Run on every repo in scope
assay scan . --report
```

Deliverables:
- HTML gap report per repo (share with prospect)
- Call site inventory spreadsheet: file, line, SDK, framework, priority
- Scope confirmation: which call sites to instrument, which to defer

**Decision point**: If scan finds significantly more/fewer sites than expected,
re-scope and re-confirm pricing before proceeding.

### Days 2-3: Instrumentation

For each call site:
```bash
# Try auto-patch first
assay patch .

# If auto-patch doesn't cover a site, instrument manually:
# OpenAI/Anthropic: assay patch handles these
# LangChain: add AssayCallbackHandler to chain callbacks
```

Verify each instrumented site emits receipts:
```bash
assay run -- python test_script.py
# Check: receipts appear in .assay/receipts/
```

Track progress: X of Y sites instrumented, remaining blockers.

**Common blockers:**
- LangChain callbacks (manual, not auto-patchable)
- Self-hosted models with non-standard SDKs (custom integration needed)
- Monorepo with scattered entrypoints (need to identify all execution paths)

### Day 4: CI Gate

```bash
# In CI pipeline:
assay run -c receipt_completeness -- python my_app.py
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
assay diff ./baseline_pack/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0 --gate-strict
```

Deliverables:
- Working CI step in their pipeline
- First successful gate pass on a real PR
- First gate failure on a deliberately broken PR (demonstrate the catch)

### Day 5: Lockfile + Custom Cards

```bash
assay lock write --cards receipt_completeness -o assay.lock
```

If they have custom compliance needs, write RunCards:
- Map each compliance control to a verifiable claim
- Start minimal: 1-2 custom cards, not 10
- Each card must have clear pass/fail semantics

Deliverables:
- `assay.lock` committed to their repo
- Custom cards documented with rationale
- Baseline proof pack saved as regression reference

## Week 2: Harden + Hand Off

### Days 6-7: Threshold Tuning

Run the gate on 5-10 real PRs. Track:
- False positives (gate blocks a good PR)
- False negatives (gate passes a bad PR)
- Noise (warnings that aren't actionable)

Adjust:
- `--gate-cost-pct` threshold (default 25, tune to their cost variance)
- `--gate-errors` threshold (default 0, may need 1-2 for flaky tests)
- Card claim thresholds (minimum receipt counts, required fields)

**Goal**: zero false positives by end of day 7. False negatives are less urgent
(they weaken the gate but don't block developers).

### Days 8-9: Key Management

```bash
# Generate CI signing key (separate from dev keys)
assay key rotate

# Set up signer allowlist in lockfile
assay lock write --cards receipt_completeness --signer-allowlist ci-key-id -o assay.lock
```

Deliver:
- CI key separated from dev keys
- Signer allowlist in lockfile (CI key required for merge-to-main packs)
- Key rotation runbook (how to rotate quarterly)

### Day 10: Documentation Handoff

Deliver the [closeout report](pilot/closeout-template.md) with:
- Before/after scan coverage
- CI gate catch summary
- Time-to-evidence measurement
- Maintenance guide: what to do when adding new call sites, updating SDKs, rotating keys
- "What This Evidence Means" doc for their security/compliance team
- Pack of links: `verify-pack` command, `explain` command, `for-compliance.md`

**Closeout call (30 min)**:
1. Walk through closeout report
2. Demonstrate offline verification (download pack, verify on a different machine)
3. Discuss ongoing support options (retainer vs. self-service)

## Escalation Paths

| Issue | Response |
|-------|----------|
| Scan finds 0 call sites | Prospect may not be using supported SDKs. Check for direct HTTP calls to LLM APIs. If none, disqualify. |
| Auto-patch fails | Fall back to manual instrumentation. Add 1-2 days to timeline. |
| CI system not supported | Write custom integration. GitHub Actions and GitLab CI are straightforward. Others may need custom scripts. |
| Prospect wants runtime monitoring | Explain: Assay is batch evidence, not real-time monitoring. Offer to help integrate with their existing monitoring. |
| Prospect wants to verify claims about external truth | Explain trust model: Assay verifies evidence integrity, not external truth. Point to `for-compliance.md`. |
| Scope creep (new repos, new requirements mid-pilot) | Re-scope, re-price. Don't absorb scope creep into the fixed-price engagement. |

## Upsell Triggers

Watch for these during the pilot -- they signal readiness for ongoing engagement:

| Signal | Upsell |
|--------|--------|
| "Can we add this to our other repos?" | Multi-repo engagement or enterprise tier |
| "We need this for our SOC 2 audit next quarter" | Advisory retainer (quarterly review) |
| "Can we customize the claim cards for our policies?" | Design partner (roadmap input) |
| "We want to verify packs from our vendors" | Vendor verification workflow (future product) |
| "Can this work with our MCP tool calls?" | MCP Notary Proxy early access (Phase 2) |
| Team runs `assay analyze --history` unprompted | Ops adoption signal -- offer retainer for threshold tuning |

## Post-Pilot Follow-Up

| Timing | Action |
|--------|--------|
| Day 11 | Send closeout report + thank-you email |
| Day 14 | Check in: "Any gate issues this week?" |
| Day 30 | Check in: "How's the CI gate holding up? Any new call sites?" |
| Day 60 | Review: "Ready for a quarterly lockfile review?" (retainer pitch) |
| Quarterly | If on retainer: lockfile audit, card review, threshold check, key rotation |
