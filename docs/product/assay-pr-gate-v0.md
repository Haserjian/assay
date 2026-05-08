# Assay PR Gate v0

Assay PR Gate gives AI-assisted pull requests a signed review packet showing
what changed, what checks ran, what passed, what did not run, and whether
policy requires human review.

This is a product planning note. It does not claim that PR Gate is implemented
today. The current implemented base is the Verification Gate v0 integrity
sample: evidence pack, Verification Report, Sigstore Signature Proof, verdict
channels, and conservative scope language.

## Product Bet

Stop selling the primitive:

> Verify this signed artifact.

Sell the review moment:

> Before we merge AI-assisted code, we require an Assay Review Packet.

The buyer does not pay for signed JSON. The buyer pays for confidence that
AI-assisted work can be reviewed, approved, escalated, audited, or defended
without trusting a dashboard, screenshot, or verbal claim.

## First Wedge

Start with GitHub pull request review for AI-assisted code.

This wedge has a concrete buyer, workflow, and decision:

| Item | v0 choice |
|---|---|
| Buyer | Engineering lead or security-minded team |
| Workflow | GitHub pull request review |
| Decision | Merge normally, require human approval, or block |
| Artifact | Signed Assay Review Packet |
| Pain | AI-assisted code is hard to trust blindly |

Do not start with generic AI governance. Do not start with dashboards. The
first product surface is the pull request comment because it appears at the
decision point.

## User Story

As an engineering lead, when an AI-assisted pull request is opened or updated,
I want a signed review packet so I can see what happened, what evidence was
captured, what checks ran, and whether policy says this needs human attention.

## Product Surface

The first surface is a GitHub PR comment.

Example:

```text
Assay PR Gate: NEEDS_REVIEW

Profile: coding_pr_v0
Recommended action: require human approval before merge

Integrity: PASS
Claim: PASS - observed CI check exited 0 for commit abc123
Replay: NOT_RUN
Trust policy: NEEDS_REVIEW - touched auth/**

Evidence captured:
- repo: Haserjian/example
- PR: #42
- commit: abc123
- changed files: 4
- risk paths touched: auth/session.py
- signer: expected GitHub Actions workflow

View signed review packet: <link>
Download Verification Report: <link>
```

The wording must stay bounded. `Claim: PASS` for v0 means a specific observed
claim was supported by captured evidence. It must not mean "the code is good"
or "all relevant tests passed."

## Decision Model

PR Gate should make the next action explicit:

```json
{
  "overall_verdict": "NEEDS_REVIEW",
  "recommended_action": "require_human_approval",
  "blocking_reason": "touched_risk_path"
}
```

The decision fields are product-facing summaries. They do not replace the
underlying verdict channels; they make the review moment legible.

## Verdict Channels

Use the existing Verification Gate channel discipline, but connect it to PR
review decisions.

| Channel | v0 meaning |
|---|---|
| Integrity | Evidence pack and Verification Report are intact and bound together. |
| Claim | A narrow PR claim is checked against captured evidence. |
| Replay | Not run in v0. Do not fake replay. |
| Trust policy | Repo policy maps facts to PASS, NEEDS_REVIEW, or BLOCK. |

For the first PR Gate demo:

```text
Integrity: PASS
Claim: PASS - observed CI check exited 0 for commit abc123
Replay: NOT_RUN
Trust policy: NEEDS_REVIEW - touched auth/**
```

## Bounded Claim Gate

The first claim gate should be painfully concrete.

Good v0 claim:

```text
Observed CI check exited 0 for commit abc123.
```

Evidence required:

- CI job or check identifier
- command or check name
- exit code or check conclusion
- commit SHA
- timestamp
- output or output hash when available

Avoid:

```text
Tests passed.
```

That phrasing can imply all relevant tests passed. PR Gate v0 should only
claim that a specific observed check passed for a specific commit.

## Trust Policy Gate

Trust policy is the first money gate because it tells a reviewer what to do.

Initial policy shape:

```yaml
profile: coding_pr_v0

risk_paths:
  - "auth/**"
  - "billing/**"
  - ".github/workflows/**"

rules:
  tests_missing:
    verdict: NEEDS_REVIEW
    action: require_human_approval

  risk_path_touched:
    verdict: NEEDS_REVIEW
    action: require_human_approval

  report_signature_invalid:
    verdict: BLOCK
    action: do_not_merge

  evidence_integrity_failed:
    verdict: BLOCK
    action: do_not_merge
```

This policy is intentionally small. It should be easy for a reviewer to
explain why a PR received PASS, NEEDS_REVIEW, or BLOCK.

## Evidence Captured

PR Gate v0 should capture the boring facts needed for review:

- repository
- PR number
- branch or ref
- commit SHA
- changed files
- diff hash
- risk path matches
- actor and workflow identity
- relevant CI check names and conclusions
- observed command, exit code, and output hash when available
- policy profile and policy hash
- timestamps

Do not make users manually assemble this evidence. The packet should be
generated as a side effect of the normal pull request workflow.

## MVP Flow

```text
1. Developer or agent opens/updates a PR.
2. GitHub Action runs.
3. Assay captures PR metadata, changed files, risk path matches, and observed checks.
4. Assay applies coding_pr_v0 policy.
5. Assay emits proof-pack/.
6. Assay emits signed-report/verify_report.json.
7. Assay signs the public Verification Report.
8. Assay uploads the packet as a workflow artifact.
9. Assay posts or updates a PR comment.
10. Reviewer reads the comment and opens the signed review packet if needed.
```

## Demo Scenario

Use a deliberately obvious PR:

```text
AI-assisted change modifies auth/session.py.
CI check exits 0 for the commit.
Assay records changed files and the observed check result.
Policy flags auth/** as high-risk.
PR comment says NEEDS_REVIEW.
Evidence pack and signed Verification Report are attached.
Tampering breaks verification.
```

This demo should make the review value visible in seconds:

```text
The code may be fine, but policy requires a human because auth/** changed.
```

## Tamper Demonstrations

Keep the existing tamper discipline and apply it to the PR packet:

| Tamper | Expected result |
|---|---|
| Change Verification Report verdict | Signature verification fails. |
| Change evidence pack file | Pack integrity fails. |
| Swap evidence pack | Pack root mismatch fails. |
| Remove risk path evidence | Policy/report consistency fails. |

## Out Of Scope For v0

- Proving the code is secure.
- Proving the AI made a good design decision.
- Replaying the agent run.
- Full static analysis.
- Full supply-chain attestation.
- Hosted dashboard.
- Ledger.
- Scorecards.
- MemoryGraph.
- Quintet.
- Multi-witness verification.
- General AI governance platform.

## Open Implementation Questions

- Should the first runnable slice live in this repo or in
  `assay-verify-action`?
- Should PR comment creation be implemented directly or delegated to an
  existing comment action?
- Which CI checks should v0 observe: named checks, local commands, or both?
- Where should `coding_pr_v0` policy live in a consumer repo?
- Should hosted verification wait until the PR comment proves useful, or
  should the first demo use a static verifier page?

## First Build Target

Build the smallest runnable PR Gate slice as a GitHub Action, wherever it can
be proven fastest.

Minimum successful demo:

```text
A GitHub PR receives an Assay comment saying PASS / NEEDS_REVIEW / BLOCK,
backed by a signed evidence pack and public Verification Report.
```

Do not block this prototype on final package boundaries, hosted dashboards, or
general trace ingestion. Prove the review loop first.

## Positioning

Short:

> Signed review packets for AI-assisted pull requests.

Buyer sentence:

> Assay PR Gate shows what changed, what checks ran, what passed, what did not
> run, and what policy says the reviewer should do next.

Boundary sentence:

> Assay does not prove AI work is correct. It makes AI-assisted work
> inspectable, attributable, tamper-evident, and bounded enough to review.
