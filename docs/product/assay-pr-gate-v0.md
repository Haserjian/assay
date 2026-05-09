# Assay PR Gate v0.1 Product Contract

Assay PR Gate produces a signed review decision for pull requests, binding
evidence, policy, verdict channels, caveats, and recommended action to a
specific commit.

## Current Status

PR Gate is implemented for the same-repository dogfood path.

Implemented:

- local PR Gate pipeline: capture -> evaluate -> pack -> verify -> render
  comment
- same-repository GitHub dogfood workflow
- stable expected signing identity:
  `https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main`
- signed Verification Report verification
- uploaded `assay-pr-gate-report` artifact
- PR comment upsert with stable `<!-- assay-pr-gate:v0 -->` marker

Dogfood evidence:

- PR `#134` produced a signed packet, uploaded artifact, local verification,
  and PR comment.
- PR `#136` also exercised the signed review packet workflow successfully.

Still bounded:

- fork-safe two-lane mode remains future work
- required-check naming and timing remain polish
- PR Gate does not prove code security, production approval, full claim
  correctness, or replay

## Product Thesis

The PR comment is not the product. The signed review decision is the product.
The PR comment is where the product becomes visible.

Do not define Assay as a better PR comment. That puts it next to ordinary CI
annotations. Define Assay PR Gate as a signed, scoped, policy-backed review
decision bound to a PR commit.

Buyer-facing sentence:

> Before risky or AI-assisted code is merged, Assay produces a signed Review
> Packet showing what changed, what was checked, what did not run, and what the
> reviewer should do next.

Short positioning:

> Signed review decisions for high-velocity PRs.

AI-assisted pull requests are the beachhead because they create urgency. The
substrate should also work for non-AI high-risk PRs where reviewer attention is
the bottleneck.

## Product Contract

Input:

- repository
- PR number
- base SHA
- head SHA
- merge or ref SHA when applicable
- changed files
- diff hash
- workflow and run identity
- observed check results
- policy profile
- risk path matches

Output:

- Assay Review Packet
- evidence pack
- Verification Report
- Signature Proof
- PR-visible review decision
- local or CLI verifier result

Primary user:

> Security-minded engineering lead at a 20-500 person software team using
> GitHub and AI coding tools.

First policy:

> AI-assisted PRs are allowed, but risky paths require a signed Assay Review
> Packet and human approval.

## Decision Vocabulary

Keep the decision surface finite.

```text
overall_decision:
  PASS
  NEEDS_REVIEW
  BLOCK
  ERROR
```

`PASS` does not mean "merge automatically." It means Assay found no policy
reason to stop normal review.

Render it as:

```text
PASS - proceed to normal review
```

Recommended actions are also fixed. Do not allow free-form action strings.
Free-form action strings cannot aggregate, compare, dashboard, audit, or price.

```text
recommended_action:
  proceed
  require_human_approval
  request_codeowner_review
  rerun_required_check
  block_missing_evidence
  block_required_check_failed
  block_integrity_failed
  block_untrusted_signer
  manual_triage
```

## Verdict Channels

For PR Gate v0.1:

```text
Integrity: PASS / FAIL
Claim: PASS / FAIL / NOT_EVALUATED
Replay: NOT_RUN
Trust policy: PASS / NEEDS_REVIEW / BLOCK
```

Keep replay as `NOT_RUN`. Do not fake replay.

The first bounded claim should be brutally conservative:

```text
Observed GitHub check run "<name>" had conclusion "<success|failure|...>" for commit "<sha>".
```

If Assay itself runs a command:

```text
Observed command "<cmd>" exited "<code>" inside workflow run "<run_id>" for commit "<sha>".
```

Do not write:

```text
Tests passed.
```

That phrase implies too much. The Assay claim is only that a specific observed
check or command had a specific result for a specific commit.

## Comment Contract

The PR comment is the product face. It must show the binding in the comment
body, not only in linked docs.

Canonical shape:

```text
Assay PR Gate: NEEDS_REVIEW

Recommended action: require_human_approval
Reason: touched risk path auth/**

Subject:
- repo: Haserjian/assay
- PR: #123
- head commit: abc123
- diff hash: sha256:...

Verdict channels:
- Integrity: PASS
- Claim: PASS - observed check "tests" concluded success for commit abc123
- Replay: NOT_RUN
- Trust policy: NEEDS_REVIEW - touched auth/session.py

Evidence:
- Evidence Box: proof-pack/pack_manifest.json
- Verification Report: signed-report/verify_report.json
- Signature Proof: signed-report/verify_report.sigstore.json

Do not infer:
- code is secure
- all possible tests passed
- AI made a good design decision
- replay was performed
- production approval was granted

Signed by expected workflow:
https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main
```

Detailed rendering rules live in:

- `docs/product/assay-pr-gate-comment-v0.md`

## Policy Contract

Initial policy profile:

```yaml
profile: coding_pr_v0

risk_paths:
  - "auth/**"
  - "billing/**"
  - ".github/workflows/**"
  - "infra/**"
  - "pyproject.toml"
  - "package-lock.json"
  - "requirements*.txt"

required_checks:
  - "tests"

rules:
  integrity_failed:
    decision: BLOCK
    recommended_action: block_integrity_failed

  untrusted_signer:
    decision: BLOCK
    recommended_action: block_untrusted_signer

  required_check_failed:
    decision: BLOCK
    recommended_action: block_required_check_failed

  required_check_missing:
    decision: NEEDS_REVIEW
    recommended_action: rerun_required_check

  risk_path_touched:
    decision: NEEDS_REVIEW
    recommended_action: require_human_approval

default:
  decision: PASS
  recommended_action: proceed
```

Detailed policy semantics live in:

- `docs/product/assay-pr-gate-policy-v0.md`
- `docs/examples/pr-gate-v0/assay-policy.yml`

## GitHub Security Model

Do not accidentally create the thing Assay is meant to defend against.

The dogfood path can start with a simple same-repo workflow. Production shape
needs a two-lane model:

Lane A, untrusted collector:

- trigger: `pull_request`
- permissions: read-only
- no secrets
- no privileged token
- collect PR metadata and check evidence
- upload unsigned or minimally signed capture artifact

Lane B, trusted signer and publisher:

- trigger: trusted event such as `workflow_run` or a controlled same-repo path
- permissions: write PR comment and request OIDC signing identity
- never checks out untrusted PR code
- validates capture artifact shape
- evaluates, signs, publishes, and comments

Security ADRs:

- `docs/adr/ADR-pr-gate-two-lane-github-security.md`
- `docs/adr/ADR-pr-gate-trust-root.md`

## Evidence Object

PR Gate evidence should be separate from generic pack internals.

Suggested shape:

```json
{
  "schema_version": "assay.pr_gate.evidence.v0.1",
  "subject": {
    "repo": "Haserjian/assay",
    "pr_number": 123,
    "base_sha": "...",
    "head_sha": "...",
    "diff_sha256": "sha256:..."
  },
  "capture": {
    "provider": "github_actions",
    "workflow_ref": "...",
    "workflow_sha": "...",
    "run_id": "...",
    "run_attempt": "...",
    "actor": "..."
  },
  "changed_files": [
    {
      "path": "auth/session.py",
      "status": "modified",
      "sha256_after": "sha256:..."
    }
  ],
  "observed_checks": [
    {
      "name": "tests",
      "provider": "github_checks",
      "head_sha": "...",
      "conclusion": "success",
      "observed_at": "..."
    }
  ],
  "policy": {
    "profile": "coding_pr_v0",
    "policy_sha256": "sha256:..."
  }
}
```

Hash contracts:

- `diff_sha256` hashes the exact bytes emitted by
  `git diff --binary --full-index <base_sha> <head_sha>` in a checkout where
  both SHAs are present. The capture object must record a different
  `diff_source` before any future implementation may hash GitHub API response
  bytes instead.
- `sha256_after` hashes the raw file bytes at `head_sha`. Deleted files must
  set `sha256_after` to `null` and keep `status: "deleted"`.
- `policy_sha256` hashes the parsed policy object after RFC 8785/JCS
  canonical JSON serialization, using Assay's existing canonicalization helper
  if available. Formatting changes in the YAML must not change this hash.
- PR Gate hash fields render as `sha256:<64 lowercase hex chars>`.

Acceptance condition:

> This object can be hashed, included in an evidence pack, and referenced by
> the Verification Report.

## Milestones

### Milestone 0: Product Constitution

Create and keep current:

- `docs/product/assay-pr-gate-v0.md`
- `docs/product/assay-pr-gate-comment-v0.md`
- `docs/product/assay-pr-gate-policy-v0.md`
- `docs/adr/ADR-pr-gate-trust-root.md`
- `docs/adr/ADR-pr-gate-two-lane-github-security.md`

Acceptance condition:

> A reviewer can read the docs and understand exactly what PR Gate claims and
> does not claim.

### Milestone 1: Policy Profile

Create:

- `docs/examples/pr-gate-v0/assay-policy.yml`

Acceptance condition:

> The policy file parses as YAML, declares the `coding_pr_v0` profile, and uses
> only fixed decision and recommended action identifiers in its rules and
> default. It must include risk paths, required checks, rule keys, and a default
> decision. It does not require evaluator behavior yet.

### Milestone 2: Capture Adapter

Planned module:

```text
Python module: assay.pr_gate.github_capture
File path: src/assay/pr_gate/github_capture.py
```

Planned CLI:

```bash
assay pr-gate capture \
  --repo "$GITHUB_REPOSITORY" \
  --pr "$PR_NUMBER" \
  --head-sha "$GITHUB_SHA" \
  --out .assay/pr-gate/evidence.json
```

Acceptance condition:

> Running capture on a PR produces stable JSON and a deterministic diff hash.

### Milestone 3: Policy Evaluator

Planned module:

```text
Python module: assay.pr_gate.policy
File path: src/assay/pr_gate/policy.py
```

Planned CLI:

```bash
assay pr-gate evaluate \
  --evidence .assay/pr-gate/evidence.json \
  --policy docs/examples/pr-gate-v0/assay-policy.yml \
  --out .assay/pr-gate/decision.json
```

Decision output:

```json
{
  "overall_decision": "NEEDS_REVIEW",
  "recommended_action": "require_human_approval",
  "reasons": [
    {
      "rule": "risk_path_touched",
      "path": "auth/session.py",
      "matched_pattern": "auth/**"
    }
  ],
  "channels": {
    "integrity": "PASS",
    "claim": "PASS",
    "replay": "NOT_RUN",
    "trust_policy": "NEEDS_REVIEW"
  }
}
```

Acceptance condition:

> Tests cover risk path, missing check, failed check, untrusted signer, and
> clean PR.

### Milestone 4: Packet Generator

Planned module:

```text
Python module: assay.pr_gate.packet
File path: src/assay/pr_gate/packet.py
```

Planned output:

```text
proof-pack/
  pack_manifest.json
  pr_gate_evidence.json
  pr_gate_decision.json
  changed_files.json
  observed_checks.json
  policy.yml
  verify_transcript.md

signed-report/
  verify_report.json
  verify_report.sigstore.json
```

Acceptance condition:

> The Verification Report points to the evidence pack root hash and names all
> verdict channels.

### Milestone 5: Stable Signing Identity

Graduate from the historical PR sample identity to:

```text
https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main
```

Acceptance condition:

> Clean report verifies. Report tamper fails. Wrong expected identity fails.

### Milestone 6: Comment Renderer

Planned module:

```text
Python module: assay.pr_gate.render_comment
File path: src/assay/pr_gate/render_comment.py
```

Planned snapshots:

```text
tests/pr_gate/snapshots/comment_pass.md
tests/pr_gate/snapshots/comment_needs_review.md
tests/pr_gate/snapshots/comment_block.md
```

Acceptance condition:

> The PR comment is stable, readable, and includes the three objects: Evidence
> Box, Verification Report, Signature Proof.

### Milestone 7: GitHub Workflow

Dogfood workflow:

```text
.github/workflows/assay-pr-gate.yml
```

Acceptance condition:

> A real Assay PR gets a comment backed by uploaded evidence pack and signed
> report artifacts.

### Milestone 8: Verification CLI

Planned CLI:

```bash
assay pr-gate verify \
  --pack proof-pack \
  --report signed-report/verify_report.json \
  --sigstore signed-report/verify_report.sigstore.json \
  --expected-identity "https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main"
```

Expected output:

```text
Result: ASSAY PR GATE VERIFIED
Decision: NEEDS_REVIEW
Recommended action: require_human_approval
Integrity: PASS
Claim: PASS
Replay: NOT_RUN
Trust policy: NEEDS_REVIEW
```

Acceptance condition:

> Clean packet verifies. Report tamper rejects. Pack tamper rejects. Wrong
> signer rejects. Policy hash mismatch rejects or downgrades to manual_triage.

### Milestone 9: Demo PR

Create a deliberately obvious dogfood PR:

```text
touches auth/session.py
has observed check success
triggers risk path policy
receives NEEDS_REVIEW
packet verifies locally
tamper demo fails
```

Acceptance condition:

> A skeptical engineering lead can watch one PR and understand the value in
> under five minutes.

## Agent Workstreams

Use parallel agents only after the interfaces above are fixed.

| Agent | Ownership | Output |
|---|---|---|
| Product/spec | Product docs and non-claims | Updated product contract and examples |
| Policy engine | `src/assay/pr_gate/policy.py` | Deterministic `decision.json` and tests |
| GitHub capture | `src/assay/pr_gate/github_capture.py` | Stable `evidence.json` and tests |
| Packet/report | `src/assay/pr_gate/packet.py` | Evidence pack and Verification Report |
| Signing/verification | PR Gate verify CLI | clean/tamper/wrong-identity tests |
| Comment renderer | `src/assay/pr_gate/render_comment.py` | Markdown snapshots |
| GitHub workflow | `.github/workflows/assay-pr-gate.yml` | Dogfood PR comments |
| Demo/docs | `docs/examples/pr-gate-v0/` | Cold-reader walkthrough and tamper demo |

## Out Of Scope For v0.1

- Hosted dashboard.
- Ledger.
- Scorecard interpretation.
- MemoryGraph.
- Quintet.
- Full agent replay.
- Full static analysis.
- Full vulnerability scanner.
- Automatic AI-authorship detection.
- Enterprise compliance mapping.
- Multi-witness verification.

These stay out until a named buyer conversation asks for them.

## Buyer Test

First uncomfortable demo:

```text
Here is a real PR.
Here is what changed.
Here is why Assay marked NEEDS_REVIEW.
Here is the signed packet.
Here is what it does not claim.
Here is what happens if I tamper with it.
Would this reduce review ambiguity on your team?
What would make this required in your workflow?
```

The sales question is not:

```text
Do you like provenance?
```

The sales question is:

```text
Would you require this before merging AI-assisted changes to auth, billing,
infra, or workflows?
```

## Real Success Conditions

1. A real Assay PR receives a signed Assay PR Gate comment saying
   `NEEDS_REVIEW` for a concrete reason.
2. The linked evidence pack verifies locally.
3. Tampering with the report, pack, policy, or signer breaks verification.
4. A skeptical engineering lead can read the comment and say: "I understand
   what this is for."

## Research Anchors

- GitHub Actions contexts expose run, workflow, ref, actor, SHA, and retention
  metadata useful for capture:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/contexts>
- GitHub Checks API supports listing check runs for a Git reference:
  <https://docs.github.com/en/rest/reference/checks>
- GitHub artifact attestations already provide signed build provenance; Assay
  should add review semantics, not compete on raw signing:
  <https://docs.github.com/actions/concepts/security/artifact-attestations>
- GitHub secure-use guidance warns about privileged triggers with untrusted PR
  checkout:
  <https://docs.github.com/en/enterprise-server@3.16/actions/reference/security/secure-use>
- GitHub Security Lab's pwn-request guidance motivates the two-lane model:
  <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>
- OpenTelemetry GenAI conventions include agent/workflow/tool spans but remain
  development-stage; PR Gate should be trace-compatible without depending on
  one final trace schema:
  <https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/>
