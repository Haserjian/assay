# Assay PR Gate Dogfood v0

## Purpose

This dogfood workflow makes PR Gate visible on real Assay pull requests.

For same-repository pull requests targeting `main`, Assay PR Gate produces a
signed review packet and posts a single marked PR comment. The comment is the
review surface. The product object is the signed review decision bound to the
evidence pack, policy, verdict channels, caveats, and PR commit.

## Workflow

The workflow is `.github/workflows/assay-pr-gate.yml`.

It runs on `pull_request_target` for same-repo PRs only:

```text
github.event.pull_request.head.repo.full_name == github.repository
```

The workflow checks out trusted base-branch code, fetches the PR head as passive
git data, and does not execute scripts from the PR head.

The workflow steps are:

1. Check out trusted base workflow code.
2. Fetch the PR head commit as passive git data.
3. Install Assay from the trusted checkout.
4. Capture PR evidence.
5. Evaluate the dogfood `coding_pr_v0` policy.
6. Build `proof-pack/` and `signed-report/`.
7. Sign `signed-report/verify_report.json` with Cosign/Sigstore.
8. Verify the signed PR Gate packet locally.
9. Render the PR comment.
10. Upload the `assay-pr-gate-report` artifact.
11. Create or update the marked PR comment.

## Uploaded Artifact

The artifact is named:

```text
assay-pr-gate-report
```

It contains:

```text
.assay/pr-gate/
  evidence.json
  decision.json
  proof-pack/
  signed-report/
  comment.md
```

## PR Comment

The workflow posts or updates one PR timeline comment with this marker:

```text
<!-- assay-pr-gate:v0 -->
```

The comment includes:

- overall decision
- recommended action
- primary reason
- PR subject
- verdict channels
- Evidence Box, Verification Report, and Signature Proof paths
- do-not-infer caveats
- expected workflow signer identity
- workflow run link
- artifact link

Existing marked comments are updated in place so the workflow does not spam
duplicate comments.

## Dogfood Policy

The workflow uses `docs/examples/pr-gate-v0/assay-dogfood-policy.yml`.

That policy intentionally has no required check names. The first live dogfood
surface should not report a missing `tests` check when this repository's checks
use different names or report at different times. Required-check semantics are
kept in `docs/examples/pr-gate-v0/assay-policy.yml` and remain part of PR Gate,
but dogfood focuses on integrity, signing, artifact publication, comment
upsert, and risk-path review.

## Signing Identity

The expected signer identity is:

```text
https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main
```

The workflow uses GitHub Actions OIDC and Sigstore/Cosign signing. Verification
requires the expected certificate identity and issuer:

```text
https://token.actions.githubusercontent.com
```

## What This Proves

The dogfood workflow proves that the PR Gate loop can produce a signed,
portable review decision for a real PR:

- the evidence pack hashes match
- the Verification Report binds to the evidence pack root
- the policy hash matches the policy file
- the decision recomputes from evidence and policy
- the signed report verifies against the expected workflow identity

## What This Does Not Prove

This workflow does not prove:

- the code is secure
- all possible tests passed
- AI made a good design decision
- replay was performed
- production approval was granted
- fork-safe production publishing is complete

## Security Boundary

This is a same-repo dogfood workflow, not the full fork-safe production design.

The workflow uses `pull_request_target` so the signing identity can be the stable
base workflow identity. That is dangerous if combined with checkout or execution
of untrusted PR code.

The rule for this workflow is:

```text
PR contents are passive evidence, not executable code.
```

The workflow may inspect diffs, object hashes, paths, check-run metadata, and
GitHub API facts. It must not run build scripts, tests, package scripts, or other
code from the PR head in the privileged signing/comment lane.

Fork-safe production mode remains a separate two-lane implementation described
in `docs/adr/ADR-pr-gate-two-lane-github-security.md`.
