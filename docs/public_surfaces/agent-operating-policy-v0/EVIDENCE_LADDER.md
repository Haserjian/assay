# Can You Break This Agent Policy Claim?

This is a skeptical reader challenge card for Agent Operating Policy v0. It is not a new engine, command, workflow, or launch claim.

## The Claim

Assay checks observed PR evidence against an explicit agent operating policy and emits a signed, reviewable verdict about whether the captured evidence satisfies that policy.

Shorter version:

```text
AGENTS.md tells the agent what to do.
Assay tells the reviewer what the captured PR evidence supports.
```

## The Evidence Ladder

The current ladder is small:

1. PR #152 created the Agent Operating Policy v0 packet under `docs/public_surfaces/agent-operating-policy-v0/`.
2. Assay PR Gate reviewed PR #152 and returned `PASS`.
3. The downloaded PR #152 signed review packet verified locally with `ASSAY PR GATE VERIFIED`.
4. A disposable copy of the PR #152 proof pack was modified, and verification failed closed with `proof-pack file hash mismatch: pr_gate_decision.json`.
5. `DOGFOOD.md` recorded the PR #152 verdict, artifact metadata, local verification result, and tamper failure.
6. PR #153 reviewed the dogfood record and returned `PASS`.
7. PR #153 merged the dogfood record into `main`.

This is the loop:

```text
instruction file
-> machine policy
-> PR evidence
-> signed gate verdict
-> dogfood record
-> second signed gate verdict
```

## What This Supports

This supports only bounded review claims:

- The AOP v0 packet exists as a public-surface artifact.
- The PR #152 captured evidence satisfied the PR Gate checks listed in the signed packet.
- The downloaded PR #152 proof pack verified locally under the expected workflow identity.
- A modified proof-pack file failed verification.
- The `DOGFOOD.md` record itself passed PR Gate in PR #153.

## What This Does Not Support

This does not show:

- that the agent followed `AGENTS.md`
- hidden runtime activity
- code safety
- production approval
- unsupported implementation claims
- replay, because the PR Gate replay channel was `NOT_RUN`
- claim evaluation, because the PR Gate claim channel was `NOT_EVALUATED`

If a reader comes away believing more than this, the wording is too broad.

## Three Ways To Challenge It

### 1. Policy Drift

Question: does the human instruction layer match the machine policy layer?

Check:

- `AGENTS.md`
- `assay.agent_policy.json`
- `assay.agent_policy.schema.json`
- the hash bindings inside the policy and fixtures

Possible break:

- `AGENTS.md` says one thing while `assay.agent_policy.json` enforces another.
- The schema accepts a policy shape the human document never describes.
- Hash bindings are stale or fail to match file bytes.

### 2. Evidence Drift

Question: does the signed verdict match the proof pack, artifact, and PR evidence?

Check:

- PR #152 PR Gate comment
- PR #152 `assay-pr-gate-report` artifact while it is available
- `proof-pack/pack_manifest.json`
- `signed-report/verify_report.json`
- `signed-report/verify_report.sigstore.json`
- `DOGFOOD.md`

Possible break:

- The PR comment says `PASS`, but the downloaded artifact does not verify.
- The report hashes do not match the proof-pack files.
- A tampered proof-pack file still verifies.
- `DOGFOOD.md` records a command or hash that does not match the artifact.

### 3. Overclaim Drift

Question: do the docs imply more than the evidence supports?

Check every reader-facing file for claims that imply:

- agent obedience
- code safety
- validated runtime activity
- production approval
- replay evidence when replay was `NOT_RUN`
- claim evaluation when claim was `NOT_EVALUATED`

Possible break:

- A summary turns `PASS - proceed to normal review` into a merge or release claim.
- The packet implies Assay observed hidden agent intent.
- The docs treat a successful check observation as evidence that all relevant tests ran.

## 30-Second Reviewer Path

1. Read `README.md`.
2. Read `DOGFOOD.md`.
3. Inspect PR #152 and PR #153.
4. Read both PR Gate verdict comments.
5. If the PR #152 artifact is still live, download `assay-pr-gate-report` and rerun the verifier.
6. Ask: "What am I actually allowed to believe?"

The intended answer is narrow: the captured PR evidence satisfied the named gate checks, the signed packet verified, and tampered proof-pack material failed closed.

## Usefulness Test

Keep this note only if it helps a skeptical engineer understand the wedge faster.

Delete it if it reads like marketing, adds a third source of policy authority, or makes the evidence ladder feel bigger than it is.
