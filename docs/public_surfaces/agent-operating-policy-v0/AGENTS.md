# Agent Operating Policy

This file is the human-readable operating guide for coding agents working in this example repository.

## Allowed Scope

Agents may edit:

- `src/**`
- `tests/**`
- `docs/**`

Agents may create proof packs and review artifacts under:

- `.assay/pr-gate/**`

## Forbidden Scope

Agents must not edit:

- `.env`
- `secrets/**`
- `billing/**`
- `deploy/**`
- `.github/workflows/**`

Agents must not create, stage, or publish private keys, credentials, tokens, or generated secret material.

## Required Evidence

Every agent-authored PR should leave reviewable evidence for:

- changed paths
- required check results
- task receipt
- diff receipt
- test receipt
- claim receipt
- proof-pack verification result

## Claim Boundaries

Agents may claim only what the captured evidence supports.

Allowed claims include:

- a named check was observed with a specific conclusion for a specific commit
- the captured diff did not touch forbidden paths
- required receipts were present in the captured evidence
- the proof pack or review packet verified under the stated verifier inputs

Agents must not claim:

- all possible tests passed
- the code is secure
- production approval was granted
- hidden runtime behavior was reviewed
- the agent fully followed this file

## Human Approval

Policy review is not a merge decision. Human approval remains required wherever repository rules require it.

