# ADR: PR Gate Two-Lane GitHub Security

## Status

Proposed.

## Context

PR Gate needs to inspect pull request facts and post a review decision. Public
and fork-friendly repositories introduce a security boundary: untrusted pull
request code must not run in a privileged workflow that can write comments,
access secrets, or request signing identity.

GitHub secure-use guidance warns that `pull_request_target` and `workflow_run`
can expose repositories when combined with checkout of untrusted pull request
code. GitHub Security Lab's pwn-request guidance recommends separating
untrusted PR processing from privileged publication paths.

## Decision

PR Gate will support two modes.

### Dogfood Mode

Use a single same-repo workflow while developing on controlled branches:

```text
pull_request workflow
read PR metadata
evaluate policy
emit packet
sign report
post comment
```

This is acceptable only for controlled dogfood where the trust boundary is
explicit.

### Production Mode

Use a two-lane model.

Lane A, untrusted collector:

- trigger: `pull_request`
- permissions: read-only
- no secrets
- no privileged token
- no signing identity
- collect PR metadata and observed check evidence
- upload unsigned or minimally signed capture artifact

Lane B, trusted signer and publisher:

- trigger: trusted event such as `workflow_run` or an equivalent controlled
  same-repo event
- permissions: write PR comments and request OIDC signing identity
- never checks out untrusted PR code
- validates capture artifact shape
- evaluates policy
- emits and signs the public Verification Report
- uploads packet artifacts
- posts or updates the PR comment

## Consequences

- Dogfood can move quickly.
- Production mode adds complexity but preserves the security boundary.
- The signer/publisher must treat collector artifacts as untrusted input until
  validated.
- PR title, branch names, file paths, and other GitHub context values must not
  be interpolated directly into shell commands.

## Non-Goals

- This ADR does not define a full sandbox for running untrusted PR code.
- This ADR does not define hosted storage.
- This ADR does not define enterprise deployment.

## References

- GitHub secure-use guidance:
  <https://docs.github.com/en/enterprise-server@3.16/actions/reference/security/secure-use>
- GitHub Security Lab pwn-request guidance:
  <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>
