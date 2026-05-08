# ADR: PR Gate Trust Root

## Status

Proposed.

## Context

Verification Gate v0 used a historical proof sample whose Sigstore identity
was tied to a pull request merge ref. That is acceptable for a frozen sample,
but PR Gate needs a stable expected signer identity that reviewers can
understand and verifiers can enforce.

GitHub Actions exposes workflow, run, ref, SHA, actor, and related context
fields. GitHub artifact attestations and Sigstore-based signing already provide
strong provenance plumbing. PR Gate should use that plumbing while adding
Assay's review semantics: verdict channels, caveats, policy result, and
recommended action.

## Decision

The intended dogfood signer identity is:

```text
Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main
```

The public Verification Report must be signed by the expected workflow
identity for the run being trusted.

The PR Gate verifier must fail if:

- the Verification Report is tampered with
- the evidence pack does not match the report's pack root
- the expected signer identity does not match
- the policy hash is missing or mismatched, unless the packet explicitly
  downgrades to `manual_triage`

## Buyer-Facing Language

Use:

```text
Signed by expected GitHub workflow.
```

Do not lead with:

```text
OIDC
Fulcio
Rekor
keyless signing
```

Those are technical appendix concepts. The reviewer-facing contract is the
expected workflow identity and the local verification result.

## Consequences

- PR Gate needs a stable workflow on `main`.
- Historical sample identities remain valid for their frozen artifacts but are
  not reproducible build targets.
- Consumer repositories need a way to configure expected signer identities.
- Private repository support may require hosted or enterprise-specific storage
  and signing policy decisions later.

## References

- GitHub Actions contexts:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/contexts>
- GitHub artifact attestations:
  <https://docs.github.com/actions/concepts/security/artifact-attestations>
- Sigstore signing overview:
  <https://docs.sigstore.dev/cosign/signing/overview/>
