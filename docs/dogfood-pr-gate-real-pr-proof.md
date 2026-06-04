# PR Gate Real PR Proof

This file is a minimal same-repository pull request target for the Assay PR Gate
dogfood workflow.

It is intentionally doc-only and outside the dogfood policy risk paths. The
pull request is meant to prove that the live workflow can produce, sign, verify,
upload, and comment on a PR Gate packet without treating the PR contents as
trusted executable code.

This local commit does not prove CI signing. That claim requires the live PR
run, downloaded artifact verification, and tamper checks.
