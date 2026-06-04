# Agent Operating Policy v0

Assay checks observed PR evidence against an explicit agent operating policy and emits a signed, reviewable verdict about whether the captured evidence satisfies that policy.

This packet is a public-surface draft. It shows the intended shape of an Agent Operating Policy without adding a new engine, CLI command, or workflow.

## Stack

```text
AGENTS.md                  = human-readable operating guide
assay.agent_policy.json    = machine-checkable policy
Assay PR Gate              = evaluator + signer + proof pack
Proof Card / PR comment    = public review surface
```

`AGENTS.md` tells coding agents and reviewers what the repository expects. `assay.agent_policy.json` projects the enforceable parts into a small policy file. Assay PR Gate evaluates captured PR evidence against that policy, packages the evidence into a proof pack, signs the review verdict, and displays the result in a review surface.

The review question is narrow:

```text
Did the captured PR evidence satisfy the declared agent operating policy?
```

## What AGENTS.md Alone Does Not Provide

AGENTS.md gives coding agents instructions. It does not prove which files changed, which checks ran, which claims were made, whether evidence supported those claims, or whether a review verdict was signed. Assay adds the review layer over captured PR evidence.

## Evidence Boundary

Agent Operating Policy v0 is about observed PR evidence:

- diff paths and hashes
- check names and conclusions
- required receipts and proof-pack material
- stated PR claims and claim-support results
- policy hashes and signed verdict status

It does not evaluate hidden agent intent, unobserved runtime activity, production approval, or the underlying correctness of code beyond the captured evidence.

## Files

- `AGENTS.md` is the human-readable policy.
- `assay.agent_policy.json` is the minimal machine-checkable projection.
- `assay.agent_policy.schema.json` describes the draft policy shape.
- `examples/` contains illustrative verdict fixtures for one pass and three rejection modes.
- `VERIFY_OUTPUT.txt` shows example draft verifier output.

## Related Assay Surfaces

This draft follows the PR Gate boundary described in `docs/product/assay-pr-gate-dogfood-v0.md` and the bounded-evaluation and caveat discipline of `docs/product/assay-pr-gate-policy-v0.md`: captured evidence, bounded policy evaluation, signed review material, caveats, and human review.

## Example Verdicts

The fixtures use two top-level verdicts:

- `POLICY_SATISFIED` means the captured evidence satisfied the declared policy.
- `REJECTED` means the captured evidence failed at least one declared policy rule.

These are a draft-local vocabulary for the agent-policy layer. They map onto the PR Gate recommendation vocabulary — `POLICY_SATISFIED` aligns with PR Gate `PASS` (`proceed`), `REJECTED` aligns with PR Gate `BLOCK` — and are not a second source of truth for the PR Gate recommendation.

These verdicts are not merge decisions. They are review evidence for a human reviewer or a higher-level gate.
