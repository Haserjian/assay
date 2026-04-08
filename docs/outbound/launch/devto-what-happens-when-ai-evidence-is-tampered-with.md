# What Happens When AI Evidence Is Tampered With?

AI systems produce logs. Most of the time, those logs live on the operator's server.

That works until trust has to cross a boundary.

The moment another engineering team, a reviewer, a buyer, or an auditor has to rely on the evidence, ordinary logs stop being enough. They can read the story the system is telling. They cannot independently tell whether the artifact they received is still the same artifact the system originally produced.

## Logs Break At Handoff

Inside one team, "we have the logs" can sound sufficient.

At handoff, it is not.

A reviewer does not want a screenshot of your dashboard. A procurement team does not want to depend on your internal admin panel. A security team does not want the truth of an AI run to disappear the moment they lose access to your infrastructure.

That is the break point.

If the evidence only makes sense while it is sitting behind your server, your server is part of the trust assumption.

## What The Proof Pack Is

Assay compiles AI activity into signed proof packs, a signed folder another team can verify offline.

That is the important object.

A proof pack is not a screenshot and not a dashboard export. It is the evidence artifact itself: receipts, hashes, a manifest, and verifier-readable output. You can move it across teams, attach it to a review, gate on it in CI, or check it in the browser without asking the original operator for backend access.

Logs explain. Proof transfers.

## The Semantic Tamper

Start with a valid proof pack. Verification passes.

Then change one meaningful field after the run.

In the canonical example, the model string changes from `gpt-4` to `gpt-5` inside the receipt stream. No rerun. No new signature. No fresh evidence. Just a post-run edit to what the artifact claims happened.

Verify again.

The result flips from pass to tampered.

That is the public wedge because the meaning is obvious. It is not an abstract claim about bytes. It is a human-readable change to the stated model after the run.

The cryptographic punchline is still the same: one byte changed, verification fails. But leading with the semantic tamper makes the trust problem visible faster.

## The Trust Boundary

The boundary matters more than the demo.

Assay proves integrity after compilation for the artifact it produced; it does not, by itself, prove initial honesty, signer identity, or an uncompromised runtime.

That means a few things.

If someone edits the artifact after the run, Assay makes that visible.

If the runtime lies before signing, Assay can preserve that lie faithfully. It is not host attestation.

If a different signer creates a mathematically valid artifact, the current public trust tier does not by itself establish that the signer was authorized to speak for your system.

That narrower claim is still useful. It turns post-run tampering from an argument into a deterministic failure, and it gives another team a bounded object they can evaluate without trusting your server.

## Handoff, CI, Review, Procurement

This gets practical quickly.

At handoff, another team can verify the same artifact offline.

In CI, a build can fail because the evidence has been tampered with, or because the claims checked against that evidence do not pass.

In review and procurement, the operator can hand over a bounded artifact instead of saying "trust our internal logs."

As AI Act obligations come into force, especially for high-risk systems, the pressure will not be for more screenshots. It will be for evidence another party can inspect, forward, and verify.

Compliance matters here, but it is not the identity. The technical truth comes first: portable evidence with an explicit trust boundary.

## Signed Failure Is The Point

A system that only knows how to say "pass" is not especially trustworthy.

A better system can preserve failure honestly.

If the artifact is authentic but the declared standard is not met, that failure should remain visible. It should not be quietly upgraded. It should not disappear in a dashboard state change. It should remain attached to the same evidence.

A signed failure is better than an unverifiable success claim.

That is the doctrine underneath the demo.

## Try It Yourself

```bash
pipx install assay-ai
assay demo-challenge
assay verify-pack challenge_pack/good/
/bin/cp -R challenge_pack/good challenge_pack/edited
perl -0pi -e 's/gpt-4/gpt-5/' challenge_pack/edited/receipt_pack.jsonl
assay verify-pack challenge_pack/edited/
```

If you want the browser path after that, drop the same artifact into the verifier here:

https://haserjian.github.io/assay-proof-gallery/verify.html
