# Show HN Prep

Human-source note only. Do not paste generated wording verbatim on HN. Rewrite in your own voice before posting.

## Title

Show HN: offline-verifiable evidence for AI runs

## 5 Talking Points

- Why you built it: most AI systems can show logs but cannot hand another team evidence they can verify.
- What it is: Assay compiles AI activity into signed proof packs, a signed folder another team can verify offline.
- The demo: verify a good pack, change `gpt-4` to `gpt-5` after the run, verify again, and watch it fail.
- The boundary: Assay proves integrity after compilation for the artifact it produced; it does not, by itself, prove initial honesty, signer identity, or an uncompromised runtime.
- The ask: if the boundary is wrong or the demo is misleading, invite critique.

## 5 Objection Bullets

- This is just signed logs. Answer: it is a portable proof pack with a manifest, signature, and offline verifier, not just log storage.
- This doesn't prove honesty. Answer: correct; the current claim is integrity after compilation, not initial honesty.
- Why not Sigstore. Answer: Sigstore signs software artifacts and build provenance; Assay targets runtime AI evidence.
- What's the trust root. Answer: today it is the signed proof pack at T0, with stronger roots available through CI-held keys and external anchors.
- What about compromised runtime. Answer: if the runtime lies before signing, Assay can preserve that lie faithfully; it is not host attestation.
