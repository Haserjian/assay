1. Most AI systems can show logs.
Fewer can hand another team evidence they can verify offline.

That's the wedge for Assay.

2. Assay compiles AI activity into signed proof packs, a signed folder another team can verify offline.

Not a dashboard export.
Not "trust our server."
A portable artifact.

3. The shortest demo is:
verify a good pack,
change `gpt-4` to `gpt-5` after the run,
verify again.

4. The result flips from pass to tampered.

No server call.
No account.
Just math.

Logs explain. Proof transfers.

5. The trust boundary is explicit:
Assay proves integrity after compilation for the artifact it produced.
It does not, by itself, prove initial honesty, signer identity, or an uncompromised runtime.

6. That narrower claim is still enough to matter at handoff, in CI, in review, and in procurement.

Try it:
`pipx install assay-ai`
`assay demo-challenge`

github.com/Haserjian/assay
