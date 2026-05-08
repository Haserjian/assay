# assay-ai 1.24.0 verify report contract note

`assay-ai` 1.24.0 is the release line for the public
`assay.verify_report.v0.1` contract.

The buyer-facing artifact set is:

- `pack_manifest.json`
- `verify_report.json`
- `verify_report.sigstore.json`

The verify report keeps verdict channels separate:

- `integrity_verdict`
- `claim_verdict`
- `replay_verdict`
- `trust_verdict`
- `overall_verdict`

It also records the evaluation profile and channel requirements so
`overall_verdict: PASS` can distinguish required checks that passed from
optional channels that were not evaluated.
