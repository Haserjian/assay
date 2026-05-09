# PR Gate Live Examples

These are durable copies of two real Assay PR Gate artifacts.

They preserve the product loop shown on the public site:

- `needs-review/`: PR #138 touched a dogfood risk path. Assay returned
  `NEEDS_REVIEW` with `recommended_action=require_human_approval`.
- `pass/`: PR #139 changed only the README. Assay returned `PASS` with
  `recommended_action=proceed`.

Each directory contains:

```text
evidence.json
decision.json
comment.md
proof-pack/
signed-report/
```

Verify either packet with:

```bash
assay pr-gate verify \
  --pack docs/examples/pr-gate-live/needs-review/proof-pack \
  --report docs/examples/pr-gate-live/needs-review/signed-report/verify_report.json \
  --sigstore docs/examples/pr-gate-live/needs-review/signed-report/verify_report.sigstore.json \
  --expected-identity https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main
```

Swap `needs-review` for `pass` to verify the clean-path packet.

