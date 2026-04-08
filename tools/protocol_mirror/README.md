# Protocol Mirror

This directory holds the manifest for files in `assay` that mirror normative
content from [`Haserjian/assay-protocol`](https://github.com/Haserjian/assay-protocol).

## Which side is canonical

**`Haserjian/assay-protocol` is canonical.** It is the normative source of
truth for the RCE (Replay-Constrained Episode) profile and its schemas.

This repo (`assay`) keeps an implementation-local copy of selected protocol
files because the verifier and runtime need to load them at import time
without a cross-repo network call. The mirror is a convenience artifact, not
an authority.

## Why the mirror exists

- Assay's verifier (`src/assay/rce_verify.py`) loads
  `rce_episode_contract.schema.json` at module-load time. Bundling the
  schema in this repo avoids a network dependency on
  `Haserjian/assay-protocol`.
- Test fixtures and conformance vectors reference the schema by relative
  path.
- The mirror lets `pip install assay-ai` ship a self-contained verifier.

The trade-off is that the mirror can silently drift from canonical. The
drift guard in this directory + `scripts/check_protocol_mirror_drift.py` +
`.github/workflows/protocol-mirror-drift.yml` makes that drift detectable in
CI.

## What's in scope (current slice)

Only the schema mirror is currently guarded:

| Mirror path | Canonical | Transform |
|---|---|---|
| `src/assay/schemas/rce_episode_contract.schema.json` | `Haserjian/assay-protocol:schemas/rce_episode_contract.schema.json` | `rewrite_schema_id` |

The `rewrite_schema_id` transform is the **only** legitimate divergence
between canonical and mirror. It rewrites the JSON Schema `$id` field from
the protocol repo's URL space to this repo's URL space, so each repo
legitimately serves the schema under its own canonical URL. Every other
byte must match exactly.

`RCE_PROFILE.md` is **not** mirrored in this slice. That can be added later
by appending an entry to `manifest.json` with `transform: identity` (no
URL rewrite needed for prose documents).

## How drift gets detected

`.github/workflows/protocol-mirror-drift.yml` runs
`scripts/check_protocol_mirror_drift.py` on every PR that touches:

- `src/assay/schemas/rce_episode_contract.schema.json`
- `tools/protocol_mirror/**`
- `scripts/check_protocol_mirror_drift.py`
- The workflow file itself

The script:

1. Reads the manifest (`manifest.json` here).
2. For each mirror entry, fetches the canonical file from `Haserjian/assay-protocol`
   at the pinned commit SHA via `gh api` (no special token — `assay-protocol`
   is public).
3. Applies the declared transform.
4. Byte-compares the result against the checked-in mirror file.
5. Exits non-zero on any drift, with a human-readable diff hint.

The pin must be a full 40-character commit SHA. Tags and moving refs like
`main` are forbidden because they break the determinism premise.

## How to refresh the mirror intentionally

When the canonical updates and you want to bring the mirror current:

1. Identify the new canonical commit SHA in `Haserjian/assay-protocol`.
2. Bump `canonical_ref` in `tools/protocol_mirror/manifest.json` to that SHA.
3. Run the script in refresh mode:

   ```bash
   python scripts/check_protocol_mirror_drift.py --mode=refresh tools/protocol_mirror/manifest.json
   ```

4. Verify the result with `git diff` — confirm the changes are what you
   expected (e.g. new schema fields, updated descriptions, no surprise
   structural changes).
5. Run the existing RCE-related tests to make sure runtime still loads
   cleanly:

   ```bash
   pytest tests/assay/test_rce_verify.py -q
   ```

6. Commit the manifest bump and the updated mirror file **in one PR**.
   Do not split them across multiple commits — they're the atomic record
   of an intentional sync.

The CI drift guard re-runs on the PR and confirms the new mirror is still
byte-equal to the new canonical at the new pin.

## How to run the check locally

```bash
python scripts/check_protocol_mirror_drift.py tools/protocol_mirror/manifest.json
```

Exit 0 = no drift. Exit 1 = drift detected (with diff hint). Requires `gh`
on PATH and authenticated for public read.

## What this guard does not cover

- **Pin freshness.** The guard does not enforce that the pin is current with
  `assay-protocol/main`. A stale-but-honest pin is fine; updating it is a
  deliberate human action via the refresh ritual.
- **Semantic correctness of the canonical.** Whether the canonical schema
  itself encodes the right contract is the protocol repo's responsibility.
- **Other normative files.** Only files listed in `manifest.json` are
  guarded. Adding more is a one-line manifest change.
