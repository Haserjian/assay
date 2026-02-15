# Assay Repo Map

Canonical reference for what lives where, what's public, and what ships from each repo.

## Public Repos

| Repo | Purpose | Ships | Release Owner |
|------|---------|-------|---------------|
| [Haserjian/assay](https://github.com/Haserjian/assay) | Core CLI, SDK, schemas, conformance corpus, docs | `assay-ai` on PyPI | Tim Bhaserjian |
| [Haserjian/assay-verify-action](https://github.com/Haserjian/assay-verify-action) | GitHub Action for CI verification gating | `Haserjian/assay-verify-action@v1` | Tim Bhaserjian |
| [Haserjian/assay-ledger](https://github.com/Haserjian/assay-ledger) | Public transparency ledger (GitHub Pages) | Append-only ledger entries via PR | Tim Bhaserjian |

## Private Repos

| Repo | Purpose | Notes |
|------|---------|-------|
| (private monorepo) | Internal: agents, receipts, governance, experiments | Assay originated here; public surface extracted to Haserjian/assay |
| assay-cloud (future) | Hosted verification, team/org management, billing | Not yet created |

## What Ships From Where

### Haserjian/assay (this repo)

Everything a user needs to install, scan, instrument, run, verify, and gate:

- `src/assay/` -- Python package (`pip install assay-ai`)
- `tests/assay/` -- Full test suite
- `conformance/` -- Verifier ABI corpus (6 packs, expected outcomes)
- `docs/` -- Quickstart, decision escrow, compliance guide, specs, pilot program
- `examples/` -- Quickstart script, demo pack generator

### Haserjian/assay-verify-action

Composite GitHub Action. References `assay-ai` from PyPI. Users add this to their workflow:

```yaml
- uses: Haserjian/assay-verify-action@v1
  with:
    pack-path: ./proof_pack_*/
```

### Haserjian/assay-ledger

Public append-only ledger. Accepts submissions via PR workflow. Entries include:
- `pack_root_sha256` (the immutable pack identifier)
- `witness_level` (unwitnessed, hash_verified, signature_verified)
- Signer fingerprint and timestamp

## Open vs Closed Product Boundary

### Open (builds trust and adoption)

| Surface | Why open |
|---------|----------|
| Receipt schema | Users must understand what they're emitting |
| Verifier + lockfile semantics | Verification must be auditable |
| scan, doctor, run, verify-pack | Core workflow must be free to try |
| Conformance corpus + expected outcomes | Verifier behavior must be deterministic and testable |
| GitHub Action integration | CI adoption requires public action |

### Closed (monetization and operations)

| Surface | Why closed |
|---------|-----------|
| Hosted witness infrastructure | Anti-abuse, uptime, operational cost |
| Enterprise policy packs and regulator mappings | Customer-specific, high-value consulting |
| Private ledger / org dashboards / retention | SaaS tier differentiator |
| Customer data and operational telemetry | Privacy and compliance |
| Support playbooks and onboarding automation | Service delivery IP |

### Boundary Rule

If it affects trust in the verification chain, it must be open.
If it affects operations, delivery, or customer-specific configuration, it can be closed.
