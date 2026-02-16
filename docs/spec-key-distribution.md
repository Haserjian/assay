# Key Distribution and Signer Identity

How a verifier maps *this signature* to *this organization*, with a
rotation and revocation story at each trust tier.

## Problem

Evidence packs are signed with Ed25519. The manifest embeds the signer's
public key and its SHA-256 fingerprint. Verification proves: "these bytes
were signed by the holder of this key." It does NOT prove: "this key
belongs to Acme Corp" or "this key has not been compromised."

The gap between "valid signature" and "trusted signer" is the key
distribution problem. This document defines how to close that gap at
each trust tier.

## Manifest Signer Fields (Current)

Every pack manifest already contains:

| Field | Type | Purpose |
|-------|------|---------|
| `signer_id` | string | Identifier for the signer (e.g., "assay-local", "ci-prod") |
| `signer_pubkey` | string | Base64-encoded Ed25519 public key (32 bytes) |
| `signer_pubkey_sha256` | string | SHA-256 fingerprint of raw public key bytes (64 hex chars) |
| `signature_alg` | string | Algorithm identifier ("ed25519") |
| `signature_scope` | string | What was signed ("JCS(pack_manifest_without_signature)") |
| `signature` | string | Base64-encoded Ed25519 signature |

These fields enable self-contained verification: a verifier with only the
pack directory can check that the signature is valid against the embedded
key. What they cannot do is tell the verifier *who* the key belongs to.

## Manifest `signer_identity` Convention (New)

To close the attribution gap, pack manifests SHOULD include a
`signer_identity` block with key provenance metadata:

```json
{
  "signer_identity": {
    "org": "acme-corp",
    "environment": "ci-prod",
    "key_provenance": "github-actions",
    "trust_tier": "T1",
    "pubkey_committed_at": "https://github.com/acme-corp/app/blob/main/.assay/keys/ci-prod.pub",
    "rotation_policy": "90d"
  }
}
```

| Field | Required | Purpose |
|-------|----------|---------|
| `org` | RECOMMENDED | Organization name (matches repo owner or domain) |
| `environment` | RECOMMENDED | Where the key lives ("local", "ci-prod", "ci-staging") |
| `key_provenance` | RECOMMENDED | How the key was provisioned ("manual", "github-actions", "sigstore") |
| `trust_tier` | RECOMMENDED | Self-declared trust tier ("T0", "T1", "T2") |
| `pubkey_committed_at` | T1+ only | URL where the public key is committed (branch-protected repo) |
| `rotation_policy` | OPTIONAL | Intended rotation cadence ("90d", "365d", "manual") |

This block is informational in T0 and machine-verifiable in T1+.

**Important:** `signer_identity` is inside the signed manifest, so it
cannot be edited after signing without invalidating the signature. But
it is *self-declared* -- the signer chooses what to write. External
verification (T1 repo check, T2 Sigstore lookup) is what makes it
trustworthy.

## Trust Tier Key Distribution

### T0: Self-Signed (shipped, v1.0+)

**Architecture:** Single machine, single key. Key generated locally via
`assay key list` / key auto-generated on first `assay run`.

**Verifier key acquisition:**

1. Receive the evidence pack from the signer
2. The public key is embedded in `pack_manifest.json` (`signer_pubkey`)
3. Run `assay verify-pack ./proof_pack_*/`
4. Verification confirms: "signature is valid against this embedded key"

**What T0 proves:**
- Internal consistency (bytes were not tampered with after signing)
- The signer had access to this specific private key

**What T0 does NOT prove:**
- Who the signer is
- That the key has not been compromised
- That the signer is associated with any particular organization

**Key exchange:** Out-of-band. Share the public key fingerprint
(`signer_pubkey_sha256`) via a secure channel (email, Slack, in-person).
The verifier compares the fingerprint in the pack to the one they
received out-of-band.

```bash
# Signer: share your fingerprint
assay key list --json | jq '.signers[0].fingerprint'

# Verifier: compare fingerprint from pack manifest
jq '.signer_pubkey_sha256' proof_pack_*/pack_manifest.json
```

**Lockfile integration:** `assay.lock` can specify
`signer_policy.mode = "allowlist"` with `allowed_fingerprints` to
enforce which keys are accepted during `verify-pack --lock`.

---

### T1: Repo-Committed Key (convention, no new code)

**Architecture:** Public key committed to a branch-protected repository.
Key provenance is traceable to a git commit with known authorship.

**Setup:**

```bash
# 1. Generate a CI-specific key
assay key rotate --new-signer ci-prod --set-active

# 2. Commit the PUBLIC key to the repo (never the private key)
cp ~/.assay/keys/ci-prod.pub .assay/keys/ci-prod.pub
git add .assay/keys/ci-prod.pub
git commit -m "Add ci-prod signing public key"
git push

# 3. Store the PRIVATE key as a CI secret
# GitHub: Settings > Secrets > ASSAY_SIGNING_KEY
# Value: base64 of ~/.assay/keys/ci-prod.key
```

**Verifier key acquisition:**

1. Receive the evidence pack
2. Extract `signer_pubkey_sha256` from the manifest
3. Look up the public key in the repo: `.assay/keys/{signer_id}.pub`
4. Compute `SHA256(pubkey_file_bytes)` and compare to manifest fingerprint
5. If they match: the signer used a key committed to this repo

```bash
# Verifier: compare manifest fingerprint to repo-committed key
MANIFEST_FP=$(jq -r '.signer_pubkey_sha256' proof_pack_*/pack_manifest.json)
REPO_FP=$(sha256sum .assay/keys/ci-prod.pub | cut -d' ' -f1)
[ "$MANIFEST_FP" = "$REPO_FP" ] && echo "Key matches repo" || echo "MISMATCH"
```

**What T1 adds over T0:**
- Key is traceable to a git commit (who committed it, when, which branch)
- Branch protection rules prevent unauthorized key replacement
- Key provenance is auditable via `git log .assay/keys/`

**Recommended branch protection rules:**
- Require pull request reviews for changes to `.assay/keys/`
- Require status checks to pass before merging
- Do not allow force pushes to main/default branch

---

### T2: Independent Witness (assay-ledger shipped, Sigstore planned)

**Architecture:** Key identity is bound to an organization or workflow
via a transparency log or certificate chain. A third party can verify
the binding without trusting the signer.

#### T2a: assay-ledger (shipped)

The [assay-ledger](https://github.com/Haserjian/assay-ledger) provides
an append-only public transparency log. Packs anchored to the ledger
gain an independent timestamp and witness signature.

**Verifier key acquisition:**
1. The pack manifest includes a ledger anchor reference
2. The verifier checks the ledger for the corresponding entry
3. The ledger entry independently confirms the pack's existence at a
   specific time, signed by the ledger's own key

**What T2a adds over T1:**
- Independent timestamp (not just the signer's local clock)
- Append-only constraint (cannot retroactively insert or delete entries)

#### T2b: Sigstore/Rekor (planned)

Sigstore binds short-lived signing certificates to OIDC identities
(GitHub Actions, Google accounts, etc.). The certificate is logged in
Rekor (a public transparency log).

**Future verifier key acquisition:**
1. Pack manifest includes a Rekor entry ID
2. The verifier looks up the Rekor entry
3. The entry proves: "this signature was made by a GitHub Actions
   workflow in repo X at time T, using a short-lived certificate"
4. No long-lived keys to manage or rotate

**What T2b would add over T2a:**
- Key bound to organizational identity (OIDC), not just a key pair
- No long-lived private key to protect (ephemeral certificates)
- Public, globally replicated transparency log

---

### T3: Runtime Attestation (future)

Hardware-backed attestation (TPM, SGX, Nitro Enclaves) proves that the
signing happened inside a specific hardware environment. Not yet planned
for Assay.

---

## Key Lifecycle

### Rotation

**When to rotate:**
- On a schedule (recommended: every 90 days for CI keys)
- When a team member with key access leaves
- When a key may have been exposed
- When upgrading trust tier (e.g., T0 to T1)

**How to rotate:**

```bash
# Generate new key, set as active, update lockfile
assay key rotate --lock assay.lock

# Or with explicit names
assay key rotate --signer ci-prod --new-signer ci-prod-20260215 --lock assay.lock
```

**What happens during rotation:**
1. New Ed25519 key pair generated
2. New key set as active signer (by default)
3. Both old and new fingerprints added to lockfile allowlist
4. Old key remains valid for verifying old packs
5. New packs use the new key

**Key principle:** Old keys are never deleted. They remain valid for
verifying packs that were signed with them. Rotation is additive.

### Revocation

Revocation is harder than rotation because it must be communicated
retroactively: "do not trust packs signed with key X after date Y
unless re-signed with a new key."

**Current mechanism (lockfile-based):**

```bash
# Remove a compromised key from the lockfile allowlist
# Edit assay.lock manually: remove the fingerprint from allowed_fingerprints
# Then verify-pack --lock will reject packs signed with the revoked key
```

**Limitations of lockfile revocation:**
- Only affects `verify-pack --lock` (not standalone verify-pack)
- No broadcast mechanism (each verifier must update their own lockfile)
- No time-scoping ("revoked after date X")

**Future mechanism (revocation list):**
- `assay key revoke --signer ci-prod --reason "key compromised" --after 2026-02-15`
- Publishes a signed revocation entry to assay-ledger
- Verifiers checking the ledger automatically reject post-revocation packs

**Recommended practice until revocation lists ship:**
1. Remove compromised fingerprint from lockfile
2. Rotate to a new key immediately
3. Re-sign any packs created during the exposure window:
   `assay proof-pack --resign --signer new-key`
4. Communicate the revocation out-of-band to known verifiers

---

## Verifier Decision Matrix

| Scenario | T0 | T1 | T2 |
|----------|----|----|-----|
| Signature valid? | Check embedded pubkey | Check embedded pubkey | Check embedded pubkey |
| Key trusted? | Out-of-band fingerprint comparison | Compare to repo-committed key | Transparency log lookup |
| Key rotated? | Accept if fingerprint in lockfile allowlist | Same + check git log for rotation commit | Same + check log entry dates |
| Key revoked? | Lockfile allowlist removal (manual) | Same + branch protection audit | Revocation entry in transparency log |
| Who signed? | "Holder of this key" (unknown identity) | "Key committed by [git author] on [date]" | "GitHub Actions in repo X at time T" |

---

## Quick Reference: Verifier Checklist

For a verifier receiving an evidence pack:

```bash
# 1. Verify integrity (any tier)
assay verify-pack ./proof_pack_*/

# 2. Check signer fingerprint (T0: compare out-of-band)
jq '.signer_pubkey_sha256' proof_pack_*/pack_manifest.json

# 3. Check against lockfile (T1+: CI-enforced)
assay verify-pack ./proof_pack_*/ --lock assay.lock

# 4. Check key provenance (T1: repo-committed)
jq '.signer_identity' proof_pack_*/pack_manifest.json

# 5. Explain what the pack proves
assay explain ./proof_pack_*/
```

---

## Summary

| What | How | Status |
|------|-----|--------|
| Self-contained signature verification | Embedded pubkey in manifest | Shipped (v1.0+) |
| Fingerprint-based key trust (T0) | Out-of-band exchange | Shipped (v1.0+) |
| Lockfile signer allowlist | `signer_policy` in assay.lock | Shipped (v1.5+) |
| Key rotation | `assay key rotate --lock` | Shipped (v1.5+) |
| `signer_identity` convention | New manifest block | Convention (this doc) |
| Repo-committed keys (T1) | `.assay/keys/*.pub` in repo | Convention (this doc) |
| Ledger-anchored keys (T2a) | assay-ledger witness | Shipped (ledger live) |
| Sigstore-bound keys (T2b) | Rekor + OIDC certificates | Planned |
| Key revocation | Lockfile removal (now), ledger revocation (future) | Partial |
