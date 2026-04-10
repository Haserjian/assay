# Assay Packet Systems

Assay contains two packet surfaces. They are not interchangeable.

**Compiled packets** are the canonical, general-purpose, third-party-verifiable trust
artifact. **Reviewer packets** are a specialized VendorQ-oriented packaging format.
When the two overlap in scope, the compiled packet is the authoritative trust object.
Proof packs remain the signed execution kernel beneath both packet surfaces; they
should not be confused with the whole upstream runtime ontology.

---

## Compiled Packet (canonical)

A compiled packet is a signed, self-contained bundle that lets a third party verify
what an AI system did, what claims are being made about it, and whether the packet is
admissible under a declared policy for a trust decision — offline.

Evidence that only the producer can interpret is a log. Evidence that a third party
can verify offline and use for a trust decision is a product.

**Command**: `assay packet init` → `assay packet compile` → `assay packet verify`

**Gate**: `scripts/assay-gate.sh <packet_dir>`

**Artifact layout**:

```
compiled_packet/
  packet_manifest.json    # signed manifest: subject, pack references, admissibility contract
  claim_bindings.jsonl    # authored claim-to-evidence links
  packet_signature.sig    # Ed25519 signature over the manifest
  packs/                  # bundled proof packs (inline for offline verification)
```

**Verdict model** (two independent axes):

| Integrity | Completeness | Top-level verdict |
|-----------|-------------|-------------------|
| `INTACT` | `COMPLETE` | `PASS` |
| `INTACT` | `PARTIAL` | `PARTIAL` |
| `INTACT` | `INCOMPLETE` | `PARTIAL` |
| `DEGRADED` | any | `DEGRADED` |
| `TAMPERED` | any | `TAMPERED` |
| `INVALID` | any | `INVALID` |

**Admissibility**: separate policy judgment — requires INTACT integrity, valid subject
binding, and bundled packs. Available in `--json` output.

**When to use**: any context where a third party needs to verify the packet offline, or
where a CI gate needs a machine-readable admissibility decision.

**Docs**:
- [`docs/specs/COMPILED_PACKET_ARCHITECTURE.md`](specs/COMPILED_PACKET_ARCHITECTURE.md) — architecture and design
- [`docs/specs/COMPILED_PACKET_SPEC_V1.md`](specs/COMPILED_PACKET_SPEC_V1.md) — full artifact spec
- [`docs/specs/PACKET_SEMANTICS_V1.md`](specs/PACKET_SEMANTICS_V1.md) — normative semantics and error codes
- [`docs/specs/COMPILED_PACKET_VERIFY_CONTRACT.md`](specs/COMPILED_PACKET_VERIFY_CONTRACT.md) — `--json` output contract
- [`docs/specs/PROOF_PACK_SCOPE_AND_RECEIPT_MAPPING_V1.md`](specs/PROOF_PACK_SCOPE_AND_RECEIPT_MAPPING_V1.md) — proof-pack kernel boundary vs richer receipt ecosystems

---

## Reviewer Packet (VendorQ-specific)

A reviewer packet is a specialized packaging format for VendorQ compliance
questionnaire workflows. It wraps a proof pack in a structured review artifact
with settlement logic, coverage matrix, and scope manifest.

**Command**: `assay vendorq export-reviewer`
**Next step**: `assay reviewer census`

**Artifact layout**:

```
reviewer_packet/
  PACKET_MANIFEST.json    # caps — different schema from compiled packet
  SETTLEMENT.json
  COVERAGE_MATRIX.md
  SCOPE_MANIFEST.json
  PACKET_INPUTS.json
  proof_pack/             # nested proof pack (trust root)
  decision_receipts/      # optional
```

**Verdict model**: `VERIFIED`, `VERIFIED_WITH_GAPS`, `INCOMPLETE_EVIDENCE`,
`EVIDENCE_REGRESSION`, `TAMPERED`, `OUT_OF_SCOPE`

**When to use**: VendorQ questionnaire review, checkpoint export, CLI reviewer
verification, and Decision Census generation. Browser verification covers the
nested proof pack only today, not the reviewer packet wrapper.

**Docs**: [`docs/reviewer-packets.md`](reviewer-packets.md)

---

## Which to Use

| Need | Use |
|------|-----|
| Portable, offline-verifiable trust artifact for any subject | Compiled packet |
| Fail-closed CI gate on evidence admissibility | Compiled packet + `assay-gate.sh` |
| VendorQ compliance questionnaire review | Reviewer packet |
| Browser verification of the trust root in a VendorQ workflow | Proof pack (upload the nested `proof_pack/`) |
| Checkpoint export with decision receipts | Reviewer packet |

---

## Planned Convergence

Reviewer packets are expected to eventually wrap or derive from compiled packets,
unifying the trust root and verification contract under a single artifact type.
That migration is not current. Until it ships, both systems are maintained
independently with separate commands and file contracts.

---

## Quick Reference

```bash
# Compiled packet — init, compile, verify, gate
assay packet init --questionnaire q.csv --packs ./demo_pack --output draft/
assay packet compile --draft draft/ --packs ./demo_pack \
  --subject-type artifact --subject-id repo:myapp@v1.2.0 \
  --subject-digest sha256:<64hex> --output compiled/
assay packet verify compiled/
assay packet verify compiled/ --json
scripts/assay-gate.sh compiled/

# Reviewer packet — VendorQ export
assay vendorq export-reviewer \
  --proof-pack ./proof_pack \
  --boundary sample_boundary.json \
  --mapping sample_mapping.json \
  --out reviewer_packet/
assay reviewer verify reviewer_packet/
```
