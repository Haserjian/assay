# Security Audit Adjudication - 2026-04-03

**Status**: Canonical post-investigation adjudication memo

**Authority**: When this memo conflicts with raw audit notes, pre-adjudication summaries, or mixed-contract security drafts from the same investigation window, this memo controls until superseded by a later adjudicated artifact.

**Scope**: This memo freezes the main reclassifications from the 2026-04-03 investigation across the Assay ecosystem surface, especially where earlier analysis mixed contracts, overstated assurance failures, or blurred docs/promise mismatches into verifier-core bugs.

**Validation basis**:
- Source inspection across `assay`, `assay-ledger`, and `agentmesh`
- Proof-pack contract review in `docs/contracts/PACK_CONTRACT.md`
- Focused ReceiptV2 test pass in `tests/assay/test_v2_sign.py` and `tests/assay/test_v2_verify.py` after the clarification patch set

## Control Buckets

| Bucket | Meaning |
|---|---|
| False / overstated | The original claim mixed layers, mixed contracts, or asserted a standards bug where none exists. |
| Real and fixed | A real semantic or assurance issue existed and the current patch set closed it at the claimed layer. |
| Real but docs-only | The main problem was promise, naming, or assurance language rather than broken cryptographic behavior. |
| Real and still open | A real design, policy, or hardening gap remains after clarification and narrow fixes. |

## Adjudication Table

| Finding | Original claim | Adjudication | Layer | Status | Next action |
|---|---|---|---|---|---|
| C2/C3 | The Python and TypeScript proof-pack verifiers check the wrong required fields, so proof-pack verification is contradictory or broken. | **False / overstated.** The earlier audit mixed the Assay proof-pack receipt contract with a different gateway/reference receipt schema. For proof-pack verification, the current contract intentionally requires the proof-pack receipt minimums described in `PACK_CONTRACT.md`, not the richer gateway/reference field set. This is not a blanket proof-pack verifier-core contradiction. | Contract boundary: proof-pack receipts vs gateway/reference receipts | Retired | Keep future audits split by contract surface. Only reopen if the proof-pack contract itself changes or a same-contract parity corpus is defined. |
| C4 | Signer authorization does not really exist, so trust evaluation is effectively absent. | **Real and still open.** The dangerous part was narrower than that: the low-level `trusted_signer` bit was easy to overread, and empty/default bootstrap posture is still weak when the authorized signer policy is not activated. `verify-pack` does have a higher-level trust evaluation layer; the clarification patch only fixed the semantics boundary, not the bootstrap gap. | Trust semantics and policy bootstrap | Partial clarification landed; bootstrap still open | Define and enforce the canonical production resolver and signer-registry path. Decide whether non-empty signer policy must be active by default. |
| C6 | PQ/archival posture is live today, but unsupported algorithms sit in active policy sets in a misleading way. | **Real and fixed.** The current build now states unsupported PQ algorithms as unsupported, and `archival-v1` wording no longer implies end-to-end PQ emit/verify capability that does not yet exist. | ReceiptV2 capability signaling and algorithm policy | Closed for the current build | Do not promote PQ capability back into operational claims until emit and verify paths exist end-to-end. |
| C7 | The public ledger independently re-verifies the whole proof pack, or at least provides stronger assurance than the workflow actually delivers. | **Real and still open.** The real issue was scope. The ledger witnesses the manifest and attestation layer, not the full pack tree. README, charter, and workflow wording now say that honestly. Stronger full-pack independent re-verification is still a protocol gap if that stronger claim is desired. | Transparency log witness scope and protocol design | Docs corrected; stronger protocol still open | If stronger claims are required, extend submission so the ledger can fetch or receive full pack contents and recompute receipt/file hashes before append. |
| H4 | AgentMesh CI and README language imply cryptographic enforcement is guaranteed by default because `assay-gate` exists in CI. | **Real but docs-only.** The problem was naming and assurance language, not a missing cryptographic verification step. `assay-gate` is baseline evidence-readiness scoring; `assay-verify` is the cryptographic proof-pack verification step; GitHub branch protection must be configured explicitly. | CI semantics and branch-protection policy | Closed via README correction | Optionally add branch-protection bootstrap or CI linting if the repo wants enforcement-by-construction instead of documentation-only guidance. |
| M1 | JCS is wrong or unsafe because it does not normalize Unicode before canonicalization. | **False / overstated.** RFC 8785 explicitly preserves parsed string data as-is and does not perform Unicode normalization. This is not a standards bug in JCS. Any ASCII-only or confusable rule belongs to higher-level schema or identifier policy. | Standards interpretation: JCS vs application policy | Retired | No code change at the JCS layer. Only add higher-layer field-name policy if the product wants that posture. |
| Homoglyph issue | Unicode lookalikes can create spoof-like field-name confusion, including around excluded or special field names. | **Real and still open, but at the correct layer.** This is not a JCS bug. It is a schema and identifier hardening question. Pre-projection ASCII-only validation or TR39-style confusable screening would address the spoof-like edge if that surface matters to the project. | Field-name policy and canonical projection hardening | Open hardening candidate | Decide between ASCII-only field names and confusable-aware screening, then implement it before projection or receipt validation if desired. |

## Settlement Notes

1. The most important retired phantom is the C2/C3 proof-pack verifier contradiction. That claim depended on mixing two different contracts.
2. The most important still-open architectural question is C7: whether the ledger should evolve from manifest/attestation witnessing to full-pack independent re-verification.
3. C4 remains a real trust-surface question, but it is now narrowed correctly: the unresolved issue is bootstrap and policy activation, not the total absence of trust evaluation.
4. M1 and the homoglyph issue must stay separated. JCS is behaving according to spec; any spoof-resistance rule lives above JCS.

## Current Constitutional Reading

The 2026-04-03 investigation reduced the original fog into four stable conclusions:

- One major verifier-core alarm was retired as a contract mix-up.
- One real semantic cleanup landed around `trusted_signer`, but bootstrap policy still needs a deliberate decision.
- One real capability-signaling issue landed cleanly around unsupported PQ posture.
- One real architectural question remains open around how much the public ledger should independently prove.

That is the canonical settlement as of this memo.
