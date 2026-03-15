# Signed Lifecycle Receipt Spec v0.1

Status: DRAFT
Scope: challenge, supersession, revocation events for Assay Passports
Prerequisite: passport signing (Ed25519 + JCS) already shipped

---

## A. Lifecycle Receipt Envelope

### A.1 Common Envelope

Every lifecycle event is a signed receipt with content-addressed identity.
Follows the same integrity posture as passport signing: JCS canonicalization,
Ed25519 signatures, SHA-256 content addressing.

```json
{
  "receipt_version": "0.1",
  "event_type": "challenge | supersession | revocation",
  "event_id": "sha256:<hex64>",

  "issued_at": "<ISO 8601 UTC>",

  "issuer": {
    "id": "<signer_id>",
    "fingerprint": "<sha256 of public key, hex64>",
    "role": "challenger | issuer | authority",
    "pubkey": "<base64 Ed25519 public key>"
  },

  "target": {
    "passport_id": "sha256:<hex64>",
    "subject_system_id": "<string>"
  },

  "reason": {
    "code": "<structured reason code>",
    "summary": "<human-readable string>"
  },

  "evidence_refs": ["<uri or sha256:hex64>"],

  "prior_event_refs": ["sha256:<hex64>"],

  "signature": {
    "algorithm": "Ed25519",
    "signature": "<base64>",
    "key_id": "<signer_id>",
    "key_fingerprint": "<hex64>",
    "signed_at": "<ISO 8601 UTC>",
    "scope": "jcs_rfc8785_without_signature"
  }
}
```

### A.2 Field Specification

| Field | Required | Type | Description |
|---|---|---|---|
| `receipt_version` | yes | string | Always `"0.1"` |
| `event_type` | yes | enum | `"challenge"`, `"supersession"`, `"revocation"` |
| `event_id` | yes | string | `"sha256:" + SHA-256(JCS(body without event_id and signature))` |
| `issued_at` | yes | string | ISO 8601 UTC timestamp |
| `issuer.id` | yes | string | Signer key ID |
| `issuer.fingerprint` | yes | string | SHA-256 of raw Ed25519 public key bytes, hex |
| `issuer.role` | yes | enum | `"challenger"`, `"issuer"`, `"authority"` |
| `issuer.pubkey` | yes | string | Base64-encoded Ed25519 public key (32 bytes) |
| `target.passport_id` | yes | string | Content-addressed passport digest, `"sha256:<hex64>"` |
| `target.subject_system_id` | no | string | Target system ID (informational) |
| `reason.code` | yes | string | Machine-readable reason code |
| `reason.summary` | yes | string | Human-readable explanation |
| `evidence_refs` | no | array | URIs or content hashes of supporting evidence |
| `prior_event_refs` | no | array | event_ids of predecessor events (chain) |
| `signature` | yes | object | Ed25519 signature block (same shape as passport) |

### A.3 Content-Addressed Identity Derivation

Identical to passport pattern:

```
1. body = all fields EXCEPT "event_id" and "signature"
2. event_id = "sha256:" + SHA-256(JCS(body))
3. signing_body = body + event_id (no signature)
4. signature = Ed25519.sign(JCS(signing_body), key)
```

This matches the passport `passport_id` derivation exactly, including the
`"sha256:"` prefix convention.

### A.4 Design Choice: Embedded Public Key

Lifecycle receipts embed `issuer.pubkey` for portable verification.

This differs from the current passport design, which does NOT embed the
public key and requires the verifier to have the signing key locally.

Rationale: lifecycle events may be consumed by parties who do not share
a keystore with the issuer. Challenge events in particular must be
verifiable by third parties who only have the receipt itself.

This is a deliberate divergence. The passport itself may adopt embedded
pubkeys in a future version, but that is out of scope here.

### A.5 Reason Codes

#### Challenge reason codes

| Code | Meaning |
|---|---|
| `coverage_gap` | Missing call-site or system coverage |
| `stale_evidence` | Evidence is outdated or no longer representative |
| `claim_dispute` | Specific claim assertion is contested |
| `scope_mismatch` | Scope declarations do not match observed behavior |
| `integrity_concern` | Suspected integrity issue not caught by verification |
| `other` | Free-form (summary required) |

#### Supersession reason codes

| Code | Meaning |
|---|---|
| `coverage_improvement` | New passport covers more call sites |
| `claim_update` | Claims updated with new evidence |
| `evidence_refresh` | Same claims, fresh evidence |
| `scope_expansion` | Scope expanded to cover more systems |
| `remediation` | Addresses a specific challenge |
| `scheduled_renewal` | Routine periodic renewal |

#### Revocation reason codes

| Code | Meaning |
|---|---|
| `key_compromise` | Signing key may be compromised |
| `false_claim` | One or more claims found to be false |
| `subject_decommissioned` | Subject system no longer exists |
| `issuer_withdrawal` | Issuer withdraws the passport |
| `authority_directive` | External authority orders revocation |

### A.6 Examples

#### Challenge receipt

```json
{
  "receipt_version": "0.1",
  "event_type": "challenge",
  "event_id": "sha256:a1b2c3...",
  "issued_at": "2026-03-14T12:00:00+00:00",
  "issuer": {
    "id": "auditor-key-1",
    "fingerprint": "9f8e7d...",
    "role": "challenger",
    "pubkey": "base64..."
  },
  "target": {
    "passport_id": "sha256:e7bd71f6...",
    "subject_system_id": "workflow.support.v1"
  },
  "reason": {
    "code": "coverage_gap",
    "summary": "Admin escalation override call site is not instrumented"
  },
  "evidence_refs": [
    "sha256:abc123..."
  ],
  "prior_event_refs": [],
  "signature": {
    "algorithm": "Ed25519",
    "signature": "base64...",
    "key_id": "auditor-key-1",
    "key_fingerprint": "9f8e7d...",
    "signed_at": "2026-03-14T12:00:01+00:00",
    "scope": "jcs_rfc8785_without_signature"
  }
}
```

#### Supersession receipt

```json
{
  "receipt_version": "0.1",
  "event_type": "supersession",
  "event_id": "sha256:d4e5f6...",
  "issued_at": "2026-03-15T09:00:00+00:00",
  "issuer": {
    "id": "assay-local",
    "fingerprint": "baaf5c...",
    "role": "issuer",
    "pubkey": "base64..."
  },
  "target": {
    "passport_id": "sha256:e7bd71f6...",
    "subject_system_id": "workflow.support.v1"
  },
  "reason": {
    "code": "remediation",
    "summary": "Addressed coverage gap for admin escalation override"
  },
  "evidence_refs": [],
  "prior_event_refs": ["sha256:a1b2c3..."],
  "supersession": {
    "new_passport_id": "sha256:f7g8h9...",
    "challenge_refs_addressed": ["sha256:a1b2c3..."]
  },
  "signature": { "..." : "..." }
}
```

#### Revocation receipt

```json
{
  "receipt_version": "0.1",
  "event_type": "revocation",
  "event_id": "sha256:j0k1l2...",
  "issued_at": "2026-03-16T00:00:00+00:00",
  "issuer": {
    "id": "assay-local",
    "fingerprint": "baaf5c...",
    "role": "issuer",
    "pubkey": "base64..."
  },
  "target": {
    "passport_id": "sha256:e7bd71f6...",
    "subject_system_id": "workflow.support.v1"
  },
  "reason": {
    "code": "key_compromise",
    "summary": "Signing key may have been exposed"
  },
  "evidence_refs": [],
  "prior_event_refs": [],
  "signature": { "..." : "..." }
}
```

### A.7 Event-Type-Specific Fields

The `supersession` event type adds one extra top-level field:

| Field | Required | Type | Description |
|---|---|---|---|
| `supersession.new_passport_id` | yes | string | `"sha256:<hex64>"` of the replacement passport |
| `supersession.challenge_refs_addressed` | no | array | event_ids of challenges this supersession addresses |

Challenge and revocation use only the common envelope fields.

---

## B. Verification + Verdict Model

### B.1 Dimensions

Verification produces six orthogonal facts. Verdict is a deterministic
function of those facts plus policy mode.

| Dimension | Type | Values |
|---|---|---|
| `signature_valid` | bool | `true` / `false` / `null` (unsigned) |
| `schema_valid` | bool | `true` / `false` |
| `content_hash_valid` | bool | `true` / `false` / `null` (no passport_id) |
| `freshness_status` | enum | `fresh` / `stale` |
| `governance_status` | enum | `none` / `challenged` / `superseded` / `revoked` |
| `event_integrity` | enum | `all_valid` / `some_invalid` / `no_events` |

### B.2 Governance Status Computation

Governance status is derived from verified lifecycle receipts, not
file adjacency. In receipt mode:

1. Collect all lifecycle receipts targeting this passport_id
2. Verify each receipt's signature and content-addressed ID
3. Check issuer role authority (see B.4)
4. Discard receipts that fail verification or authority checks
5. Apply precedence: REVOKED > SUPERSEDED > CHALLENGED > NONE

In demo mode, unsigned local JSON files are accepted without
signature verification. The governance_status is still computed
with the same precedence rules.

### B.3 Reliance Verdict

The reliance verdict is a deterministic function:

```
reliance_verdict = f(signature_valid, schema_valid, content_hash_valid,
                     freshness_status, governance_status, event_integrity,
                     policy_mode)
```

Values: `PASS`, `WARN`, `FAIL`

### B.4 Actor Authority Model

| Action | Required issuer.role | Authority check |
|---|---|---|
| Challenge | `challenger` | Any identified actor. Signature must verify against embedded pubkey. |
| Supersede | `issuer` | Issuer fingerprint must match target passport's `chain.issuer_fingerprint` or `signature.key_fingerprint`. |
| Revoke | `issuer` or `authority` | Same as supersede for `issuer`. For `authority`, fingerprint must be in passport's `authority_keys` list (future), or match the passport's issuer fingerprint. |

In demo mode, authority checks are skipped. In receipt mode, receipts
from unauthorized issuers are silently discarded (logged as warnings,
never affect governance_status).

### B.5 Deterministic Mapping Table

#### Policy modes

| Mode | Description | Use case |
|---|---|---|
| `permissive` | Only FAIL on integrity failure or revocation | Operator/development |
| `buyer-safe` | FAIL on revocation, challenged, stale | Procurement, audit |
| `strict` | FAIL on anything except PASS conditions | CI gate, compliance |

#### Mapping matrix

| signature_valid | schema_valid | content_hash_valid | freshness | governance | event_integrity | → permissive | → buyer-safe | → strict |
|---|---|---|---|---|---|---|---|---|
| false | * | * | * | * | * | FAIL | FAIL | FAIL |
| * | false | * | * | * | * | FAIL | FAIL | FAIL |
| * | * | false | * | * | * | FAIL | FAIL | FAIL |
| * | * | * | * | revoked | * | FAIL | FAIL | FAIL |
| * | * | * | * | * | some_invalid | WARN | WARN | FAIL |
| * | * | * | * | superseded | * | WARN | WARN | FAIL |
| * | * | * | * | challenged | * | WARN | FAIL | FAIL |
| * | * | * | stale | none | * | WARN | FAIL | FAIL |
| null | true | null | fresh | none | * | WARN | WARN | FAIL |
| true | true | true | fresh | none | all_valid/no_events | PASS | PASS | PASS |

Read top to bottom; first matching row wins.

Row 1-4: hard failures in all modes (integrity or revocation).
Row 5: lifecycle receipt integrity issues — warn everywhere except strict.
Row 6: superseded — warn by default, strict fails.
Row 7: challenged — permissive warns, buyer-safe and strict fail.
Row 8: stale — permissive warns, others fail.
Row 9: unsigned — permissive and buyer-safe warn, strict fails.
Row 10: clean passport — PASS everywhere.

### B.6 CLI Consequences

#### `assay passport verify` — object integrity

Reports raw dimensional facts. Does NOT compute reliance verdict.

Exit codes:
- 0: all integrity checks pass (signature, schema, content hash)
- 1: lifecycle integrity issue (event receipts fail verification)
- 2: passport integrity failure (signature invalid, content hash mismatch)
- 3: input error (file not found, malformed JSON)

Output (JSON mode):
```json
{
  "command": "passport verify",
  "signature_valid": true,
  "schema_valid": true,
  "content_hash_valid": true,
  "freshness_status": "fresh",
  "governance_status": "challenged",
  "governance_events": [
    {"event_id": "sha256:...", "event_type": "challenge", "verified": true}
  ],
  "event_integrity": "all_valid"
}
```

#### `assay passport status` — reliance verdict (NEW COMMAND)

Computes and returns the reliance verdict for a given policy mode.

```
assay passport status <passport.json> [--mode permissive|buyer-safe|strict]
```

Default mode: `permissive`

Exit codes:
- 0: PASS
- 1: WARN
- 2: FAIL
- 3: input error

Output (JSON mode):
```json
{
  "command": "passport status",
  "policy_mode": "buyer-safe",
  "reliance_verdict": "WARN",
  "dimensions": {
    "signature_valid": true,
    "schema_valid": true,
    "content_hash_valid": true,
    "freshness_status": "fresh",
    "governance_status": "challenged",
    "event_integrity": "all_valid"
  },
  "reason": "Passport is under active challenge"
}
```

#### `assay passport xray` — grade interaction

Grade computation adds `event_integrity` as a grading input:

- **F**: any integrity failure, revoked, OR event_integrity == some_invalid in strict
- **A-D**: unchanged from current grading logic

X-Ray findings now include governance event findings:
- `category: "governance"`, severity based on governance_status
- Individual event verification findings when events fail signature checks

---

## C. State Machine

### C.1 States

```
FRESH → CHALLENGED → SUPERSEDED → (terminal)
FRESH → SUPERSEDED → (terminal)
FRESH → REVOKED → (terminal)
CHALLENGED → SUPERSEDED → (terminal)
CHALLENGED → REVOKED → (terminal)
STALE → CHALLENGED → SUPERSEDED → (terminal)
STALE → SUPERSEDED → (terminal)
STALE → REVOKED → (terminal)
```

SUPERSEDED and REVOKED are terminal states. A revoked or superseded
passport cannot return to FRESH or CHALLENGED.

STALE is computed from temporal facts (valid_until), not from events.
A STALE passport can still be challenged, superseded, or revoked.

### C.2 Precedence Rules

When multiple governance events exist for the same passport:

1. **REVOKED wins over everything.** Any valid revocation receipt
   forces REVOKED regardless of other events.

2. **SUPERSEDED wins over CHALLENGED.** If both supersession and
   challenge receipts exist, the passport is SUPERSEDED (the
   supersession implicitly addresses or moots the challenges).

3. **CHALLENGED accumulates.** Multiple valid challenge receipts
   produce CHALLENGED with all challenges listed. They do not
   cancel each other.

4. **STALE is independent.** Freshness is computed from valid_until
   and current time. A passport can be both STALE and CHALLENGED,
   but the governance_status takes precedence in the output
   (CHALLENGED over STALE, per priority order).

### C.3 Invalid Transitions

These transitions are rejected:

- Challenge targeting a REVOKED passport: receipt is accepted and stored,
  but has no effect on governance_status (already terminal).
- Supersession targeting a REVOKED passport: same — receipt stored,
  no status change.
- Revocation of an already-revoked passport: idempotent; second
  revocation receipt is stored but does not change state.
- Supersession by a passport that is itself revoked: the supersession
  receipt is valid (it was signed before the new passport was revoked),
  but the consuming verifier should check the replacement passport's
  status separately.

### C.4 Chain Semantics

Supersession creates a directed chain:

```
passport_v1 --superseded_by--> passport_v2 --superseded_by--> passport_v3
```

Properties:
- A passport can be superseded at most once (first valid supersession
  receipt wins; subsequent supersession receipts for the same target
  are stored but do not change `superseded_by`).
- Chain traversal: `assay passport diff` follows supersession chains
  and reports `is_supersession: true` when B supersedes A.
- Cycle detection: a passport cannot supersede itself or a passport
  that already supersedes it. This is enforced by checking
  `target.passport_id != supersession.new_passport_id` and
  traversing the chain for cycles (max depth 10).

### C.5 Conflict Handling

| Scenario | Behavior |
|---|---|
| Multiple challenges | All valid challenges accumulate; state = CHALLENGED |
| Challenge + supersession | SUPERSEDED wins (supersession addresses challenges) |
| Challenge + revocation | REVOKED wins |
| Supersession + revocation | REVOKED wins |
| Challenge + supersession + revocation | REVOKED wins |
| Multiple supersessions (same target) | First valid supersession wins |
| Supersession chain A→B, then B revoked | A is SUPERSEDED; consumer must check B separately |
| Malformed receipt (bad JSON) | Silently discarded, logged as warning |
| Unsigned receipt in receipt mode | Discarded; not counted for governance_status |
| Unsigned receipt in demo mode | Accepted; counted for governance_status |
| Receipt with wrong target passport_id | Discarded; does not affect this passport |
| Receipt with invalid signature | Discarded in receipt mode; accepted in demo mode |
| Receipt with unauthorized issuer role | Discarded in receipt mode; accepted in demo mode |

### C.6 Demo Mode vs Receipt Mode

| Property | Demo mode | Receipt mode |
|---|---|---|
| Receipt format | Unsigned JSON (current format) | Signed envelope (this spec) |
| Discovery | File glob in passport directory | File glob in passport directory |
| Signature verification | Skipped | Required |
| Authority checks | Skipped | Required |
| Content-addressed ID | Optional | Required |
| CLI flag | `--demo` or default when no keystore | Default when keystore available |

In demo mode, the current file-adjacent unsigned receipt format continues
to work. This preserves backward compatibility with the existing
`create_challenge_receipt()`, `create_supersession_receipt()`, and
`create_revocation_receipt()` functions.

In receipt mode, unsigned receipts in the passport directory are logged
as warnings and excluded from governance_status computation.

---

## D. Implementation Delta

### D.1 Files to Add

| File | Lines (est) | Purpose |
|---|---|---|
| `src/assay/lifecycle_receipt.py` | ~250 | Signed lifecycle receipt creation and verification |
| `src/assay/verdict.py` | ~150 | Verdict computation (dimensions → reliance_verdict) |
| `src/assay/schemas/lifecycle_receipt_v0.1.schema.json` | ~100 | JSON Schema for lifecycle receipt envelope |
| `tests/assay/test_lifecycle_receipt.py` | ~200 | Signed receipt creation, verification, tampering |
| `tests/assay/test_verdict.py` | ~180 | Verdict matrix coverage for all policy modes |

### D.2 Files to Modify

| File | Change | Description |
|---|---|---|
| `src/assay/passport_lifecycle.py` | Extend | Add `load_verified_events()` that verifies receipt signatures and authority. Keep `compute_passport_state()` but add `mode` parameter (`demo`/`receipt`). |
| `src/assay/passport_commands.py` | Extend | Add `passport status` command. Modify `passport verify` to report dimensions. Modify `passport challenge/supersede/revoke` to produce signed receipts (with `--demo` fallback). |
| `src/assay/xray.py` | Extend | Add `governance` finding category. Wire `event_integrity` into grade computation. |
| `src/assay/commands.py` | None | No change needed (passport_app wiring already in place). |

### D.3 What to Deprecate

The current unsigned receipt functions in `passport_lifecycle.py`
(`create_challenge_receipt`, `create_supersession_receipt`,
`create_revocation_receipt`) are NOT deprecated. They become the
demo-mode path.

New signed receipt functions are added alongside:
- `create_signed_challenge_receipt()`
- `create_signed_supersession_receipt()`
- `create_signed_revocation_receipt()`

The CLI defaults to signed receipts when a keystore is available,
and falls back to unsigned (demo mode) otherwise.

### D.4 Migration Plan

Phase 1: Add `lifecycle_receipt.py` and `verdict.py` as new modules.
No changes to existing behavior. New functions are opt-in.

Phase 2: Modify `passport_commands.py` to:
- Add `passport status` command
- Modify `passport verify` output to include dimensional facts
- Modify `passport challenge/supersede/revoke` to default to signed
  receipts, with `--demo` flag for unsigned fallback

Phase 3: Modify `xray.py` to include governance event integrity
in grade computation.

Each phase is independently shippable and testable.

### D.5 Smallest Launch Cut

The minimum viable hardening is:

1. `lifecycle_receipt.py` — signed receipt creation + verification
2. `verdict.py` — verdict computation with policy modes
3. `passport status` command
4. Tests for all three

This can ship without modifying `passport verify`, `xray`, or
the existing demo-mode receipt functions.

---

## E. Test Plan

### E.1 Golden Cases

| Test | Input | Expected |
|---|---|---|
| Create signed challenge | Valid passport, valid keystore | Receipt with valid signature, correct event_id |
| Create signed supersession | Old + new passport, issuer key | Receipt with supersession.new_passport_id |
| Create signed revocation | Valid passport, issuer key | Receipt with valid signature |
| Verify signed challenge | Valid receipt | signature_valid=true, id_valid=true |
| Verify signed supersession | Valid receipt | signature_valid=true, authority_valid=true |
| Compute governance_status with challenge | One valid challenge receipt | governance_status=challenged |
| Compute governance_status with revocation | One valid revocation receipt | governance_status=revoked |
| Verdict: clean passport, permissive | All dimensions clean | PASS |
| Verdict: clean passport, strict | All dimensions clean | PASS |
| Verdict: challenged, permissive | governance=challenged | WARN |
| Verdict: challenged, buyer-safe | governance=challenged | FAIL |
| Verdict: superseded, strict | governance=superseded | FAIL |
| Verdict: stale, buyer-safe | freshness=stale | FAIL |
| Status CLI: exit code matches verdict | Various inputs | exit 0/1/2 |

### E.2 Adversarial Cases

| Test | Attack | Expected |
|---|---|---|
| Tampered challenge receipt | Modify reason after signing | signature_valid=false, receipt discarded |
| Forged event_id | Replace event_id with different hash | id_valid=false, receipt discarded |
| Wrong target passport_id | Challenge targets different passport | Receipt discarded (wrong target) |
| Replay: same receipt twice | Duplicate receipt file | Deduplicated by event_id |
| Future timestamp | issued_at in the future | Receipt accepted (clock skew tolerance), logged |
| Empty reason | reason.summary = "" | Schema validation failure |
| Unknown event_type | event_type = "freeze" | Schema validation failure |

### E.3 Tampering Cases

| Test | Tamper | Expected |
|---|---|---|
| Modify receipt body after signing | Change reason.code | Signature fails verification |
| Strip signature from receipt | Remove signature block | Treated as unsigned; discarded in receipt mode |
| Replace signature with different key | Re-sign with unauthorized key | Authority check fails; discarded |
| Modify event_id without re-signing | Change event_id | Content hash mismatch; discarded |
| Modify target.passport_id | Point at different passport | Receipt not loaded for original passport |

### E.4 Identity/Authorization Cases

| Test | Scenario | Expected |
|---|---|---|
| Challenger with valid key | Any key, role=challenger | Challenge accepted |
| Supersession by non-issuer | Different key, role=issuer | Authority check fails in receipt mode |
| Supersession by issuer | Issuer key, role=issuer | Supersession accepted |
| Revocation by issuer | Issuer key, role=issuer | Revocation accepted |
| Revocation by non-issuer | Different key, role=authority | Rejected unless in authority_keys (future) |
| Demo mode: unsigned challenge | No signature | Accepted in demo mode only |
| Demo mode: unauthorized supersession | Wrong key, no check | Accepted in demo mode |
| Receipt mode: unsigned receipt | No signature | Discarded with warning |

### E.5 State Machine Cases

| Test | Scenario | Expected |
|---|---|---|
| FRESH + challenge = CHALLENGED | Single challenge | governance_status=challenged |
| CHALLENGED + supersession = SUPERSEDED | Challenge then supersede | governance_status=superseded |
| CHALLENGED + revocation = REVOKED | Challenge then revoke | governance_status=revoked |
| REVOKED + challenge = REVOKED | Challenge after revoke | Revoked unchanged |
| Multiple challenges = CHALLENGED | Two challenges | governance_status=challenged, count=2 |
| Supersession chain A→B→C | Three passports | A=superseded, B=superseded, C=fresh |
| Self-supersession attempt | passport supersedes itself | Rejected |
| Supersession cycle A→B→A | Circular chain | Rejected (cycle detection) |

---

## Design Decisions Log

### Why nested signature object (not flat string)?

Matches passport signing convention. All lifecycle receipts and
passports share the same signature block shape, making verification
code reusable.

### Why `sha256:` prefix on event_id?

Matches passport_id convention. Note: this diverges from ADC
credential_id which uses raw hex without prefix. The passport
ecosystem uses the prefix; the ADC ecosystem does not. This spec
follows the passport convention.

### Why embedded public key?

Lifecycle receipts must be verifiable by third parties who do not
share a keystore. Challenges especially: an external auditor should
be able to verify that a challenge receipt is authentic without
having the challenger's key pre-installed.

This diverges from the current passport design (which does NOT
embed the public key). If passports adopt embedded pubkeys in a
future version, the patterns will converge.

### Why not change passport signing?

Out of scope. This spec hardens the governance layer without
breaking the existing passport object format or signing procedure.

### Why keep demo mode?

The current unsigned receipt format works well for local development,
demos, and quick testing. Forcing signed receipts everywhere would
add friction without benefit for non-production use cases.

The two modes are explicit, not ambiguous. Receipt mode is the
trust-bearing path; demo mode is the convenience path.
