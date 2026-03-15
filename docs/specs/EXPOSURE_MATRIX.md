# Exposure Matrix: Passport + Governance Surfaces

**Purpose:** Pin exact allowed claims and forbidden overclaims for each
audience tier. Prevents narrative drift from outrunning implementation.

**Last verified:** 2026-03-14

---

## Internal (team, architecture notes)

### Allowed claims

- Passport object model is real: signed, content-addressed, JCS-canonicalized
- Governance events (challenge, supersede, revoke) are Ed25519-signed lifecycle
  receipts with content-addressed identity and embedded public keys
- `verify` and `status` are explicitly separated: object validity vs policy-derived
  reliance posture
- Signed passports are immutable after signing; supersession linkage lives in
  receipts, not in mutated passport bodies
- Governance status and event integrity are derived from verified receipt
  ingestion, not from filesystem presence alone
- Demo lane is quarantined: `create_demo_*` helpers are non-production
- X-Ray grades passport JSON structure (A-F)
- Passport diff detects claim regressions, coverage changes, reliance class shifts
- 164 tests cover the full pipeline including integration tests

### Internal-only knowledge (do not expose publicly)

- Unsigned demo receipts still affect governance_status but not event_integrity
- Authority model is limited to issuer fingerprint matching; "designated authority"
  is a reserved extension point, not implemented
- Mixed signed/unsigned evidence directories are accepted but not formally doctrine
- Passport mint only works from Assay proof packs, not arbitrary inputs
- The `--demo` flag exists primarily for backward compatibility, not as a
  deliberate operational mode

---

## Pilot (design partners, qualified prospects)

### Allowed claims

- Assay can produce signed, verifiable passport objects from proof pack evidence
- Passports carry claims, coverage, reliance class, and validity windows
- `verify` answers structural validity; `status` answers reliance posture under
  configurable policy (permissive / buyer-safe / strict)
- Lifecycle governance is real: challenge degrades reliance, supersession links
  old to new, revocation is permanent
- All governance events are cryptographically signed
- X-Ray provides structural diagnostic and grading on passport JSON
- Trust Diff compares two passports and flags regressions
- Passport HTML renders are self-contained, portable, offline-verifiable

### Allowed demonstrations

- Mint from proof pack, sign, verify, status
- Challenge a passport, observe status degradation
- Supersede, diff the two versions
- X-Ray with grade and improvement recommendations
- Full 10-step demo (`assay passport demo`)

### Forbidden overclaims (pilot)

- "Scan any vendor trust page" — X-Ray works on passport JSON, not arbitrary URLs or PDFs
- "Mint from your SOC 2 report" — mint works from proof packs, not external documents
- "Enterprise Trust Diff" — diff is a CLI primitive, not a workflow product
- "Delegated authority" — only the original issuer can supersede or revoke
- "Real-time governance monitoring" — governance is batch evidence, not live

---

## Public (README, website, marketing, conference talks)

### Allowed claims

- Assay produces portable, signed evidence objects for AI system verification
- Passports are content-addressed and Ed25519-signed
- Lifecycle governance (challenge, supersede, revoke) is cryptographically backed
- Verification is deterministic and offline-capable
- Open source, `pip install assay-ai`

### Allowed public demonstrations

- Seeded artifact referee flow using canonical examples only:
  show, verify, status, challenge, supersede, diff
- Worked example gallery with pre-built passports
- `assay passport demo` output

### Forbidden overclaims (public)

- "Paste any trust page and get a verdict" — not implemented
- "Mint passports from vendor documents" — not implemented
- "AI trust score" or "trust rating" — Assay provides evidence-based verdicts,
  not scores or ratings
- "Enterprise Trust Diff product" — primitive exists, product does not
- "Scan your vendor's security posture" — Assay does not scan external systems
- "Automated compliance" — Assay produces evidence for compliance decisions,
  it does not make compliance determinations
- "Designated authority model" — implementation is issuer-only

### Verdict language (public-safe)

Use only these outer verdicts in public-facing material:

| Term | Meaning | Safe to use publicly |
|------|---------|---------------------|
| PASS | Evidence is valid, fresh, and unchallenged | Yes |
| WARN | Evidence has concerns but is not failed | Yes, with context |
| FAIL | Evidence has integrity failure or governance event | Yes |
| HONEST FAIL | System worked correctly but result was negative | Yes — this is the commercial center |

Do not expose these publicly without context:
- Policy mode names (permissive / buyer-safe / strict) — too implementation-specific
- Event integrity states (all_valid / some_invalid) — too granular
- Governance status values (challenged / superseded / revoked) — safe in demos
  but need framing in prose

---

## Review triggers

Re-evaluate this matrix when:
- X-Ray gains URL/PDF ingestion capability
- Mint gains external document ingestion
- Authority delegation is implemented beyond issuer fingerprint
- Trust Diff becomes a product workflow (not just a CLI primitive)
- A buyer or prospect makes a request that falls in the "forbidden" column
