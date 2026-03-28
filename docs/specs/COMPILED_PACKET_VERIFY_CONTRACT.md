# Compiled Packet Verify Contract

**Surface**: `assay packet verify <packet_dir> --json`
**Schema version**: `packet_verification.v2`
**Source of truth**: `src/assay/compiled_packet.py` → `PacketVerifyResult.to_dict()`

This document is the external contract for machine consumers of `assay packet verify
--json`. CI scripts, TS verifiers, browser consumers, and any tooling that parses this
output must treat this as the stable interface.

---

## Exit Code Contract

| Exit code | Meaning | Condition |
|-----------|---------|-----------|
| `0` | Verification succeeded structurally | `integrity_verdict == "INTACT"` |
| `1` | Structural problem | `integrity_verdict` is `TAMPERED`, `DEGRADED`, or `INVALID` |

The exit code answers: *did verification succeed?*

It does not answer: *is this packet admissible under policy?* Admissibility is in the
JSON output (`admissible` field). CI gates should read that field, not exit code alone.

Stdout contains only JSON when `--json` is passed. Stderr contains diagnostics (Rich
formatting, warnings, crash traces). Always redirect or capture them separately.

---

## Top-Level JSON Output

```json
{
  "schema_version": "packet_verification.v2",
  "packet_id": "<str>",
  "packet_root_sha256": "<str | null>",
  "source_commit": "<str>",
  "verified_at": "<ISO 8601 timestamp>",
  "verifier_id": "assay@<version>",
  "verdict": "<str>",
  "integrity_verdict": "<str>",
  "completeness_verdict": "<str>",
  "admissible": <bool>,
  "admissibility_reasons": [...],
  "subject": {...},
  "pack_results": [...],
  "coverage": {...},
  "warnings": [...],
  "errors": [...]
}
```

---

## Field Reference

### `schema_version`
- Type: `string`
- Value: `"packet_verification.v2"`
- Used to detect contract version in consumers. Bump when fields are added or semantics change.

### `packet_id`
- Type: `string`
- The `packet_id` from `packet_manifest.json`. Empty string if manifest could not be read.

### `packet_root_sha256`
- Type: `string | null`
- The `packet_root_sha256` from the signed manifest. Null if the packet is `INVALID`
  (manifest unreadable). Used to identify this packet across systems.

### `source_commit`
- Type: `string`
- Provenance field from `packet_manifest.json`.
- Required for artifact packets that claim software-release provenance.
- Empty string when the manifest omits the field on non-artifact packets.

### `verified_at`
- Type: `string` (ISO 8601, UTC)
- Timestamp of when verification ran. Set by the verifier, not from the packet.

### `verifier_id`
- Type: `string`
- `"assay@<installed version>"`. Used to track which verifier version produced this result.

### `verdict`
- Type: `string`
- Possible values: `"PASS"`, `"PARTIAL"`, `"DEGRADED"`, `"TAMPERED"`, `"INVALID"`
- Derived deterministically from `integrity_verdict × completeness_verdict`:

  | `integrity_verdict` | `completeness_verdict` | `verdict` |
  |---------------------|----------------------|-----------|
  | `INTACT` | `COMPLETE` | `PASS` |
  | `INTACT` | `PARTIAL` | `PARTIAL` |
  | `INTACT` | `INCOMPLETE` | `PARTIAL` |
  | `DEGRADED` | any | `DEGRADED` |
  | `TAMPERED` | any | `TAMPERED` |
  | `INVALID` | any | `INVALID` |

- `PARTIAL` is not a failure. It means the packet is structurally sound with incomplete
  claim coverage. Completeness axis is evaluated separately.

### `integrity_verdict`
- Type: `string`
- Possible values: `"INTACT"`, `"DEGRADED"`, `"TAMPERED"`, `"INVALID"`
- `INTACT`: signatures valid, all pack roots match references
- `DEGRADED`: structural damage (missing bundled packs, ref hash mismatch)
- `TAMPERED`: cryptographic signature verification failed
- `INVALID`: manifest missing, unparseable, or required fields absent

### `completeness_verdict`
- Type: `string`
- Possible values: `"COMPLETE"`, `"PARTIAL"`, `"INCOMPLETE"`
- `COMPLETE`: all questionnaire items have `SUPPORTED` bindings
- `PARTIAL`: some items are `UNSUPPORTED` or `PARTIAL`
- `INCOMPLETE`: major coverage gaps (unbound questionnaire items)
- Only meaningful when `integrity_verdict == "INTACT"`. Under `TAMPERED`/`DEGRADED`/`INVALID`, completeness is not trustworthy.

### `admissible`
- Type: `boolean`
- `true` if and only if all admissibility conditions are met:
  1. `integrity_verdict == "INTACT"`
  2. Subject binding present and correctly formatted
  3. Bundle mode is `"bundled"` (all packs are inline)
- `false` if any condition fails. See `admissibility_reasons` for which.
- Admissibility is a policy judgment, not a cryptographic fact. It is available for
  gate consumers; it does not drive the CLI exit code.

### `admissibility_reasons`
- Type: `array of objects`
- Empty array when `admissible == true`.
- Each object: `{"code": "<str>", "message": "<str>"}`
- Possible codes:

  | Code | Meaning |
  |------|---------|
  | `INTEGRITY_FAILURE` | `integrity_verdict != "INTACT"` |
  | `SUBJECT_BINDING_MISSING` | No valid subject block or missing `subject_digest` |
  | `NOT_SELF_CONTAINED` | `bundle_mode != "bundled"` — cannot verify offline |

### `subject`
- Type: `object | {}`
- Empty object if no subject binding in manifest or packet is `INVALID`.
- When present:
  ```json
  {
    "subject_type": "artifact",
    "subject_id": "repo:myapp@v1.2.0",
    "subject_digest": "sha256:<64 lowercase hex>",
    "subject_uri": "<optional URI>"
  }
  ```
- `subject_type` values: `"artifact"`, `"run"`, `"decision"`
- `subject_digest` format: `sha256:<64 lowercase hex>` — enforced at compile time and
  verified at verify time

### `pack_results`
- Type: `array of objects`
- One entry per pack referenced in the manifest.
- Each object:
  ```json
  {
    "pack_id": "<str>",
    "pack_root_sha256": "<str>",
    "pack_present": <bool>,
    "pack_integrity": "<str>",
    "errors": ["<str>", ...]
  }
  ```
- `pack_integrity` values:
  - `"PASS"` — pack present and verified, root hash matches reference
  - `"FAIL"` — pack present but verification failed or root hash mismatch
  - `"MISSING"` — pack referenced but not found in bundle directory
  - `"NOT_BUNDLED"` — pack referenced but not bundled (expected for non-bundled mode)
- `pack_present` is `false` for `MISSING` and `NOT_BUNDLED` cases.
- `errors` contains up to 3 short diagnostic strings per pack.

### `coverage`
- Type: `object | {}`
- Empty object if bindings could not be loaded.
- When present:
  ```json
  {
    "total_bindings": <int>,
    "total_questionnaire_items": <int>,
    "unbound_items": ["<question_id>", ...],
    "status_counts": {
      "SUPPORTED": <int>,
      "PARTIAL": <int>,
      "UNSUPPORTED": <int>,
      "OUT_OF_SCOPE": <int>,
      "NON_CLAIM": <int>
    }
  }
  ```
- `unbound_items` is non-empty when `completeness_verdict == "INCOMPLETE"`.

### `warnings`
- Type: `array of strings`
- Non-fatal issues: unbundled pack references, advisory freshness notes.
- Does not affect `integrity_verdict` or `admissible`.

### `errors`
- Type: `array of objects`
- Each object: `{"code": "<str>", "message": "<str>", "field": "<str | omitted>"}`
- `field` is present only when the error is tied to a specific manifest field.
- Error codes by severity:

  | Code | Severity | Meaning |
  |------|----------|---------|
  | `E_PKT_SCHEMA` | FATAL → `INVALID` | Missing/invalid manifest fields |
  | `E_PKT_TAMPER` | FATAL → `TAMPERED` | Manifest hash mismatch |
  | `E_PKT_SIG_INVALID` | FATAL → `TAMPERED` | Signature verification failed |
  | `E_PKT_ROOT_INVARIANT` | FATAL → `TAMPERED` | packet_root_sha256 recomputation mismatch |
  | `E_PKT_PACK_MISSING` | DEGRADING → `DEGRADED` | Bundled pack not found |
  | `E_PKT_PACK_INVALID` | DEGRADING → `DEGRADED` | Bundled pack failed verification |
  | `E_PKT_REF_MISMATCH` | DEGRADING → `DEGRADED` | Pack root hash reference mismatch |

---

## Example: INTACT + PARTIAL packet (admissible)

```json
{
  "schema_version": "packet_verification.v2",
  "packet_id": "pkt-2026-03-27-abc123",
  "packet_root_sha256": "sha256:a1b2c3...",
  "verified_at": "2026-03-27T12:00:00Z",
  "verifier_id": "assay@1.19.0",
  "verdict": "PARTIAL",
  "integrity_verdict": "INTACT",
  "completeness_verdict": "PARTIAL",
  "admissible": true,
  "admissibility_reasons": [],
  "source_commit": "d1f001ccabc926d7f671c80399b5db1efca25034",
  "subject": {
    "subject_type": "artifact",
    "subject_id": "repo:myapp@v1.2.0",
    "subject_digest": "sha256:deadbeefdeadbeef..."
  },
  "pack_results": [
    {
      "pack_id": "demo_pack",
      "pack_root_sha256": "sha256:ffff...",
      "pack_present": true,
      "pack_integrity": "PASS",
      "errors": []
    }
  ],
  "coverage": {
    "total_bindings": 6,
    "total_questionnaire_items": 6,
    "unbound_items": [],
    "status_counts": {
      "SUPPORTED": 2,
      "PARTIAL": 1,
      "UNSUPPORTED": 3,
      "OUT_OF_SCOPE": 0,
      "NON_CLAIM": 0
    }
  },
  "warnings": [],
  "errors": []
}
```

---

## Example: Non-bundled packet (NOT_SELF_CONTAINED)

```json
{
  "verdict": "PARTIAL",
  "integrity_verdict": "INTACT",
  "completeness_verdict": "PARTIAL",
  "admissible": false,
  "admissibility_reasons": [
    {
      "code": "NOT_SELF_CONTAINED",
      "message": "Packet is not bundled — evidence cannot be verified offline"
    }
  ],
  ...
}
```

---

## Example: Tampered packet

```json
{
  "verdict": "TAMPERED",
  "integrity_verdict": "TAMPERED",
  "completeness_verdict": "COMPLETE",
  "admissible": false,
  "admissibility_reasons": [
    {
      "code": "INTEGRITY_FAILURE",
      "message": "Integrity is TAMPERED, must be INTACT"
    }
  ],
  "errors": [
    {"code": "E_PKT_TAMPER", "message": "Manifest hash does not match signed content"}
  ],
  ...
}
```

---

## Stability Guarantees

- Fields listed here will not be removed without a `schema_version` bump.
- Additional fields may be added without a version bump (consumers must ignore unknown fields).
- The `errors[].code` vocabulary is normative per `PACKET_SEMANTICS_V1.md §4`. New codes
  may be added; existing codes will not be removed.
- `completeness_verdict` and `integrity_verdict` string values are normative and stable.

---

## Consumer Pattern (shell)

```bash
RESULT=$(assay packet verify "$PACKET_DIR" --json 2>/dev/null)
INTEGRITY=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['integrity_verdict'])")
ADMISSIBLE=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['admissible'])")
```

For CI gating, use `scripts/assay-gate.sh` which handles stdout/stderr separation,
JSON parsing, and fail-closed enforcement in a single step.

## Consumer Pattern (Python)

```python
import json, subprocess
result = subprocess.run(
    ["assay", "packet", "verify", str(packet_dir), "--json"],
    capture_output=True, text=True
)
data = json.loads(result.stdout)
assert data["integrity_verdict"] == "INTACT"
assert data["admissible"] is True
```

## Consumer Pattern (TypeScript / browser)

See `assay-verify-ts` for the TS implementation of the compiled packet verifier.
The `--json` output contract is the interop substrate between Python and TS consumers.
