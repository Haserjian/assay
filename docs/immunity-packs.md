# Assay Immunity Packs

**Assay turns AI failures into portable immunity.**

An Assay Immunity Pack is a small evidence artifact derived from an honest
failure or near miss. It preserves the failure shape, emits a replayable
regression case, and derives one or more caution-only markers that a future
runtime could use to avoid repeating the same class of mistake.

The v0 implementation is deliberately plain: JSON in, deterministic JSON out,
no LLM classification, no runtime Guardian integration, and no market or legal
settlement layer.

## Flow

```text
Failure artifact
-> InoculationPack
-> EpigeneticMarker
-> future caution rule
```

## InoculationPack

An `InoculationPack` is the portable failure evidence object. It records:

- the source failure or proof-pack pointer
- deterministic failure class and severity
- trigger shape
- optional dignity, Delta-C, Omega-H, and Guardian context
- minimal replay case
- recommended marker specs
- regression test metadata
- evidence hashes
- review or expiration metadata
- rollback pointer

The schema is bundled at:

```text
src/assay/schemas/inoculation_pack.v0.1.schema.json
```

## EpigeneticMarker

An `EpigeneticMarker` is the caution object derived from a pack. It is not
memory inheritance and it is not a permission grant. It is a verified scar:
future matching episodes can use it to require stronger proof, require review,
reduce blast radius, defer, block, route to a safer provider, emit an honest
failure, or add a regression test.

The schema is bundled at:

```text
src/assay/schemas/epigenetic_marker.v0.1.schema.json
```

## Hard Invariant

Epigenetic markers must never increase authority.

They may only increase caution, require stronger verification, require
human/steward review, narrow blast radius, lower confidence, block or defer an
action, add a regression test, or attach rollback/expiration metadata.

They may not grant tool permissions, raise trust, bypass policy, skip
verification, suppress failure reporting, or authorize stronger execution.

The implementation enforces this through `validate_marker_safety()`.

## Example Input

```json
{
  "failure_id": "failure_tool_001",
  "source_proof_pack_id": "proof_pack_tool_001",
  "created_at": "2026-05-08T12:10:00Z",
  "trigger_shape": "unsafe tool call attempt: delete production records",
  "requested_action": "tool_call:delete production records",
  "guardian_decision": {
    "verdict": "REFUSE",
    "reason": "unsafe tool call"
  },
  "minimal_replay_case": {
    "tool": "database.delete",
    "arguments": {
      "table": "customers",
      "scope": "all"
    },
    "expected_guardian_action": "block"
  },
  "evidence_hashes": {
    "guardian_receipt": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
  },
  "review_after": "90d",
  "rollback_pointer": "policy_v12"
}
```

## Example Output Shape

The derived `InoculationPack` includes a stable `pack_id`, preserves the
`minimal_replay_case`, adds computed hashes for the input and replay case, and
recommends a marker:

```json
{
  "artifact_type": "assay.inoculation_pack",
  "schema_version": "0.1",
  "failure_class": "unsafe_tool_call_attempt",
  "trigger_shape": "unsafe tool call attempt: delete production records",
  "recommended_markers": [
    {
      "marker_type": "unsafe_tool_call_attempt",
      "recommended_guardian_action": "block",
      "authority_delta": -3,
      "expires_after": "90d",
      "rollback_pointer": "policy_v12"
    }
  ]
}
```

The derived `EpigeneticMarker` binds that caution to the source pack:

```json
{
  "artifact_type": "assay.epigenetic_marker",
  "schema_version": "0.1",
  "marker_type": "unsafe_tool_call_attempt",
  "recommended_guardian_action": "block",
  "authority_delta": -3,
  "confidence": 0.8,
  "expires_after": "90d",
  "rollback_pointer": "policy_v12"
}
```

## CLI

```bash
assay immunity derive tests/assay/fixtures/immunity/unsafe_tool_call_attempt.json --json
```

By default, outputs are written under:

```text
artifacts/immunity/
artifacts/immunity/markers/
```

You can choose another location:

```bash
assay immunity derive failure.json --out-dir /tmp/immunity --json
```

The command also accepts a proof-pack directory with a `pack_manifest.json`.
For directory input, v0 derives a normalized failure artifact from the manifest,
optional `verify_report.json`, and file hashes.

Directory paths are not part of the derived identity. Moving or copying the
same proof-pack bytes should produce the same `InoculationPack` and marker IDs.

## Verify

`assay immunity verify` closes the artifact loop. It accepts either an
`InoculationPack` JSON file or an `EpigeneticMarker` JSON file and checks:

- JSON schema
- required fields
- caution-only guardian action semantics
- `authority_delta <= 0`
- absence of authority-grant fields
- evidence-hash presence
- rollback and expiration metadata
- safety of pack `recommended_markers`
- `pack_id` / `marker_id` recomputation from canonical identity fields

If `expires_at` is present and already in the past, verification rejects the
artifact as stale.

```bash
assay immunity verify artifacts/immunity/inoculation_pack_ipack_abc123.json --json
assay immunity verify artifacts/immunity/markers/emarker_def456.json --json
```

`verify` can also bind-check an `InoculationPack` against its source proof
pack:

```bash
assay immunity verify artifacts/immunity/inoculation_pack_ipack_abc123.json \
  --source-pack tests/contracts/vectors/semantic/claim_insufficient \
  --json
```

With `--source-pack`, v0 checks:

- `source_proof_pack_id` matches the source `pack_manifest.json`
- `source_failure_id` matches the source-derived failure identity
- source evidence hashes still match current source files
- `verify_report.json` hash matches when present
- the `InoculationPack` `pack_id` matches the source-derived canonical pack

Source binding is only available for `InoculationPack` artifacts. An
`EpigeneticMarker` points to an immunity pack, not directly to the source proof
pack.

Exit codes:

- `0`: valid immunity artifact
- `1`: invalid or stale immunity artifact
- `3`: bad input (malformed JSON, wrong path shape)

## Signal Export

`assay immunity signal` exports a source-bound caution signal from a verified
`InoculationPack` and its matching `EpigeneticMarker`:

```bash
assay immunity signal artifacts/immunity/inoculation_pack_ipack_abc123.json \
  --marker artifacts/immunity/markers/emarker_def456.json \
  --source-pack tests/contracts/vectors/semantic/claim_insufficient \
  --json
```

The output is a caution-only JSON signal for future Guardian or Receiptor
consumers:

```json
{
  "signal_type": "assay.guardian_caution_signal",
  "recommended_action": "require_stronger_proof",
  "authority_delta": -1,
  "may_increase_authority": false,
  "source_bound": true
}
```

This is still not runtime integration. It is an exportable signal that downstream
systems can choose to consume later.

## Python API

```python
from assay.immunity import (
    derive_epigenetic_markers,
    derive_inoculation_pack,
    validate_marker_safety,
)

pack = derive_inoculation_pack(failure_artifact)
markers = derive_epigenetic_markers(pack)
for marker in markers:
    validate_marker_safety(marker)
```

## Deterministic Classification

v0 uses simple keyword and error-code rules:

| Signal | Failure class |
|--------|---------------|
| missing or unverifiable evidence | `evidence_gap` |
| dignity floor or Clause-0 near miss | `dignity_boundary_near_miss` |
| receipt hash, lineage, chain, or tamper conflict | `receipt_lineage_conflict` |
| unsafe tool call or destructive requested action | `unsafe_tool_call_attempt` |
| conflicting provider outputs | `provider_disagreement` |
| stale known fact or timestamp/freshness failure | `stale_truth_detected` |
| policy conflict or policy violation | `policy_conflict` |

No LLM classification is used in v0, so tests remain stable.

## Tests

```bash
pytest tests/assay/test_immunity.py -q
```

The tests cover valid derivation, marker derivation, caution-only enforcement,
invalid actions, authority-increasing proposals, deterministic output, missing
required fields, replay preservation, evidence hashes, rollback/expiration
metadata, offline verification, source binding, signal export, and real
proof-pack dogfooding.

## Repo Demo

This repo already contains a real honest-failure proof pack at:

```text
tests/contracts/vectors/semantic/claim_insufficient/
```

That pack is a useful dogfood source because integrity passes while the claim
set fails honestly: the evidence is authentic, but one declared claim is not
satisfied.

Run the full loop:

```bash
assay verify-pack tests/contracts/vectors/semantic/claim_insufficient --json
assay immunity derive tests/contracts/vectors/semantic/claim_insufficient --out-dir artifacts/immunity/claim_insufficient --json
assay immunity verify artifacts/immunity/claim_insufficient/inoculation_pack_<pack-id>.json --source-pack tests/contracts/vectors/semantic/claim_insufficient --json
assay immunity verify artifacts/immunity/claim_insufficient/markers/<marker-id>.json --json
assay immunity signal artifacts/immunity/claim_insufficient/inoculation_pack_<pack-id>.json --marker artifacts/immunity/claim_insufficient/markers/<marker-id>.json --source-pack tests/contracts/vectors/semantic/claim_insufficient --json
```

The second command returns the exact generated file paths in JSON. Use those
paths as the inputs to the `verify` commands.

The result is the Assay-native loop:

```text
real honest-failure proof pack
-> derived InoculationPack
-> derived EpigeneticMarker
-> offline immunity verification
-> source-bound caution signal
```
