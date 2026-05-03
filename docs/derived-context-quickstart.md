# Receipted Derived Context Quickstart

Receipted Derived Context treats generated context as evidence-bearing state.
The first native backend is deterministic and local:

```text
local files -> source snapshots -> line chunks -> receipts -> verify
```

No CocoIndex, embeddings, LLM calls, MemoryGraph writes, providers, watchers, or
daemon mode are involved in this flow.

## Commands

Scan a repository path:

```bash
assay derived scan .
```

Preview proposed derived-state changes:

```bash
assay derived plan .
```

Commit the staged plan transactionally:

```bash
assay derived apply .
```

Explain a committed artifact:

```bash
assay derived explain art_91f3c4...
```

Verify a receipt:

```bash
assay derived verify drcpt_f640c9...
```

## Reviewer-Readable Explain Output

Example shape:

```json
{
  "status": "ok",
  "explain": {
    "artifact": {
      "artifact_id": "art_91f3c4...",
      "artifact_type": "source_chunk",
      "source_snapshot_id": "snap_a80d7b...",
      "transform_id": "xfm_78ae13...",
      "output_hash": "sha256:...",
      "receipt_id": "drcpt_f640c9...",
      "derivation_verification_level": "DV1",
      "status": "active"
    },
    "source": {
      "source_type": "local_file",
      "uri": "file://src/example.py"
    },
    "transform": {
      "name": "line_chunker",
      "version": "0.1.0",
      "code_hash": "sha256:...",
      "config_hash": "sha256:...",
      "runtime_hash": "sha256:..."
    },
    "receipt": {
      "kind": "derived.artifact.created",
      "subject_id": "art_91f3c4...",
      "output_hash": "sha256:...",
      "derivation_verification_level": "DV1",
      "metadata": {
        "receipt_schema_version": "1"
      }
    }
  }
}
```

`verify` recomputes deterministic source chunks and checks that the receipt JSON,
receipt ID, committed artifact, transform, source snapshots, input artifacts, and
derivation verification level are internally consistent.

## Trust Boundary

This MVP emits T0 derived-context receipts: JCS-canonical, digest-locked,
structurally verified, and self-attested. They are not T1/Tier 3 evidence until
wrapped by a signed Assay proof-pack or another explicit signing path.

## Backend Boundary

The native backend is the authority-preserving implementation for this MVP.
CocoIndex may later be evaluated as a `DerivedBackend`, but only as a proposal
engine. Assay receipts and committed state remain authority; Guardian controls
commitment.

`DerivedBackend` is a pre-consumer protocol in this slice. The hidden
experimental CLI exercises the native planner/store/verifier path directly; the
first production caller of `DerivedBackend` must be named before claiming wired
backend integration.
