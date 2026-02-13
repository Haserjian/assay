"""
Evidence Pack Generator: Export trace + verification + claim mapping for patent defense.

Produces a self-contained zip with:
- trace.jsonl (the raw receipt chain)
- verify_report.json (integrity verification results)
- merkle_root.json (tamper-evident hash tree)
- claim_map.json (patent claim → code → test mapping)
- build_metadata.json (versions, timestamps, environment)
- README.md (human-readable summary)

Usage:
    assay pack <trace_id> -o evidence_pack.zip
    assay pack <trace_id> --include-source  # Include relevant source files
"""
from __future__ import annotations

import hashlib
import json
import platform
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay import __version__ as assay_version
from assay._receipts.canonicalize import to_jcs_bytes
from assay._receipts.merkle import compute_merkle_root


def get_merkle_root(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute Merkle root for a list of trace entries."""
    if not entries:
        return {
            "root": None,
            "leaf_count": 0,
            "leaf_hashes": [],
            "hash_algorithm": "sha256",
            "canonicalization": "jcs-rfc8785",
        }

    leaf_hashes: List[str] = []
    for entry in entries:
        canonical_bytes = to_jcs_bytes(entry)
        leaf_hashes.append(hashlib.sha256(canonical_bytes).hexdigest())

    root = compute_merkle_root(leaf_hashes)

    return {
        "root": root,
        "leaf_count": len(entries),
        "leaf_hashes": leaf_hashes,
        "hash_algorithm": "sha256",
        "canonicalization": "jcs-rfc8785",
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


# Patent claim to code mapping
CLAIM_MAP = {
    "claim_1": {
        "title": "Audit trail for AI operations",
        "description": "System maintains complete audit trail of all AI model calls",
        "implementation": [
            {
                "file": "src/receipts/domains/model_call.py",
                "class": "ModelCallReceipt",
                "fields": ["model_id", "input_tokens", "output_tokens", "latency_ms", "finish_reason"],
            }
        ],
        "tests": ["tests/receipts/test_patent_receipts.py::TestModelCallReceipt"],
        "invariants": ["total_tokens == input_tokens + output_tokens"],
    },
    "claim_14": {
        "title": "Dignity floor enforcement",
        "description": "Actions blocked when cumulative dignity would fall below floor",
        "implementation": [
            {
                "file": "src/receipts/domains/dignity_budget.py",
                "class": "DignityBudgetRefusalReceipt",
                "fields": ["budget_before", "budget_projected", "budget_floor", "budget_deficit"],
            }
        ],
        "tests": ["tests/receipts/test_patent_receipts.py::TestDignityBudgetRefusalReceipt"],
        "invariants": ["budget_projected < budget_floor", "budget_deficit == budget_floor - budget_projected"],
    },
    "claim_15": {
        "title": "Guardian verdict with dignity facets",
        "description": "Verdicts include matched policies and computed dignity facet scores",
        "implementation": [
            {
                "file": "src/receipts/domains/guardian_verdict.py",
                "class": "GuardianVerdictReceipt",
                "fields": ["verdict", "dignity_composite", "dignity_facet_scores", "matched_policies"],
            },
            {
                "file": "src/receipts/domains/guardian_verdict.py",
                "class": "DignityFacetScore",
                "fields": ["facet", "score", "weight", "reasoning"],
            },
        ],
        "tests": ["tests/receipts/test_patent_receipts.py::TestGuardianVerdictReceipt"],
        "invariants": ["DEFER requires escalation_path", "Cannot ALLOW when dignity_floor_violated"],
    },
    "claim_17": {
        "title": "Capability max_calls tracking",
        "description": "Capability permits track remaining call budget",
        "implementation": [
            {
                "file": "src/receipts/domains/capability_use.py",
                "class": "CapabilityUseReceipt",
                "fields": ["max_calls_original", "calls_before", "calls_after", "calls_remaining"],
            }
        ],
        "tests": ["tests/receipts/test_patent_receipts.py::TestCapabilityUseReceipt"],
        "invariants": [
            "calls_after == calls_before + 1",
            "calls_remaining >= 0 (budget overrun blocked)",
            "calls_remaining required when max_calls_original set",
        ],
    },
}


def get_build_metadata() -> Dict[str, Any]:
    """Collect build and environment metadata."""
    return {
        "assay_version": assay_version,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "assay evidence-pack",
        "canonicalization": "jcs-rfc8785",
        "hash_algorithm": "sha256",
        "assay_root": str(Path(__file__).parent.parent.parent),
    }


def generate_readme(
    trace_id: str,
    entry_count: int,
    merkle_root: str,
    verify_passed: bool,
    build_meta: Dict[str, Any],
) -> str:
    """Generate human-readable README for the evidence pack."""
    status = "PASSED" if verify_passed else "FAILED"
    canonicalization = build_meta.get("canonicalization", "jcs-rfc8785")
    hash_algorithm = build_meta.get("hash_algorithm", "sha256")
    forensic_mode = build_meta.get("forensic_mode", False)
    forensic_note = "enabled" if forensic_mode else "disabled"
    return f"""# Evidence Pack: {trace_id}

Generated: {build_meta['generated_at']}
Generator: Assay {build_meta['assay_version']}
Canonicalization: {canonicalization}
Hash algorithm: {hash_algorithm}
Forensic mode: {forensic_note}

## Contents

| File | Description |
|------|-------------|
| trace.jsonl | Raw receipt chain ({entry_count} entries) |
| verify_report.json | Integrity verification results |
| merkle_root.json | Tamper-evident hash tree |
| claim_map.json | Patent claim → code → test mapping |
| build_metadata.json | Versions, timestamps, environment |
| README.md | This file |

## Verification Status

**{status}**

Merkle Root: `{merkle_root}`

## How to Verify

1. Recompute the Merkle root from trace.jsonl
2. Compare with the root in merkle_root.json
3. If they match, the trace has not been tampered with

```python
import json
import hashlib
from assay._receipts.canonicalize import to_jcs_bytes
from assay._receipts.merkle import compute_merkle_root

def verify_merkle(trace_path, merkle_path):
    with open(trace_path) as f:
        entries = [json.loads(line) for line in f if line.strip()]

    leaf_hashes = [
        hashlib.sha256(to_jcs_bytes(entry)).hexdigest()
        for entry in entries
    ]
    computed_root = compute_merkle_root(leaf_hashes)

    with open(merkle_path) as f:
        merkle = json.load(f)

    return computed_root == merkle['root']
```

## Patent Claims Implemented

See claim_map.json for the full mapping. Summary:

- **Claim 1**: Audit trail for AI operations (ModelCallReceipt)
- **Claim 14**: Dignity floor enforcement (DignityBudgetRefusalReceipt)
- **Claim 15**: Guardian verdict with dignity facets (GuardianVerdictReceipt)
- **Claim 17**: Capability max_calls tracking (CapabilityUseReceipt)

## Legal Notice

This evidence pack is generated for patent defense and audit purposes.
The receipts and metadata herein constitute evidence of reduction to practice.
"""


@dataclass
class EvidencePack:
    """Container for evidence pack generation."""

    trace_id: str
    entries: List[Dict[str, Any]] = field(default_factory=list)
    verify_errors: List[str] = field(default_factory=list)
    verify_warnings: List[str] = field(default_factory=list)
    raw_trace_bytes: Optional[bytes] = field(default=None)

    def load_trace(self, store, preserve_raw: bool = False) -> bool:
        """Load trace entries from store.

        Args:
            store: The AssayStore to load from.
            preserve_raw: If True, also load raw bytes for forensic fidelity.
        """
        self.entries = store.read_trace(self.trace_id)
        if preserve_raw:
            self.raw_trace_bytes = store.read_trace_raw(self.trace_id)
        return len(self.entries) > 0

    def verify(self, require_receipt_id: bool = False) -> bool:
        """Run verification checks on the trace.

        Args:
            require_receipt_id: If True, missing receipt_id is an error. If False, it's a warning.
        """
        self.verify_errors = []
        self.verify_warnings = []

        if not self.entries:
            self.verify_errors.append("Trace is empty")
            return False

        seen_ids = set()
        prev_timestamp: Optional[datetime] = None

        for i, entry in enumerate(self.entries):
            entry_num = i + 1

            # Check for type
            entry_type = entry.get("type") or entry.get("receipt_type")
            if not entry_type:
                self.verify_errors.append(f"Entry {entry_num}: missing type")

            # Check receipt_id presence and uniqueness
            receipt_id = entry.get("receipt_id")
            if receipt_id:
                if receipt_id in seen_ids:
                    self.verify_errors.append(f"Entry {entry_num}: duplicate receipt_id")
                seen_ids.add(receipt_id)
            else:
                # Missing receipt_id - error or warning based on config
                msg = f"Entry {entry_num}: missing receipt_id"
                if require_receipt_id:
                    self.verify_errors.append(msg)
                else:
                    self.verify_warnings.append(msg)

            # Check temporal ordering (parse to datetime for correct comparison)
            timestamp_str = entry.get("_stored_at")
            if timestamp_str:
                try:
                    # Parse ISO format timestamp
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    if prev_timestamp and timestamp < prev_timestamp:
                        self.verify_errors.append(f"Entry {entry_num}: temporal ordering violation")
                    prev_timestamp = timestamp
                except (ValueError, TypeError):
                    self.verify_warnings.append(f"Entry {entry_num}: invalid timestamp format")

        return len(self.verify_errors) == 0

    def get_verify_report(self) -> Dict[str, Any]:
        """Generate verification report."""
        passed = self.verify()
        return {
            "trace_id": self.trace_id,
            "passed": passed,
            "entry_count": len(self.entries),
            "errors": self.verify_errors,
            "warnings": self.verify_warnings,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_merkle(self) -> Dict[str, Any]:
        """Compute Merkle root for the trace."""
        return get_merkle_root(self.entries)

    def export_zip(self, output_path: Path, include_source: bool = False) -> Path:
        """Export the evidence pack as a zip file.

        If raw_trace_bytes is set (via load_trace with preserve_raw=True),
        the original trace bytes are preserved for forensic fidelity.
        Otherwise, entries are re-serialized (canonicalized).
        """
        build_meta = get_build_metadata()
        verify_report = self.get_verify_report()
        merkle = self.get_merkle()

        # Note in metadata whether raw bytes were preserved
        build_meta["forensic_mode"] = self.raw_trace_bytes is not None

        readme = generate_readme(
            trace_id=self.trace_id,
            entry_count=len(self.entries),
            merkle_root=merkle.get("root", "N/A"),
            verify_passed=verify_report["passed"],
            build_meta=build_meta,
        )

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Trace data - use raw bytes if available for forensic fidelity
            if self.raw_trace_bytes is not None:
                zf.writestr("trace.jsonl", self.raw_trace_bytes)
            else:
                # Canonicalized (JCS) trace for deterministic replay
                trace_content = "\n".join(
                    to_jcs_bytes(entry).decode("utf-8") for entry in self.entries
                )
                zf.writestr("trace.jsonl", trace_content)

            # Verification report
            zf.writestr("verify_report.json", json.dumps(verify_report, indent=2))

            # Merkle root
            zf.writestr("merkle_root.json", json.dumps(merkle, indent=2))

            # Claim map
            zf.writestr("claim_map.json", json.dumps(CLAIM_MAP, indent=2))

            # Build metadata
            zf.writestr("build_metadata.json", json.dumps(build_meta, indent=2))

            # README
            zf.writestr("README.md", readme)

            # Optionally include source files
            if include_source:
                assay_root = Path(__file__).parent.parent.parent
                source_files = [
                    "src/receipts/domains/model_call.py",
                    "src/receipts/domains/capability_use.py",
                    "src/receipts/domains/guardian_verdict.py",
                    "src/receipts/domains/dignity_budget.py",
                    "src/receipts/domains/web_tool.py",
                    "src/assay/guardian.py",
                    "src/assay/health.py",
                    "src/assay/store.py",
                    "tests/receipts/test_patent_receipts.py",
                ]
                for src_file in source_files:
                    src_path = assay_root / src_file
                    if src_path.exists():
                        zf.write(src_path, f"source/{src_file}")

        return output_path


def create_evidence_pack(
    trace_id: str,
    output_path: Optional[Path] = None,
    include_source: bool = False,
    preserve_raw: bool = False,
) -> Path:
    """
    Create an evidence pack for a trace.

    Args:
        trace_id: The trace to package
        output_path: Where to write the zip (default: evidence_pack_{trace_id}.zip)
        include_source: Whether to include relevant source files
        preserve_raw: Preserve original trace bytes (forensic fidelity) vs re-serialize

    Returns:
        Path to the created zip file
    """
    from assay.store import get_default_store

    store = get_default_store()
    pack = EvidencePack(trace_id=trace_id)

    if not pack.load_trace(store, preserve_raw=preserve_raw):
        raise ValueError(f"Trace not found: {trace_id}")

    if output_path is None:
        output_path = Path(f"evidence_pack_{trace_id}.zip")

    return pack.export_zip(output_path, include_source=include_source)


__all__ = [
    "EvidencePack",
    "create_evidence_pack",
    "get_merkle_root",
    "get_build_metadata",
    "CLAIM_MAP",
]
