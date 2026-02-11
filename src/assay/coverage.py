"""Coverage Contract: bridges scan results to runtime receipts.

The contract records which call sites the scanner found, assigns each
a stable callsite_id, and provides verification that runtime receipts
cover those sites.

Flow:
  1. assay scan --emit-contract assay.coverage.json  (writes contract)
  2. Integration patches tag receipts with callsite_id  (runtime)
  3. verify_coverage() matches receipt IDs against contract  (check)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay._receipts.canonicalize import to_jcs_bytes


def compute_callsite_id(path: str, line: int) -> str:
    """Stable callsite identifier from file path and line number.

    Both the scanner (AST) and runtime (inspect.stack) can produce
    the same path:line pair, making this the stable join key.

    Returns first 12 hex chars of SHA-256.
    """
    material = f"{path}:{line}"
    return hashlib.sha256(material.encode()).hexdigest()[:12]


@dataclass
class ContractSite:
    """A single call site in the coverage contract."""

    callsite_id: str
    path: str
    line: int
    call: str
    confidence: str  # "high" or "medium" (LOW excluded by default)
    instrumented: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "callsite_id": self.callsite_id,
            "path": self.path,
            "line": self.line,
            "call": self.call,
            "confidence": self.confidence,
            "instrumented": self.instrumented,
        }


@dataclass
class CoverageContract:
    """Coverage contract generated from scan results."""

    call_sites: List[ContractSite] = field(default_factory=list)
    generated_at: str = ""
    project_root: str = "."

    @classmethod
    def from_scan_result(
        cls,
        result: Any,
        *,
        include_low: bool = False,
        project_root: str = ".",
    ) -> CoverageContract:
        """Build a coverage contract from scanner output.

        By default, only HIGH and MEDIUM confidence sites are included.
        LOW confidence sites are excluded from the contract denominator
        because they are heuristic matches with high false-positive rates.
        """
        from assay.scanner import Confidence

        sites: List[ContractSite] = []
        for finding in result.findings:
            if not include_low and finding.confidence == Confidence.LOW:
                continue
            cid = compute_callsite_id(finding.path, finding.line)
            sites.append(ContractSite(
                callsite_id=cid,
                path=finding.path,
                line=finding.line,
                call=finding.call,
                confidence=finding.confidence.value,
                instrumented=finding.instrumented,
            ))

        return cls(
            call_sites=sites,
            generated_at=datetime.now(timezone.utc).isoformat(),
            project_root=project_root,
        )

    @property
    def contract_hash(self) -> str:
        """Deterministic hash of the contract's call sites."""
        sites_data = [s.to_dict() for s in self.call_sites]
        return hashlib.sha256(to_jcs_bytes(sites_data)).hexdigest()

    @property
    def summary(self) -> Dict[str, int]:
        total = len(self.call_sites)
        high = sum(1 for s in self.call_sites if s.confidence == "high")
        medium = sum(1 for s in self.call_sites if s.confidence == "medium")
        low = sum(1 for s in self.call_sites if s.confidence == "low")
        return {
            "total_sites": total,
            "high": high,
            "medium": medium,
            "low": low,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_version": "1.0",
            "generated_at": self.generated_at,
            "generated_by": "assay-scan",
            "project_root": self.project_root,
            "call_sites": [s.to_dict() for s in self.call_sites],
            "summary": self.summary,
            "contract_hash": self.contract_hash,
        }

    def write(self, path: Path) -> None:
        """Write contract to a JSON file."""
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n")

    @classmethod
    def load(cls, path: Path) -> CoverageContract:
        """Load a contract from a JSON file.

        Validates the stored contract_hash against the recomputed hash
        to detect tampering.
        """
        data = json.loads(path.read_text())
        sites = [
            ContractSite(
                callsite_id=s["callsite_id"],
                path=s["path"],
                line=s["line"],
                call=s["call"],
                confidence=s["confidence"],
                instrumented=s["instrumented"],
            )
            for s in data.get("call_sites", [])
        ]
        contract = cls(
            call_sites=sites,
            generated_at=data.get("generated_at", ""),
            project_root=data.get("project_root", "."),
        )
        stored_hash = data.get("contract_hash", "")
        if stored_hash and stored_hash != contract.contract_hash:
            raise ValueError(
                f"Coverage contract tampered: stored hash {stored_hash[:16]}... "
                f"!= computed {contract.contract_hash[:16]}..."
            )
        return contract


def verify_coverage(
    contract: CoverageContract,
    receipts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Match receipt callsite_ids against contract sites.

    Returns coverage analysis dict with:
      covered_ids: callsite_ids found in both contract and receipts
      uncovered_ids: callsite_ids in contract but not in receipts
      extra_ids: callsite_ids in receipts but not in contract
      coverage_pct: len(covered) / len(contract sites)
      covered_count: number of covered sites
      total_count: total contract sites
    """
    contract_ids = {s.callsite_id for s in contract.call_sites}
    receipt_ids: set[str] = set()
    for r in receipts:
        cid = r.get("callsite_id")
        if cid:
            receipt_ids.add(cid)

    covered = contract_ids & receipt_ids
    uncovered = contract_ids - receipt_ids
    extra = receipt_ids - contract_ids

    total = len(contract_ids)
    pct = len(covered) / total if total > 0 else 1.0

    return {
        "covered_ids": sorted(covered),
        "uncovered_ids": sorted(uncovered),
        "extra_ids": sorted(extra),
        "coverage_pct": pct,
        "covered_count": len(covered),
        "total_count": total,
    }


__all__ = [
    "compute_callsite_id",
    "ContractSite",
    "CoverageContract",
    "verify_coverage",
]
