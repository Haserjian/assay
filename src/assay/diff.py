"""Diff two Assay proof packs.

Compares receipts, claims, cost, latency, model mix, and integrity
status between two packs. Pack A is baseline, Pack B is current.

Exit codes:
  0  No regression
  1  Regression detected (claims regressed or thresholds exceeded)
  2  Integrity failure (one or both packs tampered)
  3  Bad input (missing files, not directories)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from assay.analyze import AnalysisResult, analyze_receipts, load_pack_receipts


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ClaimDelta:
    """Change in a single claim between two packs."""

    claim_id: str
    a_passed: Optional[bool]  # None = absent from pack A
    b_passed: Optional[bool]  # None = absent from pack B
    regressed: bool = False   # was pass, now fail

    @property
    def status(self) -> str:
        if self.a_passed is None:
            return "new"
        if self.b_passed is None:
            return "removed"
        if self.regressed:
            return "regressed"
        if self.a_passed == self.b_passed:
            return "unchanged"
        return "improved"  # was fail, now pass


@dataclass
class ModelDelta:
    """Change in a model's usage between two packs."""

    model_id: str
    a_calls: int = 0
    b_calls: int = 0
    a_cost: float = 0.0
    b_cost: float = 0.0

    @property
    def status(self) -> str:
        if self.a_calls == 0:
            return "added"
        if self.b_calls == 0:
            return "removed"
        return "changed"

    @property
    def calls_delta(self) -> int:
        return self.b_calls - self.a_calls

    @property
    def cost_delta(self) -> float:
        return self.b_cost - self.a_cost


@dataclass
class PackInfo:
    """Metadata extracted from a pack manifest."""

    path: str
    pack_id: str = ""
    integrity: str = ""  # "PASS" or "FAIL"
    claim_check: str = ""  # "PASS", "FAIL", or "N/A"
    claim_set_hash: str = ""
    signer_id: str = ""
    signer_fingerprint: str = ""
    verifier_version: str = ""
    n_receipts: int = 0
    timestamp_start: str = ""
    timestamp_end: str = ""
    claim_results: Dict[str, bool] = field(default_factory=dict)


@dataclass
class DiffResult:
    """Full diff between two packs."""

    pack_a: PackInfo
    pack_b: PackInfo

    # Preflight
    both_valid: bool = True
    integrity_errors: List[str] = field(default_factory=list)
    same_claim_set: bool = True
    signer_changed: bool = False
    version_changed: bool = False

    # Claims
    claim_deltas: List[ClaimDelta] = field(default_factory=list)
    has_regression: bool = False

    # Analysis
    a_analysis: Optional[AnalysisResult] = None
    b_analysis: Optional[AnalysisResult] = None

    # Model churn
    model_deltas: List[ModelDelta] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "pack_a": {
                "path": self.pack_a.path,
                "pack_id": self.pack_a.pack_id,
                "integrity": self.pack_a.integrity,
                "claim_check": self.pack_a.claim_check,
                "signer_id": self.pack_a.signer_id,
                "verifier_version": self.pack_a.verifier_version,
                "n_receipts": self.pack_a.n_receipts,
            },
            "pack_b": {
                "path": self.pack_b.path,
                "pack_id": self.pack_b.pack_id,
                "integrity": self.pack_b.integrity,
                "claim_check": self.pack_b.claim_check,
                "signer_id": self.pack_b.signer_id,
                "verifier_version": self.pack_b.verifier_version,
                "n_receipts": self.pack_b.n_receipts,
            },
            "preflight": {
                "both_valid": self.both_valid,
                "same_claim_set": self.same_claim_set,
                "signer_changed": self.signer_changed,
                "version_changed": self.version_changed,
                "integrity_errors": self.integrity_errors,
            },
            "has_regression": self.has_regression,
            "claims": [
                {
                    "claim_id": cd.claim_id,
                    "a_passed": cd.a_passed,
                    "b_passed": cd.b_passed,
                    "status": cd.status,
                }
                for cd in self.claim_deltas
            ],
        }
        if self.a_analysis and self.b_analysis:
            a = self.a_analysis
            b = self.b_analysis
            d["summary"] = {
                "model_calls": {"a": a.model_calls, "b": b.model_calls, "delta": b.model_calls - a.model_calls},
                "total_tokens": {"a": a.total_tokens, "b": b.total_tokens, "delta": b.total_tokens - a.total_tokens},
                "cost_usd": {"a": round(a.cost_usd, 4), "b": round(b.cost_usd, 4), "delta": round(b.cost_usd - a.cost_usd, 4)},
                "errors": {"a": a.errors, "b": b.errors, "delta": b.errors - a.errors},
            }
            if a.latencies and b.latencies:
                d["latency_ms"] = {
                    "p50": {"a": a.latency_p50, "b": b.latency_p50, "delta": (b.latency_p50 or 0) - (a.latency_p50 or 0)},
                    "p95": {"a": a.latency_p95, "b": b.latency_p95, "delta": (b.latency_p95 or 0) - (a.latency_p95 or 0)},
                }
        if self.model_deltas:
            d["models"] = [
                {
                    "model_id": md.model_id,
                    "status": md.status,
                    "a_calls": md.a_calls,
                    "b_calls": md.b_calls,
                    "calls_delta": md.calls_delta,
                    "cost_delta": round(md.cost_delta, 4),
                }
                for md in self.model_deltas
            ]
        return d

    @property
    def exit_code(self) -> int:
        if not self.both_valid:
            return 2
        if self.has_regression:
            return 1
        return 0


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def _load_pack_info(pack_dir: Path) -> PackInfo:
    """Extract metadata from a pack's manifest and verify report."""
    info = PackInfo(path=str(pack_dir))

    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        return info

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    att = manifest.get("attestation", {})

    info.pack_id = att.get("pack_id", "")
    info.integrity = att.get("receipt_integrity", "")
    info.claim_check = att.get("claim_check", "N/A")
    info.claim_set_hash = manifest.get("claim_set_hash", "")
    info.signer_id = manifest.get("signer_id", "")
    info.signer_fingerprint = manifest.get("signer_pubkey_sha256", "")
    info.verifier_version = att.get("verifier_version", "")
    info.n_receipts = att.get("n_receipts", 0)
    info.timestamp_start = att.get("timestamp_start", "")
    info.timestamp_end = att.get("timestamp_end", "")

    # Load per-claim results from verify_report.json
    report_path = pack_dir / "verify_report.json"
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        cv = report.get("claim_verification", {})
        for cr in cv.get("results", []):
            info.claim_results[cr["claim_id"]] = cr["passed"]

    return info


def _verify_pack_integrity(pack_dir: Path) -> Tuple[bool, List[str]]:
    """Quick integrity check on a pack. Returns (passed, errors)."""
    errors: List[str] = []
    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        return False, [f"No pack_manifest.json in {pack_dir}"]

    try:
        from assay.integrity import verify_pack_manifest
        from assay.keystore import get_default_keystore

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ks = get_default_keystore()
        result = verify_pack_manifest(manifest, pack_dir, ks)
        if not result.passed:
            for e in result.errors:
                errors.append(f"{pack_dir.name}: {e.message}")
            return False, errors
        return True, []
    except Exception as e:
        return False, [f"{pack_dir.name}: verification error: {e}"]


def diff_packs(pack_a: Path, pack_b: Path, *, verify: bool = True) -> DiffResult:
    """Diff two proof packs.

    Args:
        pack_a: Baseline pack directory.
        pack_b: Current pack directory.
        verify: If True, verify integrity of both packs before diffing.

    Returns:
        DiffResult with all deltas.
    """
    info_a = _load_pack_info(pack_a)
    info_b = _load_pack_info(pack_b)
    result = DiffResult(pack_a=info_a, pack_b=info_b)

    # Preflight: integrity
    if verify:
        a_ok, a_errs = _verify_pack_integrity(pack_a)
        b_ok, b_errs = _verify_pack_integrity(pack_b)
        if not a_ok or not b_ok:
            result.both_valid = False
            result.integrity_errors = a_errs + b_errs
            return result

    # Preflight: comparability
    result.same_claim_set = (
        info_a.claim_set_hash == info_b.claim_set_hash
        and info_a.claim_set_hash != ""
    )
    result.signer_changed = (
        info_a.signer_fingerprint != info_b.signer_fingerprint
        and info_a.signer_fingerprint != ""
        and info_b.signer_fingerprint != ""
    )
    result.version_changed = (
        info_a.verifier_version != info_b.verifier_version
        and info_a.verifier_version != ""
        and info_b.verifier_version != ""
    )

    # Claims comparison
    all_claim_ids = sorted(set(info_a.claim_results) | set(info_b.claim_results))
    for cid in all_claim_ids:
        a_passed = info_a.claim_results.get(cid)
        b_passed = info_b.claim_results.get(cid)
        regressed = (a_passed is True and b_passed is False)
        result.claim_deltas.append(ClaimDelta(
            claim_id=cid,
            a_passed=a_passed,
            b_passed=b_passed,
            regressed=regressed,
        ))
        if regressed:
            result.has_regression = True

    # Receipt analysis
    try:
        receipts_a = load_pack_receipts(pack_a)
        receipts_b = load_pack_receipts(pack_b)
    except FileNotFoundError:
        return result

    result.a_analysis = analyze_receipts(receipts_a)
    result.b_analysis = analyze_receipts(receipts_b)

    # Model deltas
    all_models = sorted(
        set(result.a_analysis.by_model) | set(result.b_analysis.by_model)
    )
    for model_id in all_models:
        a_bucket = result.a_analysis.by_model.get(model_id, {})
        b_bucket = result.b_analysis.by_model.get(model_id, {})
        result.model_deltas.append(ModelDelta(
            model_id=model_id,
            a_calls=a_bucket.get("calls", 0),
            b_calls=b_bucket.get("calls", 0),
            a_cost=a_bucket.get("cost_usd", 0.0),
            b_cost=b_bucket.get("cost_usd", 0.0),
        ))

    return result
