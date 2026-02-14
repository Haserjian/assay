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
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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
# Threshold gates
# ---------------------------------------------------------------------------

@dataclass
class GateResult:
    """Result of a single threshold gate check."""

    name: str
    threshold: float
    actual: Optional[float] = None
    passed: bool = True
    unit: str = ""       # "pct" or "count"
    skipped: bool = False  # True when data was unavailable


@dataclass
class GateEvaluation:
    """Combined results from all threshold gates."""

    results: List[GateResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(g.passed for g in self.results)

    @property
    def any_failed(self) -> bool:
        return any(not g.passed for g in self.results)

    @staticmethod
    def _json_safe(v: Optional[float]) -> Optional[float]:
        """Convert inf/nan to None for RFC-compliant JSON."""
        if v is None:
            return None
        if math.isinf(v) or math.isnan(v):
            return None
        return v

    def to_dict(self) -> Dict[str, Any]:
        return {
            "all_passed": self.all_passed,
            "results": [
                {
                    "name": g.name,
                    "threshold": self._json_safe(g.threshold),
                    "actual": self._json_safe(g.actual),
                    "passed": g.passed,
                    "unit": g.unit,
                    "skipped": g.skipped,
                }
                for g in self.results
            ],
        }


def _pct_change(a_val: float, b_val: float) -> float:
    """Percentage change from a to b. Returns inf when a is 0 and b > 0."""
    if a_val == 0:
        return float("inf") if b_val > 0 else 0.0
    return ((b_val - a_val) / a_val) * 100


def evaluate_gates(
    result: DiffResult,
    *,
    cost_pct: Optional[float] = None,
    p95_pct: Optional[float] = None,
    errors: Optional[int] = None,
    strict: bool = False,
) -> GateEvaluation:
    """Evaluate threshold gates against a diff result.

    Each gate is only checked if a threshold is provided. When analysis
    data is unavailable the gate is marked as skipped.

    Args:
        result: The diff result to evaluate.
        cost_pct: Max allowed cost increase in percent (e.g. 20 = 20%).
        p95_pct: Max allowed p95 latency increase in percent.
        errors: Max allowed error count in pack B.
        strict: If True, missing data causes gate failure instead of skip.

    Returns:
        GateEvaluation with per-gate results.
    """
    evaluation = GateEvaluation()
    has_analysis = result.a_analysis is not None and result.b_analysis is not None

    def _skip_result(name: str, threshold: float, unit: str) -> GateResult:
        """A gate that cannot be evaluated due to missing data."""
        if strict:
            return GateResult(
                name=name, threshold=threshold, passed=False,
                unit=unit, skipped=True,
            )
        return GateResult(
            name=name, threshold=threshold, passed=True,
            unit=unit, skipped=True,
        )

    if cost_pct is not None:
        if has_analysis:
            pct = _pct_change(result.a_analysis.cost_usd, result.b_analysis.cost_usd)
            if math.isinf(pct):
                passed = math.isinf(cost_pct)
            else:
                passed = pct <= cost_pct
            evaluation.results.append(GateResult(
                name="cost_pct", threshold=cost_pct,
                actual=round(pct, 1) if not math.isinf(pct) else None,
                passed=passed, unit="pct",
            ))
        else:
            evaluation.results.append(_skip_result("cost_pct", cost_pct, "pct"))

    if p95_pct is not None:
        has_latency = (
            has_analysis
            and result.a_analysis.latency_p95 is not None
            and result.b_analysis.latency_p95 is not None
        )
        if has_latency:
            pct = _pct_change(
                float(result.a_analysis.latency_p95),
                float(result.b_analysis.latency_p95),
            )
            if math.isinf(pct):
                passed = math.isinf(p95_pct)
            else:
                passed = pct <= p95_pct
            evaluation.results.append(GateResult(
                name="p95_pct", threshold=p95_pct,
                actual=round(pct, 1) if not math.isinf(pct) else None,
                passed=passed, unit="pct",
            ))
        else:
            evaluation.results.append(_skip_result("p95_pct", p95_pct, "pct"))

    if errors is not None:
        if result.b_analysis is not None:
            b_errors = result.b_analysis.errors
            evaluation.results.append(GateResult(
                name="errors", threshold=float(errors),
                actual=float(b_errors),
                passed=b_errors <= errors, unit="count",
            ))
        else:
            evaluation.results.append(_skip_result("errors", float(errors), "count"))

    return evaluation


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


# ---------------------------------------------------------------------------
# --against-previous: auto-discover baseline pack
# ---------------------------------------------------------------------------

def find_previous_pack(current_pack: Path) -> Optional[Path]:
    """Find the most recent proof pack before *current_pack* in the same
    parent directory.

    Scans for ``proof_pack_*`` directories that contain a
    ``pack_manifest.json``, sorts by modification time, and returns the
    one immediately preceding *current_pack*.
    """
    parent = current_pack.parent
    if not parent.is_dir():
        return None

    current_resolved = current_pack.resolve()
    packs: List[Tuple[float, Path]] = []

    for d in parent.iterdir():
        if not d.is_dir() or not d.name.startswith("proof_pack"):
            continue
        if not (d / "pack_manifest.json").exists():
            continue
        packs.append((d.stat().st_mtime, d))

    if len(packs) < 2:
        return None

    # Sort ascending by mtime
    packs.sort(key=lambda t: t[0])

    # Find current pack's position
    for i, (_, p) in enumerate(packs):
        if p.resolve() == current_resolved:
            return packs[i - 1][1] if i > 0 else None

    # current_pack not found (shouldn't happen) -- return most recent
    return packs[-1][1]


# ---------------------------------------------------------------------------
# --why: receipt-level regression explanation
# ---------------------------------------------------------------------------

@dataclass
class WhyExplanation:
    """Causal explanation for a single regressed claim."""

    claim_id: str
    expected: str
    actual: str
    evidence_receipt_ids: List[str] = field(default_factory=list)
    causal_chains: List[List[Dict[str, Any]]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "expected": self.expected,
            "actual": self.actual,
            "evidence_receipt_ids": self.evidence_receipt_ids,
            "causal_chains": [
                [
                    {
                        "receipt_id": r.get("receipt_id"),
                        "type": r.get("type"),
                        "parent_receipt_id": r.get("parent_receipt_id"),
                    }
                    for r in chain
                ]
                for chain in self.causal_chains
            ],
        }


def _trace_chain(
    receipt_id: str,
    index: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Walk parent_receipt_id chain backward from a receipt."""
    chain: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    current: Optional[str] = receipt_id

    while current and current not in seen:
        seen.add(current)
        receipt = index.get(current)
        if receipt is None:
            break
        chain.append(receipt)
        current = receipt.get("parent_receipt_id")

    return chain


def explain_why(
    diff_result: DiffResult,
    pack_b: Path,
) -> List[WhyExplanation]:
    """Explain regressed claims using receipt-level forensics.

    For each regressed claim:
    1. Reads verify_report.json for expected vs actual.
    2. Identifies evidence receipts (those that caused the mismatch).
    3. Traces parent_receipt_id chains backward from evidence receipts.

    Returns one WhyExplanation per regressed claim (empty list if none).
    """
    regressed = [cd for cd in diff_result.claim_deltas if cd.regressed]
    if not regressed:
        return []

    # Load claim details from pack B's verify report
    claim_details: Dict[str, Dict[str, Any]] = {}
    report_path = pack_b / "verify_report.json"
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        for cr in report.get("claim_verification", {}).get("results", []):
            claim_details[cr["claim_id"]] = cr

    # Load receipts from pack B and index by ID
    receipts: List[Dict[str, Any]] = []
    try:
        receipts = load_pack_receipts(pack_b)
    except FileNotFoundError:
        pass
    receipt_index = {
        r["receipt_id"]: r for r in receipts if r.get("receipt_id")
    }

    explanations: List[WhyExplanation] = []
    for cd in regressed:
        detail = claim_details.get(cd.claim_id, {})
        evidence_ids: List[str] = detail.get("evidence_receipt_ids", [])

        # Trace causal chains for evidence receipts
        chains: List[List[Dict[str, Any]]] = []
        for rid in evidence_ids:
            chain = _trace_chain(rid, receipt_index)
            if chain:
                chains.append(chain)

        explanations.append(WhyExplanation(
            claim_id=cd.claim_id,
            expected=detail.get("expected", ""),
            actual=detail.get("actual", ""),
            evidence_receipt_ids=evidence_ids,
            causal_chains=chains,
        ))

    return explanations
