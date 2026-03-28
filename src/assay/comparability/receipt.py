"""Comparability receipt emission.

Emits a structured receipt for every comparability verdict — SATISFIED,
DENIED, DOWNGRADED, and UNDETERMINED. Each receipt records what was
compared, what the contract said, and what consequence followed.

Only receipts from real API-backed runs constitute case law (organic
precedent). Receipts from synthetic fixture runs are engine proof
only and should not be cited as precedent.

Receipts are emitted via the standard assay store (emit_receipt),
making them part of the trace and available for proof pack inclusion.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from assay.comparability.types import ConstitutionalDiff

try:
    from assay import __version__ as _assay_version
except Exception:
    _assay_version = "0.0.0"


def emit_comparability_receipt(
    diff: ConstitutionalDiff,
    *,
    source: str = "assay compare",
) -> Dict[str, Any]:
    """Emit a comparability verdict receipt to the current trace.

    Emits for ALL verdicts, not only denials. The full corpus — including
    SATISFIED verdicts — enables analysis of denial patterns, fragile
    fields, and completeness rates.

    Args:
        diff: The constitutional diff to record.
        source: Which command emitted this ("assay compare" or "assay gate compare").

    Returns:
        The receipt dict that was written (includes receipt_id).
    """
    from assay.store import emit_receipt

    # Build minimal, stable receipt payload
    payload: Dict[str, Any] = {
        "contract_id": diff.contract_id,
        "contract_version": diff.contract_version,
        "contract_hash": diff.contract_hash,
        "verdict": diff.verdict.value,
        "exit_code": diff.exit_code,
        "baseline_ref": diff.baseline_ref,
        "candidate_ref": diff.candidate_ref,
        "baseline_label": diff.baseline_label,
        "candidate_label": diff.candidate_label,
        "instrument_continuity": diff.instrument_continuity.value,
        "source": source,
        "engine_version": _assay_version,
    }

    # Mismatches — keep field-level detail for case law
    if diff.mismatches:
        payload["mismatches"] = [
            {
                "field": m.field,
                "severity": m.severity.value,
                "group": m.group.value,
                "rule": m.rule,
                "baseline_value": _safe_value(m.baseline_value),
                "candidate_value": _safe_value(m.candidate_value),
            }
            for m in diff.mismatches
        ]

    # Missing required fields
    missing: list[str] = []
    for comp in (diff.baseline_completeness, diff.candidate_completeness):
        if comp:
            for f in comp.missing_fields:
                if f not in missing:
                    missing.append(f)
    if missing:
        payload["missing_required_fields"] = missing

    # Consequence
    if diff.consequence:
        payload["consequence"] = {
            "claim_status": diff.consequence.claim_status.value,
            "blocked_actions": diff.consequence.blocked_actions,
            "required_actions": diff.consequence.required_actions,
        }

    # Claim under test
    if diff.claim:
        payload["claim"] = {
            "type": diff.claim.claim_type,
            "summary": diff.claim.summary,
        }
        if diff.claim.metric:
            payload["claim"]["metric"] = diff.claim.metric
        if diff.claim.delta is not None:
            payload["claim"]["delta"] = diff.claim.delta

    # Satisfied fields count (for corpus analytics)
    payload["satisfied_count"] = len(diff.satisfied_fields)
    payload["mismatch_count"] = len(diff.mismatches)
    payload["total_contract_fields"] = (
        len(diff.satisfied_fields) + len(diff.mismatches) + len(missing)
    )

    return emit_receipt(
        "comparability_verdict",
        payload,
    )


def _safe_value(v: Any) -> Any:
    """Coerce value to JSON-safe type. Truncate long strings."""
    if v is None:
        return None
    if isinstance(v, (int, float, bool)):
        return v
    s = str(v)
    if len(s) > 200:
        return s[:197] + "..."
    return s
