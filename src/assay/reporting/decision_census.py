"""Decision Census Report.

This module derives a workflow-wide coverage artifact from an existing compiled
reviewer packet. The first version is intentionally narrow: it reads the packet
surface Assay already produces, reconciles expected vs observed decision-point
emissions, and writes a portable report bundle.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from assay.reviewer_packet_verify import _parse_coverage_matrix, _split_evidence_refs
from assay.vendorq_models import VendorQInputError, load_json, now_utc_iso, write_json

_REQUIRED_FILES = ("SETTLEMENT.json", "SCOPE_MANIFEST.json", "COVERAGE_MATRIX.md")
_OPTIONAL_FILES = ("PACKET_INPUTS.json", "PACKET_MANIFEST.json")

_STATUS_MAP = {
    "EVIDENCED": "emitted",
    "PARTIAL": "uncertain",
    "FAILED": "missing",
    "HUMAN_ATTESTED": "human_attested",
    "OUT_OF_SCOPE": "out_of_scope",
}


def _sha256_short(*parts: str) -> str:
    payload = "||".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _load_packet_bundle(packet_dir: Path) -> Dict[str, Any]:
    if not packet_dir.exists() or not packet_dir.is_dir():
        raise VendorQInputError(f"packet_dir_not_found: {packet_dir}")

    missing = [name for name in _REQUIRED_FILES if not (packet_dir / name).exists()]
    if missing:
        raise VendorQInputError(f"packet_missing_required_file: {', '.join(missing)}")

    settlement = load_json(packet_dir / "SETTLEMENT.json")
    scope_manifest = load_json(packet_dir / "SCOPE_MANIFEST.json")
    coverage_matrix = _parse_coverage_matrix((packet_dir / "COVERAGE_MATRIX.md").read_text(encoding="utf-8"))

    packet_inputs: Dict[str, Any] = {}
    packet_manifest: Dict[str, Any] = {}
    packet_inputs_present = (packet_dir / "PACKET_INPUTS.json").exists()
    packet_manifest_present = (packet_dir / "PACKET_MANIFEST.json").exists()
    if packet_inputs_present:
        packet_inputs = load_json(packet_dir / "PACKET_INPUTS.json")
    if packet_manifest_present:
        packet_manifest = load_json(packet_dir / "PACKET_MANIFEST.json")

    return {
        "packet_dir": packet_dir.resolve(),
        "settlement": settlement,
        "scope_manifest": scope_manifest,
        "coverage_matrix": coverage_matrix,
        "packet_inputs": packet_inputs,
        "packet_manifest": packet_manifest,
        "packet_inputs_present": packet_inputs_present,
        "packet_manifest_present": packet_manifest_present,
    }


def _question_index(packet_inputs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    questions = packet_inputs.get("questions")
    if not isinstance(questions, list):
        return {}
    index: Dict[str, Dict[str, Any]] = {}
    for question in questions:
        if not isinstance(question, dict):
            continue
        prompt = str(question.get("prompt") or "").strip()
        if prompt:
            index[prompt] = question
    return index


def _normalize_status(source_status: str) -> str:
    return _STATUS_MAP.get(source_status, "uncertain")


def _expected_receipt_type(question: Optional[Dict[str, Any]], source_status: str) -> str:
    if question:
        status_rule = str(question.get("status_rule") or "")
        if status_rule == "ALL_EVIDENCE_REQUIRED":
            return "proof_pack_verification"
        if status_rule == "PARTIAL_IF_RATIO_LT_1":
            return "coverage_measurement"
        if status_rule == "HUMAN_ATTESTED":
            return "human_attestation"
        if status_rule == "OUT_OF_SCOPE":
            return "out_of_scope"

    if source_status == "HUMAN_ATTESTED":
        return "human_attestation"
    if source_status in {"EVIDENCED", "PARTIAL", "FAILED"}:
        return "coverage_evidence"
    return "unknown"


def _expected_emission(question: Optional[Dict[str, Any]], source_status: str) -> str:
    if question:
        status_rule = str(question.get("status_rule") or "")
        if status_rule == "ALL_EVIDENCE_REQUIRED":
            return "machine_evidence"
        if status_rule == "PARTIAL_IF_RATIO_LT_1":
            return "coverage_measurement"
        if status_rule == "HUMAN_ATTESTED":
            return "human_attestation"
        if status_rule == "OUT_OF_SCOPE":
            return "none"

    return {
        "EVIDENCED": "machine_evidence",
        "PARTIAL": "coverage_measurement",
        "FAILED": "required_proof",
        "HUMAN_ATTESTED": "human_attestation",
        "OUT_OF_SCOPE": "none",
    }.get(source_status, "unknown")


def _observed_emission(source_status: str) -> Optional[str]:
    return {
        "EVIDENCED": "emitted",
        "PARTIAL": "partial",
        "FAILED": None,
        "HUMAN_ATTESTED": "human_attested",
        "OUT_OF_SCOPE": None,
    }.get(source_status, "uncertain")


def _authorization_source(source_status: str, question: Optional[Dict[str, Any]]) -> str:
    if question:
        status_rule = str(question.get("status_rule") or "")
        if status_rule == "ALL_EVIDENCE_REQUIRED":
            return "machine_evidence"
        if status_rule == "PARTIAL_IF_RATIO_LT_1":
            return "coverage_measurement"
        if status_rule == "HUMAN_ATTESTED":
            return "human_attestation"
        if status_rule == "OUT_OF_SCOPE":
            return "scope_exclusion"

    return {
        "EVIDENCED": "machine_evidence",
        "PARTIAL": "coverage_measurement",
        "FAILED": "missing_authorization",
        "HUMAN_ATTESTED": "human_attestation",
        "OUT_OF_SCOPE": "scope_exclusion",
    }.get(source_status, "unknown")


def _human_crossing(source_status: str, question: Optional[Dict[str, Any]]) -> Optional[bool]:
    if question:
        status_rule = str(question.get("status_rule") or "")
        if status_rule == "HUMAN_ATTESTED":
            return True
        if status_rule in {"ALL_EVIDENCE_REQUIRED", "PARTIAL_IF_RATIO_LT_1", "OUT_OF_SCOPE"}:
            return False
    if source_status == "HUMAN_ATTESTED":
        return True
    if source_status in {"EVIDENCED", "PARTIAL", "FAILED", "OUT_OF_SCOPE"}:
        return False
    return None


def _merge_notes(*notes: Optional[str]) -> str:
    cleaned = [str(note).strip() for note in notes if note and str(note).strip()]
    return " ".join(cleaned)


def _decision_point_id(packet_id: str, label: str, explicit_id: Optional[str] = None) -> str:
    if explicit_id:
        return str(explicit_id)
    return f"dcp_{_sha256_short(packet_id, label)}"


def _build_decision_point(
    *,
    packet_id: str,
    row: Dict[str, str],
    question: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    source_status = str(row.get("Status") or "UNCERTAIN")
    normalized_status = _normalize_status(source_status)
    evidence_refs = _split_evidence_refs(str(row.get("Evidence") or ""))
    label = str(question.get("prompt") if question else row.get("Claim / Question") or "Unnamed decision point")
    decision_point_id = _decision_point_id(packet_id, label, str(question.get("question_id")) if question and question.get("question_id") else None)
    proof_refs = list(evidence_refs)
    notes = _merge_notes(question.get("notes") if question else None, row.get("Notes"))

    return {
        "decision_point_id": decision_point_id,
        "label": label,
        "stage": str(question.get("scope") if question else row.get("Scope") or "unknown"),
        "decision_point_type": _expected_receipt_type(question, source_status),
        "expected_receipt_type": _expected_receipt_type(question, source_status),
        "expected_artifact_type": _expected_emission(question, source_status),
        "expected_emission": _expected_emission(question, source_status),
        "observed_emission": _observed_emission(source_status),
        "observed_receipt_id": None,
        "authorization_source": _authorization_source(source_status, question),
        "human_crossing": _human_crossing(source_status, question),
        "status": normalized_status,
        "source_status": source_status,
        "proof_refs": proof_refs,
        "notes": notes,
    }


def _coverage_summary(decision_points: List[Dict[str, Any]]) -> Dict[str, Any]:
    in_scope = [row for row in decision_points if row["status"] != "out_of_scope"]
    if not in_scope:
        return {
            "expected_count": 0,
            "observed_count": 0,
            "missing_count": 0,
            "coverage_ratio": 0.0,
            "coverage_state": "uncensusable",
            "omission_severity": "none",
        }

    observed_statuses = {"emitted", "human_attested", "uncertain", "refused"}
    expected_count = len(in_scope)
    observed_count = sum(1 for row in in_scope if row["status"] in observed_statuses)
    missing_count = sum(1 for row in in_scope if row["status"] == "missing")
    coverage_ratio = round(observed_count / expected_count, 4) if expected_count else 0.0

    if missing_count:
        coverage_state = "incomplete"
    elif any(row["status"] == "uncertain" for row in in_scope):
        coverage_state = "degraded"
    else:
        coverage_state = "complete"

    if coverage_state == "complete":
        omission_severity = "none"
    elif coverage_state == "degraded":
        omission_severity = "low"
    elif missing_count == 1:
        omission_severity = "medium"
    else:
        omission_severity = "high"

    return {
        "expected_count": expected_count,
        "observed_count": observed_count,
        "missing_count": missing_count,
        "coverage_ratio": coverage_ratio,
        "coverage_state": coverage_state,
        "omission_severity": omission_severity,
    }


def _render_table(rows: Iterable[Dict[str, Any]]) -> str:
    lines = [
        "| Decision Point | Status | Observed Emission | Authorization Source | Proof | Notes |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        proof = "; ".join(row.get("proof_refs") or []) or "None"
        notes = row.get("notes") or ""
        lines.append(
            f"| {row['label']} | {row['status']} | {row.get('observed_emission') or 'None'} | "
            f"{row.get('authorization_source') or 'unknown'} | {proof} | {notes} |"
        )
    return "\n".join(lines)


def _gap_severity(status: str) -> str:
    if status == "missing":
        return "high"
    if status == "uncertain":
        return "medium"
    return "low"


def _gap_probable_cause(row: Dict[str, Any]) -> str:
    source_status = str(row.get("source_status") or "unknown").lower()
    status = str(row.get("status") or "unknown").lower()
    if status == "missing":
        if source_status == "failed":
            return "Declared evidence was not satisfied in the packet."
        return "No emitted evidence was available in the packet surface."
    if status == "uncertain":
        if source_status == "partial":
            return "Coverage was partial in the packet surface."
        if source_status == "human_attested":
            return "The row depends on human attestation rather than a machine-emitted receipt."
        return "Observed evidence is incomplete or degraded."
    return "No remediation needed."


def _gap_remediation_hint(row: Dict[str, Any]) -> str:
    expected_artifact = str(row.get("expected_artifact_type") or "evidence artifact")
    status = str(row.get("status") or "unknown").lower()
    if status == "missing":
        return f"Collect or surface the expected {expected_artifact}."
    if status == "uncertain":
        return f"Complete or tighten the {expected_artifact} path, then rerun the census."
    return "No remediation needed."


def _build_gap_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    status = str(row.get("status") or "").lower()
    if status not in {"missing", "uncertain"}:
        return None

    return {
        "gap_id": f"gap_{_sha256_short(str(row.get('decision_point_id') or ''), status, str(row.get('expected_artifact_type') or ''))}",
        "decision_point_id": row.get("decision_point_id"),
        "decision_point_type": row.get("decision_point_type") or row.get("expected_receipt_type") or "unknown",
        "expected_artifact_type": row.get("expected_artifact_type") or row.get("expected_emission") or "unknown",
        "observed_status": status,
        "severity": _gap_severity(status),
        "probable_cause": _gap_probable_cause(row),
        "remediation_hint": _gap_remediation_hint(row),
        "label": row.get("label"),
        "stage": row.get("stage"),
        "proof_refs": list(row.get("proof_refs") or []),
        "source_status": row.get("source_status"),
    }


def build_decision_gap_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Derive a remediation-focused gap report from a Decision Census report."""
    decision_points = report.get("decision_points", [])
    gap_rows = []
    excluded_out_of_scope = 0

    for row in decision_points:
        if str(row.get("status") or "").lower() == "out_of_scope":
            excluded_out_of_scope += 1
            continue
        gap_row = _build_gap_row(row)
        if gap_row is not None:
            gap_rows.append(gap_row)

    missing_count = sum(1 for row in gap_rows if row["observed_status"] == "missing")
    uncertain_count = sum(1 for row in gap_rows if row["observed_status"] == "uncertain")

    return {
        "gap_report_id": f"dgr_{report['report_id']}",
        "generated_at": now_utc_iso(),
        "source_report_id": report["report_id"],
        "inventory": report.get("inventory", {}),
        "coverage_summary": report.get("coverage_summary", {}),
        "gap_summary": {
            "gap_count": len(gap_rows),
            "missing_count": missing_count,
            "uncertain_count": uncertain_count,
            "excluded_out_of_scope_count": excluded_out_of_scope,
            "remediation_ready": bool(gap_rows),
        },
        "gaps": gap_rows,
        "unsupported_surfaces": report.get("unsupported_surfaces", []),
        "notes": [
            "Gap rows are derived only from missing or uncertain census rows.",
            "Out-of-scope rows are excluded from remediation by design.",
        ],
    }


def render_gap_markdown(gap_report: Dict[str, Any]) -> str:
    """Render a remediation-focused gap report."""
    summary = gap_report.get("gap_summary", {})
    lines = [
        "# Decision Gaps",
        "",
        f"- Gap report ID: `{gap_report['gap_report_id']}`",
        f"- Source report ID: `{gap_report['source_report_id']}`",
        f"- Gap count: **{summary.get('gap_count', 0)}**",
        f"- Missing count: **{summary.get('missing_count', 0)}**",
        f"- Uncertain count: **{summary.get('uncertain_count', 0)}**",
        f"- Out-of-scope excluded: **{summary.get('excluded_out_of_scope_count', 0)}**",
        f"- Remediation ready: **{str(summary.get('remediation_ready', False)).lower()}**",
        "",
        "## Gaps",
        "",
    ]

    gaps = gap_report.get("gaps", [])
    if not gaps:
        lines.append("No remediation gaps detected.")
    else:
        lines.extend([
            "| Decision Point | Observed Status | Severity | Probable Cause | Remediation Hint | Proof |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for row in gaps:
            proof = "; ".join(row.get("proof_refs") or []) or "None"
            lines.append(
                f"| {row.get('label') or row.get('decision_point_id')} | {row.get('observed_status')} | "
                f"{row.get('severity')} | {row.get('probable_cause')} | {row.get('remediation_hint')} | {proof} |"
            )

    if gap_report.get("unsupported_surfaces"):
        lines.extend(["", "## Unsupported Surfaces"])
        for item in gap_report["unsupported_surfaces"]:
            lines.append(f"- {item}")

    if gap_report.get("notes"):
        lines.extend(["", "## Notes"])
        for note in gap_report["notes"]:
            lines.append(f"- {note}")

    return "\n".join(lines).rstrip() + "\n"


def write_gap_report(gap_report: Dict[str, Any], out_dir: Path) -> Dict[str, Any]:
    """Write the Decision Gaps bundle to disk."""
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "DECISION_GAPS.json", gap_report)
    (out_dir / "DECISION_GAPS.md").write_text(render_gap_markdown(gap_report), encoding="utf-8")
    return {
        "output_dir": str(out_dir.resolve()),
        "gap_report_id": gap_report["gap_report_id"],
        "gap_count": gap_report["gap_summary"]["gap_count"],
    }


def build_decision_census_report(packet_dir: Path) -> Dict[str, Any]:
    """Build a Decision Census report dict from a compiled reviewer packet."""
    bundle = _load_packet_bundle(packet_dir)
    settlement = bundle["settlement"]
    scope_manifest = bundle["scope_manifest"]
    packet_inputs = bundle["packet_inputs"]
    question_index = _question_index(packet_inputs)
    packet_id = str(settlement.get("packet_id") or packet_dir.name)

    decision_points: List[Dict[str, Any]] = []
    for row in bundle["coverage_matrix"]:
        question = question_index.get(str(row.get("Claim / Question") or "").strip())
        decision_points.append(
            _build_decision_point(
                packet_id=packet_id,
                row=row,
                question=question,
            )
        )

    coverage_summary = _coverage_summary(decision_points)
    inventory_basis = "packet_inputs+coverage_rows" if bundle["packet_inputs_present"] else "coverage_rows_only"
    proof_refs: List[str] = []
    seen_refs = set()
    for point in decision_points:
        for ref in point.get("proof_refs") or []:
            if ref not in seen_refs:
                seen_refs.add(ref)
                proof_refs.append(ref)

    authorization_counter = Counter(point["authorization_source"] for point in decision_points if point["status"] != "out_of_scope")
    authorization_paths = [
        {"authorization_source": source, "count": count}
        for source, count in sorted(authorization_counter.items(), key=lambda item: (item[0], item[1]))
    ]

    human_crossings = [
        {
            "decision_point_id": point["decision_point_id"],
            "label": point["label"],
            "status": point["status"],
            "proof_refs": point["proof_refs"],
        }
        for point in decision_points
        if point.get("human_crossing") is True
    ]

    unsupported_surfaces = [
        "Row-level receipt IDs are not exposed by the current reviewer packet surfaces.",
    ]
    if not bundle["packet_inputs_present"]:
        unsupported_surfaces.append(
            "PACKET_INPUTS.json is absent, so the expected consequential decision inventory is inferred from the coverage matrix alone."
        )
    if not bundle["packet_manifest_present"]:
        unsupported_surfaces.append(
            "PACKET_MANIFEST.json is absent, so packet-manifest provenance is unavailable to the census layer."
        )

    notes = [
        "Inventory source: reviewer packet questions when available; otherwise coverage rows.",
        "Row-level receipt IDs are not exposed by the current packet surface, so proof refs are used instead.",
    ]
    for note in scope_manifest.get("boundary_notes", []) or []:
        if str(note).strip():
            notes.append(str(note).strip())
    for basis in settlement.get("settlement_basis", []) or []:
        if str(basis).strip():
            notes.append(str(basis).strip())

    report = {
        "report_id": f"dcc_{packet_id}",
        "generated_at": now_utc_iso(),
        "source_packet": {
            "packet_dir": str(bundle["packet_dir"]),
            "packet_id": packet_id,
            "packet_version": settlement.get("packet_version"),
            "settlement_state": settlement.get("settlement_state"),
            "integrity_state": settlement.get("integrity_state"),
            "claim_state": settlement.get("claim_state"),
            "freshness_state": settlement.get("freshness_state"),
            "scope_state": settlement.get("scope_state"),
            "packet_inputs_present": bundle["packet_inputs_present"],
            "packet_manifest_present": bundle["packet_manifest_present"],
        },
        "scope": {
            "workflow_name": scope_manifest.get("workflow_name") or "unknown",
            "workflow_id": packet_id,
            "boundary": scope_manifest.get("repo_or_system_in_scope")
            or scope_manifest.get("workflow_description")
            or "unknown",
            "domain": "other",
            "entrypoints_in_scope": scope_manifest.get("entrypoints_in_scope") or [],
        },
        "inventory": {
            "basis": inventory_basis,
            "questions_present": bundle["packet_inputs_present"],
            "packet_manifest_present": bundle["packet_manifest_present"],
        },
        "coverage_summary": coverage_summary,
        "decision_points": decision_points,
        "authorization_paths": authorization_paths,
        "human_crossings": human_crossings,
        "proof_refs": proof_refs,
        "unsupported_surfaces": unsupported_surfaces,
        "notes": notes,
    }
    return report


def render_markdown(report: Dict[str, Any]) -> str:
    """Render a compact markdown report for humans."""
    scope = report["scope"]
    summary = report["coverage_summary"]

    lines = [
        "# Decision Census Report",
        "",
        f"- Report ID: `{report['report_id']}`",
        f"- Workflow: `{scope['workflow_name']}`",
        f"- Boundary: `{scope['boundary']}`",
        f"- Domain: `{scope['domain']}`",
        f"- Inventory basis: `{report.get('inventory', {}).get('basis', 'unknown')}`",
        f"- Coverage state: **{summary['coverage_state']}**",
        f"- Coverage ratio: **{summary['coverage_ratio']:.2f}**",
        f"- Expected decision points: **{summary['expected_count']}**",
        f"- Observed emissions: **{summary['observed_count']}**",
        f"- Missing emissions: **{summary['missing_count']}**",
        f"- Omission severity: **{summary['omission_severity']}**",
        "",
        "## Coverage Matrix",
        "",
        _render_table(report["decision_points"]),
        "",
        "## Notes",
    ]

    for note in report.get("notes", []):
        lines.append(f"- {note}")

    if report.get("proof_refs"):
        lines.extend(["", "## Proof References"])
        for ref in report["proof_refs"]:
            lines.append(f"- {ref}")

    if report.get("unsupported_surfaces"):
        lines.extend(["", "## Unsupported Surfaces"])
        for item in report["unsupported_surfaces"]:
            lines.append(f"- {item}")

    return "\n".join(lines).rstrip() + "\n"


def render_coverage_matrix(report: Dict[str, Any]) -> str:
    """Render the matrix as its own markdown file."""
    return "# Coverage Matrix\n\n" + _render_table(report["decision_points"]) + "\n"


def write_report(report: Dict[str, Any], out_dir: Path) -> Dict[str, Any]:
    """Write the report bundle to disk."""
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "DECISION_CENSUS.json", report)
    (out_dir / "DECISION_CENSUS.md").write_text(render_markdown(report), encoding="utf-8")
    (out_dir / "COVERAGE_MATRIX.md").write_text(render_coverage_matrix(report), encoding="utf-8")
    gap_report = build_decision_gap_report(report)
    gap_bundle = write_gap_report(gap_report, out_dir)
    return {
        "output_dir": str(out_dir.resolve()),
        "report_id": report["report_id"],
        "coverage_state": report["coverage_summary"]["coverage_state"],
        "coverage_ratio": report["coverage_summary"]["coverage_ratio"],
        "gap_output_dir": gap_bundle["output_dir"],
        "gap_report_id": gap_bundle["gap_report_id"],
        "gap_count": gap_bundle["gap_count"],
    }
