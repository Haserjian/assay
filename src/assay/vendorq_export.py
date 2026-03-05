"""Export helpers for VendorQ answer packets."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay.vendorq_models import VendorQInputError


def _render_markdown(
    answers_payload: Dict[str, Any],
    verify_report: Optional[Dict[str, Any]] = None,
) -> str:
    nav_map: Dict[str, List[Dict[str, Any]]] = {}
    if verify_report is not None:
        for nav in verify_report.get("evidence_navigation", []):
            aid = str(nav.get("answer_id", ""))
            nav_map.setdefault(aid, []).append(nav)

    lines: List[str] = []
    lines.append("# Verifiable Vendor Packet")
    lines.append("")
    lines.append("> Verification scope: this packet verifies that claims are evidence-backed by the referenced packs.")
    lines.append("> It does not independently certify organizational compliance or legal sufficiency.")
    lines.append("")
    lines.append(f"Policy Profile: `{answers_payload.get('policy_profile', 'unknown')}`")
    lines.append(f"Questions Hash: `{answers_payload.get('questions_hash', 'unknown')}`")
    lines.append("")

    for ans in answers_payload.get("answers", []):
        qid = str(ans.get("question_id", ""))
        aid = str(ans.get("answer_id", ""))
        lines.append(f"## {qid}")
        lines.append("")
        lines.append(f"- Status: `{ans.get('status', '')}`")
        lines.append(f"- Claim Type: `{ans.get('claim_type', '')}`")
        lines.append(f"- Answer Mode: `{ans.get('answer_mode', '')}`")
        lines.append(f"- Confidence: `{ans.get('confidence', 0.0)}`")
        lines.append(f"- Answer Bool: `{ans.get('answer_bool', None)}`")
        lines.append(f"- Answer Value: `{ans.get('answer_value', None)}`")
        details = str(ans.get("details", "")).strip()
        lines.append(f"- Details: {details if details else '(none)' }")

        refs = list(ans.get("evidence_refs", []))
        if refs:
            lines.append("- Evidence Refs:")
            for ref in refs:
                pack_id = ref.get("pack_id", "")
                receipt_id = ref.get("receipt_id", "")
                field_path = ref.get("field_path", "")
                lines.append(f"  - `{pack_id}:{receipt_id}` field=`{field_path}`")
        else:
            lines.append("- Evidence Refs: none")

        nav_rows = nav_map.get(aid, [])
        if nav_rows:
            lines.append("- Evidence Navigation Chain:")
            for nav in nav_rows:
                lines.append(
                    f"  - question=`{nav.get('question_id')}` "
                    f"answer=`{nav.get('answer_id')}` "
                    f"pointer=`{nav.get('receipt_pointer')}` "
                    f"digest=`{nav.get('pack_digest')}`"
                )
                lines.append(f"    - verify: `{nav.get('verify_command')}`")
        else:
            # fallback chain from answer refs only
            if refs:
                lines.append("- Evidence Navigation Chain (fallback):")
                for ref in refs:
                    pack_id = ref.get("pack_id", "")
                    receipt_id = ref.get("receipt_id", "")
                    lines.append(
                        f"  - question=`{qid}` answer=`{aid}` pointer=`{pack_id}:{receipt_id}` digest=`unknown`"
                    )
                    lines.append(f"    - verify: `assay verify-pack {pack_id}`")

        lines.append("")

    if answers_payload.get("global_warnings"):
        lines.append("## Global Warnings")
        lines.append("")
        for w in answers_payload["global_warnings"]:
            lines.append(f"- {w}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def export_answers(
    answers_payload: Dict[str, Any],
    fmt: str,
    out_path: Path,
    verify_report: Optional[Dict[str, Any]] = None,
) -> None:
    f = fmt.strip().lower()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if f == "json":
        out_path.write_text(json.dumps(answers_payload, indent=2) + "\n")
        return
    if f == "md":
        out_path.write_text(_render_markdown(answers_payload, verify_report=verify_report), encoding="utf-8")
        return

    raise VendorQInputError(f"unsupported_export_format: {fmt}")
