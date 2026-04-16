"""Reviewer Packet v0.1 -- buyer-facing evidence packet projection layer.

Minimal dataclasses for the reviewer-ready evidence packet.
This is the shape a skeptical buyer reads.

Architecture law: This is a projection layer for commercial reviewability,
not an independent source of truth. Canonical evidence remains the proof
pack and the settlement-based reviewer-packet path in
reviewer_packet_compile.py / reviewer_packet_verify.py. This module
defines a lightweight buyer-facing *view* of that evidence for demo,
outbound, and first-contact scenarios.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

AUTHORITY_CLASSES = frozenset({
    "machine_evidenced",
    "human_attested",
    "mixed",
    "insufficient",
})

ANSWER_STATUSES = frozenset({
    "ANSWERED",
    "INSUFFICIENT_EVIDENCE",
    "NOT_APPLICABLE",
})


@dataclass
class EvidenceRef:
    """Pointer to a specific piece of evidence in the proof pack."""

    receipt_id: str
    receipt_type: str
    authority_class: str  # machine_evidenced | human_attested
    description: str
    artifact_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "receipt_type": self.receipt_type,
            "authority_class": self.authority_class,
            "description": self.description,
        }
        if self.artifact_path is not None:
            d["artifact_path"] = self.artifact_path
        return d


@dataclass
class QuestionAnswer:
    """One question-answer pair in the reviewer questionnaire."""

    question_id: str
    question_text: str
    status: str  # ANSWERED | INSUFFICIENT_EVIDENCE | NOT_APPLICABLE
    authority_class: str  # machine_evidenced | human_attested | mixed | insufficient
    evidence_refs: List[EvidenceRef] = field(default_factory=list)
    answer_text: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "question_id": self.question_id,
            "question_text": self.question_text,
            "status": self.status,
            "authority_class": self.authority_class,
            "evidence_refs": [r.to_dict() for r in self.evidence_refs],
        }
        if self.answer_text is not None:
            d["answer_text"] = self.answer_text
        if self.notes is not None:
            d["notes"] = self.notes
        return d


@dataclass
class ReviewerPacket:
    """The top-level reviewer-facing evidence packet."""

    packet_id: str
    workflow_name: str
    workflow_description: str
    questions: List[QuestionAnswer]
    proof_pack_path: str
    proof_pack_id: str
    proof_pack_verified: bool
    signer_id: str
    signer_fingerprint: str
    generated_at: str

    @property
    def answered_count(self) -> int:
        return sum(1 for q in self.questions if q.status == "ANSWERED")

    @property
    def unresolved_count(self) -> int:
        return sum(1 for q in self.questions if q.status == "INSUFFICIENT_EVIDENCE")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "schema_version": "0.1.0",
            "workflow_name": self.workflow_name,
            "workflow_description": self.workflow_description,
            "questions": [q.to_dict() for q in self.questions],
            "proof_pack_path": self.proof_pack_path,
            "proof_pack_id": self.proof_pack_id,
            "proof_pack_verified": self.proof_pack_verified,
            "signer_id": self.signer_id,
            "signer_fingerprint": self.signer_fingerprint,
            "generated_at": self.generated_at,
            "summary": {
                "total_questions": len(self.questions),
                "answered": self.answered_count,
                "unresolved": self.unresolved_count,
                "authority_breakdown": self._authority_breakdown(),
            },
        }

    def _authority_breakdown(self) -> Dict[str, int]:
        breakdown: Dict[str, int] = {}
        for q in self.questions:
            breakdown[q.authority_class] = breakdown.get(q.authority_class, 0) + 1
        return breakdown

    def write(self, out_dir: Path) -> Path:
        """Write packet artifacts to out_dir. Returns out_dir."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        packet_dict = self.to_dict()

        # packet.json — the canonical packet
        (out_dir / "packet.json").write_text(
            json.dumps(packet_dict, indent=2), encoding="utf-8"
        )

        # questionnaire_answers.json — just the Q&A pairs
        (out_dir / "questionnaire_answers.json").write_text(
            json.dumps(packet_dict["questions"], indent=2), encoding="utf-8"
        )

        # evidence_index.json — receipt_id -> evidence ref mapping
        # A receipt can be referenced by multiple questions, so
        # referenced_by is a list to avoid key-collision data loss.
        index: Dict[str, Any] = {}
        for q in self.questions:
            for ref in q.evidence_refs:
                if ref.receipt_id in index:
                    existing = index[ref.receipt_id]
                    if q.question_id not in existing["referenced_by"]:
                        existing["referenced_by"].append(q.question_id)
                else:
                    index[ref.receipt_id] = {
                        "receipt_type": ref.receipt_type,
                        "authority_class": ref.authority_class,
                        "referenced_by": [q.question_id],
                        "description": ref.description,
                    }
        (out_dir / "evidence_index.json").write_text(
            json.dumps(index, indent=2), encoding="utf-8"
        )

        # reviewer_summary.md — human-readable summary
        lines = [
            f"# Reviewer Packet: {self.workflow_name}",
            "",
            f"**Packet ID:** `{self.packet_id}`",
            f"**Generated:** {self.generated_at}",
            f"**Proof Pack:** `{self.proof_pack_id}` (verified: {self.proof_pack_verified})",
            f"**Signer:** `{self.signer_id}` (`{self.signer_fingerprint[:16]}...`)",
            "",
            f"## Summary",
            "",
            f"- **{self.answered_count}** of **{len(self.questions)}** questions answered",
            f"- **{self.unresolved_count}** honestly unresolved",
            "",
            "## Questions",
            "",
        ]
        for q in self.questions:
            status_marker = {
                "ANSWERED": "PASS",
                "INSUFFICIENT_EVIDENCE": "GAP",
                "NOT_APPLICABLE": "N/A",
            }.get(q.status, q.status)
            lines.append(f"### {q.question_id}: {q.question_text}")
            lines.append("")
            lines.append(f"- **Status:** {status_marker}")
            lines.append(f"- **Authority:** {q.authority_class}")
            if q.answer_text:
                lines.append(f"- **Answer:** {q.answer_text}")
            if q.evidence_refs:
                lines.append(f"- **Evidence:** {len(q.evidence_refs)} ref(s)")
                for ref in q.evidence_refs:
                    lines.append(f"  - `{ref.receipt_id}` ({ref.receipt_type}, {ref.authority_class})")
            if q.notes:
                lines.append(f"- **Notes:** {q.notes}")
            lines.append("")

        (out_dir / "reviewer_summary.md").write_text(
            "\n".join(lines), encoding="utf-8"
        )

        return out_dir


__all__ = [
    "ANSWER_STATUSES",
    "AUTHORITY_CLASSES",
    "EvidenceRef",
    "QuestionAnswer",
    "ReviewerPacket",
]
