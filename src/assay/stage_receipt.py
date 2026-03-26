"""Structured stage receipts for verification audit traces.

Each verification run emits an ordered list of stage receipts showing
what was checked, in what order, and what each step found.

Stage topology matches PACK_CONTRACT §14. Stage receipts are
informational (not normative across implementations), but stage
names should align with the shared vocabulary for interoperability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class StageReceipt:
    """One stage of a verification run."""

    stage: str
    status: str  # "ok" | "fail" | "skipped"
    code: Optional[str] = None
    reason: Optional[str] = None
    detail: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"stage": self.stage, "status": self.status}
        if self.code is not None:
            d["code"] = self.code
        if self.reason is not None:
            d["reason"] = self.reason
        if self.detail is not None:
            d["detail"] = self.detail
        return d


class StageCollector:
    """Accumulates stage receipts during a verification run."""

    def __init__(self) -> None:
        self._stages: List[StageReceipt] = []

    def record(
        self,
        stage: str,
        ok: bool,
        *,
        code: Optional[str] = None,
        reason: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._stages.append(StageReceipt(
            stage=stage,
            status="ok" if ok else "fail",
            code=code,
            reason=reason,
            detail=detail,
        ))

    @property
    def stages(self) -> List[StageReceipt]:
        return list(self._stages)
