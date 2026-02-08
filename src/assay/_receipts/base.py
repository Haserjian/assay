"""
Minimal base receipt types vendored for assay-ai standalone use.

This is a stripped-down version of receipts.base that provides only the
types needed by the vendored domain receipt modules (blockages, web_tool,
launch_readiness). The full receipts.base lives in the CCIO monorepo.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from assay._receipts.compat.pyd import BaseModel, ConfigDictLike, Field, model_validator


class Domain(str, Enum):
    MLB = "mlb"
    MARKETS = "markets"
    GOVERNANCE = "governance"
    CLINICAL = "clinical"
    LEGACY_PA = "legacy_pa"


def _normalise_utc_millis(dt: datetime) -> datetime:
    """Return a UTC datetime truncated to millisecond precision."""
    if dt.tzinfo is None:
        coerced = dt.replace(tzinfo=timezone.utc)
    else:
        coerced = dt.astimezone(timezone.utc)
    if coerced.microsecond:
        coerced = coerced.replace(microsecond=(coerced.microsecond // 1000) * 1000)
    return coerced


class BaseReceipt(BaseModel):
    """Minimal base receipt for standalone assay-ai domain receipts."""

    model_config = ConfigDictLike(frozen=True, protected_namespaces=(), extra="forbid")

    receipt_id: str
    domain: str = Field(default=Domain.GOVERNANCE.value)
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    schema_version: str = Field(default="3.0")
    receipt_type: str = Field(default="BaseReceipt")

    @model_validator(mode="after")
    def _normalise_timestamps(self) -> "BaseReceipt":
        object.__setattr__(self, "ts", _normalise_utc_millis(self.ts))
        return self

    def model_dump(self, *args: Any, mode: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
        data = super().model_dump(*args, mode=mode, **kwargs)
        return data


__all__ = [
    "BaseReceipt",
    "Domain",
    "_normalise_utc_millis",
]
