"""Shared vocabulary for MCP hostile scenario tests.

Each hostile scenario produces a two-axis verdict:

  EnforcementVerdict — what the enforcement layer did
    CAUGHT           — blocked before reaching the server
    ALLOWED_BY_POLICY — explicitly permitted by a configured policy rule
    GAP              — no current control prevents this; documented absence

  EvidenceVerdict — what the audit trail can claim
    ATTRIBUTABLE     — full provenance available (tool name, arguments hash,
                       invocation ID); any observer can reconstruct the chain
    PARTIAL          — some provenance exists but the causal chain is incomplete
    NONE             — no audit trail; the action is forensically invisible

These are separate axes. A call can be:
  GAP + ATTRIBUTABLE: allowed (no defense) but traceable
  CAUGHT + ATTRIBUTABLE: denied and receipt records why
  GAP + NONE: the worst case; no defense and no trail

Both verdicts are required to fully characterize a hostile scenario.
Neither alone is sufficient.
"""

from __future__ import annotations

from enum import Enum
from typing import List


class EnforcementVerdict(str, Enum):
    CAUGHT = "caught"
    ALLOWED_BY_POLICY = "allowed_by_policy"
    GAP = "gap"


class EvidenceVerdict(str, Enum):
    ATTRIBUTABLE = "attributable"
    PARTIAL = "partial"
    NONE = "none"
