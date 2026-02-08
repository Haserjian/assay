"""
Assay: Receipt-native AI safety toolkit.

Thin wrapper (~400 lines) over CCIO infrastructure for:
- Validating tool calls against policy
- Emitting structured receipts (not just logs)
- Surfacing blockages (incompleteness, contradiction, paradox)
- Health checks (grace window detection)

Ship first, refine later.
"""

__version__ = "1.1.0"

from .guardian import GuardianVerdict, no_coherence_by_dignity_debt
from .health import GraceConfig, is_grace_window
from .store import AssayStore, get_default_store, emit_receipt
from .bridge import BridgeConfig, ReceiptBridge

__all__ = [
    "__version__",
    "GuardianVerdict",
    "no_coherence_by_dignity_debt",
    "GraceConfig",
    "is_grace_window",
    "AssayStore",
    "get_default_store",
    "emit_receipt",
    "BridgeConfig",
    "ReceiptBridge",
]
