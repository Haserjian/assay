"""
Assay: Tamper-evident audit trails for AI systems.

- Scan codebases for uninstrumented LLM call sites
- Instrument SDKs (OpenAI, Anthropic, LangChain) with 2-line patches
- Produce signed proof packs (receipts, manifest, Ed25519 signature)
- Verify evidence integrity (exit 0/1/2/3: pass / honest failure / tampered / bad input)
"""

__version__ = "1.5.4"

from .guardian import GuardianVerdict, no_coherence_by_dignity_debt
from .health import GraceConfig, is_grace_window
from .store import AssayStore, get_default_store, emit_receipt

__all__ = [
    "__version__",
    "GuardianVerdict",
    "no_coherence_by_dignity_debt",
    "GraceConfig",
    "is_grace_window",
    "AssayStore",
    "get_default_store",
    "emit_receipt",
]
