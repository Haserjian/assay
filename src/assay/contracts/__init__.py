"""Bundled comparability contracts shipped with the assay-ai package."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

CONTRACTS_DIR = Path(__file__).parent

STOCK_CONTRACT = "judge-comparability-v1"


def resolve_contract_path(contract: Optional[str]) -> str:
    """Resolve a contract argument to a file path.

    Resolution order:
      1. If the path exists on disk, use it directly.
      2. If it matches a bundled contract name (with or without extension), use that.
      3. Fall through and return the original string (caller handles the error).

    When contract is None, defaults to the stock judge-comparability-v1 contract.
    """
    if contract is None:
        contract = STOCK_CONTRACT

    # Direct path
    p = Path(contract)
    if p.exists():
        return str(p)

    # Try as a bundled contract name
    name = contract
    for ext in (".yaml", ".yml", ".json"):
        bundled = CONTRACTS_DIR / f"{name}{ext}"
        if bundled.exists():
            return str(bundled)

    # Try with the name as-is (maybe already has extension)
    bundled = CONTRACTS_DIR / name
    if bundled.exists():
        return str(bundled)

    # Fall through — let the caller's error handling deal with it
    return contract
