"""Canonical Merkle helpers for receipts.

Centralized implementation ensures a single deterministic algorithm used
across AnchorService, EvidenceReceipt, and tests.

Algorithm notes:
- Leaves are hex-encoded strings (32-byte SHA-256 hex output).
- Leaf bytes are computed with bytes.fromhex(leaf_hex)
- Internal node hash = SHA256(left_bytes || right_bytes)
- When an odd node remains, duplicate the last node (left==right) for pairing.
"""
from __future__ import annotations

from typing import List
import hashlib


def compute_merkle_root(leaves: List[str]) -> str:
    """Compute Merkle root from ordered hex leaves (deterministic).

    Returns hex string of SHA-256 root.
    """
    if not leaves:
        return hashlib.sha256(b"").hexdigest()

    current = [bytes.fromhex(h) for h in leaves]

    while len(current) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(hashlib.sha256(left + right).digest())
        current = next_level

    return current[0].hex()


def generate_inclusion_proof(leaves: List[str], idx: int) -> List[str]:
    """Generate inclusion proof for a single leaf index.

    Returns a list of sibling node hex strings (bottom-up order).
    """
    current = [bytes.fromhex(h) for h in leaves]
    proof: List[str] = []
    index = idx

    while len(current) > 1:
        sibling_index = index ^ 1
        if sibling_index < len(current):
            proof.append(current[sibling_index].hex())
        else:
            proof.append(current[index].hex())

        # build next level
        next_level: List[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            next_level.append(hashlib.sha256(left + right).digest())

        current = next_level
        index = index // 2

    return proof


def verify_merkle_inclusion(leaf: str, proof: List[str], root: str, index: int = 0) -> bool:
    """Verify a leaf inclusion proof against the given root."""
    cur = bytes.fromhex(leaf)
    idx = index
    for node_hex in proof:
        node = bytes.fromhex(node_hex)
        if idx % 2 == 0:
            combined = cur + node
        else:
            combined = node + cur
        cur = hashlib.sha256(combined).digest()
        idx = idx // 2

    return cur.hex() == root


def compute_merkle_leaf_from_value(value_hex: str) -> str:
    """Convenience helper: produce a leaf hash from a hex-encoded value.

    This is the canonical leaf encoding used for receipts (e.g. SHA256 over
    dna payload encoded as hex). We hash the provided hex-decoded bytes to
    produce the leaf digest.
    """
    return hashlib.sha256(bytes.fromhex(value_hex)).hexdigest()


__all__ = [
    "compute_merkle_root",
    "generate_inclusion_proof",
    "verify_merkle_inclusion",
    "compute_merkle_leaf_from_value",
]
