"""
Standalone Ed25519 key management for Assay Proof Packs.

Keys are stored at ~/.assay/keys/{signer_id}.key
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from nacl.signing import SigningKey, VerifyKey


DEFAULT_SIGNER_ID = "assay-local"
ACTIVE_SIGNER_FILE = ".active_signer"


class AssayKeyStore:
    """File-based Ed25519 key store for signing Proof Packs."""

    def __init__(self, keys_dir: Optional[Path] = None):
        if keys_dir is None:
            from assay.store import assay_home
            keys_dir = assay_home() / "keys"
        self.keys_dir = Path(keys_dir)

    def _key_path(self, signer_id: str) -> Path:
        return self.keys_dir / f"{signer_id}.key"

    def _pub_path(self, signer_id: str) -> Path:
        return self.keys_dir / f"{signer_id}.pub"

    def _active_signer_path(self) -> Path:
        return self.keys_dir / ACTIVE_SIGNER_FILE

    def has_key(self, signer_id: str) -> bool:
        return self._key_path(signer_id).exists() and self._pub_path(signer_id).exists()

    def generate_key(self, signer_id: str = DEFAULT_SIGNER_ID) -> SigningKey:
        """Generate and persist a new Ed25519 signing key."""
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        sk = SigningKey.generate()
        self._key_path(signer_id).write_bytes(sk.encode())
        self._pub_path(signer_id).write_bytes(sk.verify_key.encode())
        return sk

    def ensure_key(self, signer_id: str = DEFAULT_SIGNER_ID) -> SigningKey:
        """Return existing key or generate a new one."""
        if self.has_key(signer_id):
            return self.get_signing_key(signer_id)
        return self.generate_key(signer_id)

    def get_signing_key(self, signer_id: str = DEFAULT_SIGNER_ID) -> SigningKey:
        """Load a signing key from disk."""
        key_bytes = self._key_path(signer_id).read_bytes()
        return SigningKey(key_bytes)

    def get_verify_key(self, signer_id: str = DEFAULT_SIGNER_ID) -> VerifyKey:
        """Load a verification key from disk."""
        pub_bytes = self._pub_path(signer_id).read_bytes()
        return VerifyKey(pub_bytes)

    def sign(self, data: bytes, signer_id: str = DEFAULT_SIGNER_ID) -> bytes:
        """Sign data and return raw signature bytes."""
        sk = self.ensure_key(signer_id)
        return sk.sign(data).signature

    def sign_b64(self, data: bytes, signer_id: str = DEFAULT_SIGNER_ID) -> str:
        """Sign data and return base64-encoded signature."""
        return base64.b64encode(self.sign(data, signer_id)).decode("ascii")

    def verify(
        self, data: bytes, signature: bytes, signer_id: str = DEFAULT_SIGNER_ID
    ) -> bool:
        """Verify a signature. Returns True if valid, False otherwise."""
        try:
            vk = self.get_verify_key(signer_id)
            vk.verify(data, signature)
            return True
        except Exception:
            return False

    def verify_b64(
        self, data: bytes, signature_b64: str, signer_id: str = DEFAULT_SIGNER_ID
    ) -> bool:
        """Verify a base64-encoded signature."""
        try:
            sig_bytes = base64.b64decode(signature_b64)
            return self.verify(data, sig_bytes, signer_id)
        except Exception:
            return False

    def delete_key(self, signer_id: str) -> bool:
        """Delete a signer's key and pubkey files. Returns True if deleted."""
        key_path = self._key_path(signer_id)
        pub_path = self._pub_path(signer_id)
        deleted = False
        if key_path.exists():
            key_path.unlink()
            deleted = True
        if pub_path.exists():
            pub_path.unlink()
            deleted = True
        # If this was the active signer, remove the marker
        marker = self._active_signer_path()
        if marker.exists():
            active = marker.read_text().strip()
            if active == signer_id:
                marker.unlink()
        return deleted

    def list_signers(self) -> List[str]:
        """List known signer IDs (sorted) that have both key and pubkey files."""
        if not self.keys_dir.exists():
            return []
        signers: List[str] = []
        for key_path in sorted(self.keys_dir.glob("*.key")):
            signer_id = key_path.stem
            if self.has_key(signer_id):
                signers.append(signer_id)
        return signers

    def signer_fingerprint(self, signer_id: str = DEFAULT_SIGNER_ID) -> str:
        """Return signer public key SHA-256 fingerprint."""
        pub_bytes = self._pub_path(signer_id).read_bytes()
        return hashlib.sha256(pub_bytes).hexdigest()

    def get_active_signer(self) -> str:
        """Return active signer ID with backward-compatible fallback rules."""
        marker = self._active_signer_path()
        if marker.exists():
            signer_id = marker.read_text().strip()
            if signer_id and self.has_key(signer_id):
                return signer_id

        if self.has_key(DEFAULT_SIGNER_ID):
            return DEFAULT_SIGNER_ID

        signers = self.list_signers()
        if signers:
            return signers[0]
        return DEFAULT_SIGNER_ID

    def set_active_signer(self, signer_id: str) -> None:
        """Set active signer ID. Signer must already exist."""
        if not self.has_key(signer_id):
            raise ValueError(f"Signer not found: {signer_id}")
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._active_signer_path().write_text(f"{signer_id}\n")

    def signer_info(self) -> List[Dict[str, Any]]:
        """Return signer metadata list for CLI rendering."""
        active = self.get_active_signer()
        items: List[Dict[str, Any]] = []
        for signer_id in self.list_signers():
            items.append(
                {
                    "signer_id": signer_id,
                    "active": signer_id == active,
                    "fingerprint": self.signer_fingerprint(signer_id),
                    "key_path": str(self._key_path(signer_id)),
                    "pub_path": str(self._pub_path(signer_id)),
                }
            )
        return items


def get_default_keystore() -> AssayKeyStore:
    """Return the default keystore."""
    return AssayKeyStore()


__all__ = [
    "AssayKeyStore",
    "get_default_keystore",
    "DEFAULT_SIGNER_ID",
    "ACTIVE_SIGNER_FILE",
]
