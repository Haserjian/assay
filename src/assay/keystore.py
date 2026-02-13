"""
Standalone Ed25519 key management for Assay Proof Packs.

Keys are stored at ~/.assay/keys/{signer_id}.key
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

from nacl.signing import SigningKey, VerifyKey


DEFAULT_SIGNER_ID = "assay-local"


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

    def has_key(self, signer_id: str) -> bool:
        return self._key_path(signer_id).exists()

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


def get_default_keystore() -> AssayKeyStore:
    """Return the default keystore."""
    return AssayKeyStore()


__all__ = [
    "AssayKeyStore",
    "get_default_keystore",
    "DEFAULT_SIGNER_ID",
]
