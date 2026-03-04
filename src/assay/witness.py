"""
Witness v0: Independent timestamp attestation for Proof Packs.

A witness bundle ties a pack_root_sha256 to an external time/existence
authority (RFC 3161 TSA or Rekor transparency log). This provides T2
trust: an independent third party attests that the hash existed at a
specific time.

Usage:
    bundle = request_witness(pack_dir, witness_type="rfc3161")
    # -> writes witness_bundle.json into pack_dir

    result = verify_witness(pack_dir)
    # -> WitnessVerifyResult
"""
from __future__ import annotations

import base64
import json
import secrets
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

SCHEMA_VERSION = "1.0.0"
WITNESS_BUNDLE_FILENAME = "witness_bundle.json"

# Default TSA for RFC 3161 (FreeTSA, free and public)
DEFAULT_TSA_URL = "https://freetsa.org/tsr"
DEFAULT_TSA_CA_URL = "https://freetsa.org/files/cacert.pem"
DEFAULT_TSA_CERT_URL = "https://freetsa.org/files/tsa.crt"


@dataclass
class WitnessVerifyResult:
    """Result of verifying a witness bundle."""
    passed: bool
    errors: List[str] = field(default_factory=list)
    gen_time: Optional[str] = None


class WitnessError(Exception):
    """Raised when witness operations fail."""


def _read_pack_root(pack_dir: Path) -> str:
    """Read pack_root_sha256 from a pack manifest."""
    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        raise WitnessError(f"pack_manifest.json not found in {pack_dir}")
    manifest = json.loads(manifest_path.read_text())
    pack_root = manifest.get("pack_root_sha256", "")
    if not pack_root:
        raise WitnessError("pack_root_sha256 missing from manifest")
    return pack_root


def _read_attestation_sha(pack_dir: Path) -> str:
    """Read attestation_sha256 from a pack manifest."""
    manifest_path = pack_dir / "pack_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    return manifest.get("attestation_sha256", manifest.get("pack_root_sha256", ""))


def _fetch_url(url: str, data: Optional[bytes] = None,
               content_type: Optional[str] = None,
               timeout: int = 30) -> bytes:
    """Fetch URL content. POST if data is provided."""
    req = Request(url)
    if content_type:
        req.add_header("Content-Type", content_type)
    resp = urlopen(req, data=data, timeout=timeout)
    return resp.read()


def _openssl_ts_query(digest_hex: str, nonce: str, out_path: Path) -> None:
    """Create an RFC 3161 timestamp query using openssl ts."""
    cmd = [
        "openssl", "ts", "-query",
        "-digest", digest_hex,
        "-sha256",
        "-nonce", nonce,
        "-cert",
        "-out", str(out_path),
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise WitnessError(f"openssl ts -query failed: {result.stderr.decode()}")


def _openssl_ts_verify(
    token_path: Path,
    ca_cert_path: Path,
    tsa_cert_path: Path,
    *,
    query_path: Optional[Path] = None,
    digest_hex: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Verify an RFC 3161 timestamp response using openssl ts."""
    if query_path is None and not digest_hex:
        raise WitnessError("openssl ts -verify requires query_path or digest_hex")

    cmd = [
        "openssl", "ts", "-verify",
        "-in", str(token_path),
        "-CAfile", str(ca_cert_path),
        "-untrusted", str(tsa_cert_path),
    ]
    if query_path is not None:
        cmd.extend(["-queryfile", str(query_path)])
    else:
        cmd.extend(["-digest", digest_hex, "-sha256"])
    return subprocess.run(cmd, capture_output=True, timeout=30)


def _extract_gen_time(token_der: bytes) -> Optional[str]:
    """Extract genTime from a DER-encoded TSA response using openssl."""
    with tempfile.NamedTemporaryFile(suffix=".tsr", delete=False) as f:
        f.write(token_der)
        f.flush()
        tmp = Path(f.name)

    try:
        result = subprocess.run(
            ["openssl", "ts", "-reply", "-in", str(tmp), "-text"],
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        text = result.stdout.decode()
        for line in text.splitlines():
            if "Time stamp:" in line:
                # Format: "Time stamp: Mar  4 12:34:56 2026 GMT"
                raw = line.split("Time stamp:", 1)[1].strip()
                try:
                    dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
                    return dt.replace(tzinfo=timezone.utc).isoformat()
                except ValueError:
                    return raw
        return None
    finally:
        tmp.unlink(missing_ok=True)


def request_rfc3161_witness(
    pack_root_sha256: str,
    *,
    tsa_url: str = DEFAULT_TSA_URL,
    tsa_ca_url: str = DEFAULT_TSA_CA_URL,
    tsa_cert_url: str = DEFAULT_TSA_CERT_URL,
) -> Dict[str, Any]:
    """Request an RFC 3161 timestamp for a pack root hash.

    Args:
        pack_root_sha256: The SHA-256 hash to timestamp.
        tsa_url: TSA server URL.
        tsa_ca_url: URL for the TSA CA certificate.
        tsa_cert_url: URL for the TSA signing certificate.

    Returns:
        Dict with query_b64, token_b64, ca_cert_b64, tsa_cert_b64, nonce, gen_time.
    """
    # RFC 3161 nonce is an integer. Keep within signed 64-bit to avoid parser edge cases.
    nonce = str(secrets.randbits(63))

    try:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            query_path = td_path / "query.tsq"
            response_path = td_path / "response.tsr"

            # Create timestamp query
            _openssl_ts_query(pack_root_sha256, nonce, query_path)

            # POST to TSA
            query_bytes = query_path.read_bytes()
            response_bytes = _fetch_url(
                tsa_url,
                data=query_bytes,
                content_type="application/timestamp-query",
            )
            response_path.write_bytes(response_bytes)

            # Fetch CA + TSA certs for offline verification
            ca_cert_pem = _fetch_url(tsa_ca_url)
            tsa_cert_pem = _fetch_url(tsa_cert_url)

            # Extract genTime
            gen_time = _extract_gen_time(response_bytes)
    except WitnessError:
        raise
    except Exception as e:
        raise WitnessError(f"RFC 3161 witness request failed: {e}") from e

    return {
        "query_b64": base64.b64encode(query_bytes).decode("ascii"),
        "token_b64": base64.b64encode(response_bytes).decode("ascii"),
        "ca_cert_b64": base64.b64encode(ca_cert_pem).decode("ascii"),
        "tsa_cert_b64": base64.b64encode(tsa_cert_pem).decode("ascii"),
        "nonce": nonce,
        "gen_time": gen_time,
        "tsa_url": tsa_url,
    }


def generate_witness_bundle(
    pack_dir: Path,
    *,
    witness_type: str = "rfc3161",
    tsa_url: str = DEFAULT_TSA_URL,
    tsa_ca_url: str = DEFAULT_TSA_CA_URL,
    tsa_cert_url: str = DEFAULT_TSA_CERT_URL,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Generate a witness bundle for a Proof Pack.

    Args:
        pack_dir: Path to the Proof Pack directory.
        witness_type: "rfc3161" (default) or "rekor" (not yet implemented).
        tsa_url: TSA server URL (RFC 3161 only).
        tsa_ca_url: URL for TSA CA certificate.
        tsa_cert_url: URL for TSA signing certificate.
        output_path: Where to write the bundle. Default: pack_dir/witness_bundle.json.

    Returns:
        The witness bundle dict.
    """
    pack_dir = Path(pack_dir)
    pack_root = _read_pack_root(pack_dir)
    att_sha = _read_attestation_sha(pack_dir)

    if witness_type == "rfc3161":
        tsa_result = request_rfc3161_witness(
            pack_root,
            tsa_url=tsa_url,
            tsa_ca_url=tsa_ca_url,
            tsa_cert_url=tsa_cert_url,
        )
    elif witness_type == "rekor":
        raise WitnessError("Rekor witness type is not yet implemented.")
    else:
        raise WitnessError(f"Unknown witness type: {witness_type!r}")

    bundle: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "witness_type": witness_type,
        "pack_root_sha256": pack_root,
        "attestation_sha256": att_sha,
        "tsa_url": tsa_result.get("tsa_url"),
        "query_b64": tsa_result.get("query_b64"),
        "token_b64": tsa_result["token_b64"],
        "ca_cert_b64": tsa_result.get("ca_cert_b64"),
        "tsa_cert_b64": tsa_result.get("tsa_cert_b64"),
        "nonce": tsa_result.get("nonce"),
        "gen_time": tsa_result.get("gen_time"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "verified_at": None,
    }

    out = output_path or (pack_dir / WITNESS_BUNDLE_FILENAME)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2) + "\n")

    return bundle


def verify_witness_bundle(
    bundle: Dict[str, Any],
    pack_root_sha256: str,
) -> WitnessVerifyResult:
    """Verify a witness bundle against a pack root hash.

    Checks:
    1. Schema version
    2. D12 invariant (pack_root_sha256 == attestation_sha256)
    3. pack_root_sha256 matches expected value
    4. Token signature verification (via openssl ts -verify)

    Args:
        bundle: The witness bundle dict.
        pack_root_sha256: Expected pack root hash to verify against.

    Returns:
        WitnessVerifyResult with passed/errors.
    """
    errors: List[str] = []

    # 1. Schema version
    if bundle.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"Unknown schema_version: {bundle.get('schema_version')!r} "
            f"(expected {SCHEMA_VERSION!r})"
        )

    # 2. D12 invariant
    b_root = bundle.get("pack_root_sha256", "")
    b_att = bundle.get("attestation_sha256", "")
    if b_root and b_att and b_root != b_att:
        errors.append(
            f"D12 invariant violated: pack_root_sha256 ({b_root[:16]}...) "
            f"!= attestation_sha256 ({b_att[:16]}...)"
        )

    # 3. Pack root match
    if b_root != pack_root_sha256:
        errors.append(
            f"Pack root mismatch: bundle references {b_root[:16]}..., "
            f"expected {pack_root_sha256[:16]}..."
        )

    # 4. Token verification
    witness_type = bundle.get("witness_type", "")
    gen_time = bundle.get("gen_time")

    if witness_type == "rfc3161":
        query_b64 = bundle.get("query_b64", "")
        token_b64 = bundle.get("token_b64", "")
        ca_cert_b64 = bundle.get("ca_cert_b64", "")
        tsa_cert_b64 = bundle.get("tsa_cert_b64", "")

        if not token_b64:
            errors.append("Missing token_b64 in witness bundle")
        elif not ca_cert_b64 or not tsa_cert_b64:
            errors.append("Missing ca_cert_b64 or tsa_cert_b64 for offline verification")
        else:
            try:
                token_der = base64.b64decode(token_b64)
                ca_pem = base64.b64decode(ca_cert_b64)
                tsa_pem = base64.b64decode(tsa_cert_b64)

                with tempfile.TemporaryDirectory() as td:
                    td_path = Path(td)
                    token_path = td_path / "token.tsr"
                    ca_path = td_path / "ca.pem"
                    tsa_path = td_path / "tsa.crt"
                    query_path: Optional[Path] = None

                    token_path.write_bytes(token_der)
                    ca_path.write_bytes(ca_pem)
                    tsa_path.write_bytes(tsa_pem)
                    if query_b64:
                        query_path = td_path / "query.tsq"
                        query_path.write_bytes(base64.b64decode(query_b64))

                    result = _openssl_ts_verify(
                        token_path,
                        ca_path,
                        tsa_path,
                        query_path=query_path,
                        digest_hex=pack_root_sha256 if query_path is None else None,
                    )

                    if result.returncode != 0:
                        stderr = result.stderr.decode().strip()
                        errors.append(f"RFC 3161 verification failed: {stderr}")
            except Exception as e:
                errors.append(f"RFC 3161 verification error: {e}")

    elif witness_type == "rekor":
        errors.append("Rekor verification is not yet implemented.")
    else:
        errors.append(f"Unknown witness_type: {witness_type!r}")

    return WitnessVerifyResult(
        passed=len(errors) == 0,
        errors=errors,
        gen_time=gen_time,
    )


def verify_witness_from_pack(
    pack_dir: Path,
    *,
    bundle_path: Optional[Path] = None,
) -> WitnessVerifyResult:
    """Verify a witness bundle found in (or alongside) a pack directory.

    Args:
        pack_dir: Path to the Proof Pack directory.
        bundle_path: Explicit path to witness_bundle.json. Defaults to pack_dir/witness_bundle.json.

    Returns:
        WitnessVerifyResult.
    """
    pack_dir = Path(pack_dir)
    bp = bundle_path or (pack_dir / WITNESS_BUNDLE_FILENAME)
    bp = Path(bp)

    if not bp.exists():
        return WitnessVerifyResult(
            passed=False,
            errors=[f"Witness bundle not found: {bp}"],
        )

    try:
        bundle = json.loads(bp.read_text())
    except Exception as e:
        return WitnessVerifyResult(
            passed=False,
            errors=[f"Invalid witness bundle JSON: {e}"],
        )
    try:
        pack_root = _read_pack_root(pack_dir)
    except WitnessError as e:
        return WitnessVerifyResult(
            passed=False,
            errors=[str(e)],
        )

    return verify_witness_bundle(bundle, pack_root)


__all__ = [
    "SCHEMA_VERSION",
    "WITNESS_BUNDLE_FILENAME",
    "WitnessError",
    "WitnessVerifyResult",
    "generate_witness_bundle",
    "verify_witness_bundle",
    "verify_witness_from_pack",
    "request_rfc3161_witness",
]
