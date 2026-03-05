"""Evidence indexing and resolution for VendorQ."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from assay.vendorq_models import (
    VendorQInputError,
    canonical_sha256,
    now_utc_iso,
    parse_iso8601,
    resolve_pointer,
)


REQUIRED_PACK_FILES = (
    "pack_manifest.json",
    "pack_signature.sig",
    "receipt_pack.jsonl",
    "verify_report.json",
    "verify_transcript.md",
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise VendorQInputError(f"invalid_json: {path}: {e.msg}")


def _read_receipts(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def compute_pack_digest(pack_dir: Path, manifest: Dict[str, Any]) -> str:
    files = manifest.get("files", [])
    compact = [
        {
            "path": str(f.get("path", "")),
            "sha256": str(f.get("sha256", "")),
        }
        for f in files
    ]
    compact.sort(key=lambda x: x["path"])
    material = {
        "pack_id": manifest.get("attestation", {}).get("pack_id", pack_dir.name),
        "files": compact,
        "manifest_sha256": _sha256_file(pack_dir / "pack_manifest.json"),
    }
    return canonical_sha256(material)


def _require_pack_files(pack_dir: Path) -> None:
    for name in REQUIRED_PACK_FILES:
        p = pack_dir / name
        if not p.exists():
            raise VendorQInputError(f"pack_missing_file: {pack_dir}/{name}")


def load_pack(pack_dir: Path) -> Dict[str, Any]:
    if not pack_dir.exists() or not pack_dir.is_dir():
        raise VendorQInputError(f"pack_dir_not_found: {pack_dir}")

    _require_pack_files(pack_dir)

    manifest = _read_json(pack_dir / "pack_manifest.json")
    receipts = _read_receipts(pack_dir / "receipt_pack.jsonl")
    verify_report = _read_json(pack_dir / "verify_report.json")
    verify_transcript = (pack_dir / "verify_transcript.md").read_text(encoding="utf-8")

    att = manifest.get("attestation", {})
    pack_id = str(att.get("pack_id") or pack_dir.name)
    timestamp_end = str(att.get("timestamp_end") or now_utc_iso())
    time_authority = str(att.get("time_authority") or "local_clock")
    digest = compute_pack_digest(pack_dir, manifest)

    receipts_by_id = {
        str(r.get("receipt_id")): r
        for r in receipts
        if r.get("receipt_id") is not None
    }

    return {
        "pack_id": pack_id,
        "path": str(pack_dir),
        "digest": digest,
        "manifest": manifest,
        "attestation": att,
        "receipts": receipts,
        "receipts_by_id": receipts_by_id,
        "verify_report": verify_report,
        "verify_transcript": verify_transcript,
        "timestamp_end": timestamp_end,
        "time_authority": time_authority,
        "verified_at": str(verify_report.get("verified_at") or now_utc_iso()),
    }


def build_evidence_index(pack_dirs: List[Path]) -> Dict[str, Any]:
    if not pack_dirs:
        raise VendorQInputError("no_pack_dirs")

    by_pack: Dict[str, Dict[str, Any]] = {}
    packs: List[Dict[str, Any]] = []

    for p in pack_dirs:
        pack = load_pack(p)
        pack_id = pack["pack_id"]
        if pack_id in by_pack:
            raise VendorQInputError(f"duplicate_pack_id: {pack_id}")
        by_pack[pack_id] = pack
        packs.append(
            {
                "pack_id": pack_id,
                "path": pack["path"],
                "digest": pack["digest"],
                "n_receipts": len(pack["receipts"]),
                "time_authority": pack["time_authority"],
                "timestamp_end": pack["timestamp_end"],
            }
        )

    packs.sort(key=lambda x: x["pack_id"])
    return {
        "packs": packs,
        "by_pack": by_pack,
    }


def _resolve_target_obj(pack: Dict[str, Any], evidence_ref: Dict[str, Any]) -> Tuple[bool, Any, str]:
    kind = str(evidence_ref.get("evidence_kind", ""))
    rid = str(evidence_ref.get("receipt_id", ""))

    if kind == "RECEIPT":
        obj = pack["receipts_by_id"].get(rid)
        if obj is None:
            return False, None, "receipt_not_found"
    elif kind == "REPORT_SECTION":
        obj = pack["verify_report"]
    elif kind == "PACK_TRANSCRIPT":
        obj = {"text": pack["verify_transcript"]}
    elif kind == "FILE_HASH":
        target_path = str(evidence_ref.get("target", {}).get("path", ""))
        files = pack["manifest"].get("files", [])
        match = next((f for f in files if str(f.get("path", "")) == target_path), None)
        if match is None:
            return False, None, "file_hash_target_not_found"
        obj = match
    else:
        return False, None, "unknown_evidence_kind"

    pointer = str(evidence_ref.get("target", {}).get("pointer", ""))
    ok, value = resolve_pointer(obj, pointer)
    if not ok:
        return False, None, "target_pointer_not_found"
    return True, value, "ok"


def resolve_evidence_ref(index: Dict[str, Any], evidence_ref: Dict[str, Any]) -> Tuple[bool, Any, str, Optional[Dict[str, Any]]]:
    pack_id = str(evidence_ref.get("pack_id", ""))
    pack = index["by_pack"].get(pack_id)
    if pack is None:
        return False, None, "pack_not_found", None

    ok, value, msg = _resolve_target_obj(pack, evidence_ref)
    return ok, value, msg, pack


def extract_numeric_value(index: Dict[str, Any], evidence_ref: Dict[str, Any]) -> Tuple[bool, Optional[float]]:
    ok, value, _msg, _pack = resolve_evidence_ref(index, evidence_ref)
    if not ok:
        return False, None
    if isinstance(value, bool):
        return False, None
    if isinstance(value, (int, float)):
        return True, float(value)
    return False, None


def _evidence_timestamp(pack: Dict[str, Any], receipt: Optional[Dict[str, Any]] = None) -> str:
    if receipt is not None:
        ts = str(receipt.get("timestamp") or "")
        if parse_iso8601(ts) is not None:
            return ts
    ts = str(pack.get("timestamp_end") or now_utc_iso())
    if parse_iso8601(ts) is not None:
        return ts
    return now_utc_iso()


def make_receipt_evidence_ref(pack: Dict[str, Any], receipt: Dict[str, Any], field_path: str = "type") -> Dict[str, Any]:
    ok, value = resolve_pointer(receipt, field_path)
    span_obj = value if ok else receipt
    return {
        "pack_id": pack["pack_id"],
        "receipt_id": str(receipt.get("receipt_id", "")),
        "evidence_kind": "RECEIPT",
        "target": {
            "path": "receipt_pack.jsonl",
            "pointer": field_path,
        },
        "span_hash": canonical_sha256(span_obj),
        "field_path": field_path,
        "time_authority": pack["time_authority"],
        "evidence_timestamp": _evidence_timestamp(pack, receipt),
    }


def make_manifest_evidence_ref(pack: Dict[str, Any], field_path: str) -> Dict[str, Any]:
    manifest = pack["manifest"]
    ok, value = resolve_pointer(manifest, field_path)
    span_obj = value if ok else manifest
    return {
        "pack_id": pack["pack_id"],
        "receipt_id": "__manifest__",
        "evidence_kind": "REPORT_SECTION",
        "target": {
            "path": "pack_manifest.json",
            "pointer": field_path,
        },
        "span_hash": canonical_sha256(span_obj),
        "field_path": field_path,
        "time_authority": str(pack["attestation"].get("time_authority") or pack["time_authority"]),
        "evidence_timestamp": _evidence_timestamp(pack, None),
    }


def evidence_supports_affirmative(index: Dict[str, Any], evidence_ref: Dict[str, Any]) -> bool:
    ok, value, _msg, _pack = resolve_evidence_ref(index, evidence_ref)
    if not ok:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value > 0
    if isinstance(value, str):
        v = value.strip().lower()
        return v in {"yes", "true", "pass", "passed", "present", "compliant", "ok"}
    return False
