"""
Compiled Packet v1 — reviewer-ready evidence packet.

Binds questionnaire items to claims backed by proof packs.
Produces a portable, independently verifiable artifact.

See docs/specs/COMPILED_PACKET_SPEC_V1.md for the full specification.

Core invariant: proof packs remain the evidentiary substrate.
Compiled packets reference and bind proof packs — they do not replace or swallow them.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.keystore import AssayKeyStore, DEFAULT_SIGNER_ID, get_default_keystore

try:
    from assay import __version__ as _assay_version
except Exception:
    _assay_version = "0.0.0"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BINDING_STATUS_VALUES = {"SUPPORTED", "PARTIAL", "UNSUPPORTED", "OUT_OF_SCOPE", "NON_CLAIM"}
EVIDENCE_BASIS_VALUES = {"MACHINE", "HUMAN", "MIXED", "NONE"}
CLAIM_TYPE_VALUES = {
    "CERTIFICATION", "PROCESS", "TECH_CONTROL",
    "INCIDENT", "METRIC", "COMMITMENT", "LEGAL",
}
SUBJECT_TYPE_VALUES = {"artifact", "run", "decision"}

# Canonical subject_digest format: "sha256:<64 hex chars>"
# This is the only accepted format. Raw hex, bare hashes, or other
# algorithms are rejected. The algorithm tag is part of the identity.
import re
_SUBJECT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

PACKET_MANIFEST_FILE = "packet_manifest.json"
PACKET_SIGNATURE_FILE = "packet_signature.sig"
BINDINGS_FILE = "claim_bindings.jsonl"
QUESTIONNAIRE_FILE = "questionnaire_import.json"
COVERAGE_FILE = "coverage_report.json"
PACKS_DIR = "packs"

KERNEL_FILES = [
    BINDINGS_FILE,
    QUESTIONNAIRE_FILE,
    COVERAGE_FILE,
    PACKET_MANIFEST_FILE,
    PACKET_SIGNATURE_FILE,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _generate_packet_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"pkt_{ts}_{uuid.uuid4().hex[:8]}"


def _generate_binding_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"bind_{ts}_{uuid.uuid4().hex[:8]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Pack loading
# ---------------------------------------------------------------------------

def _load_pack_metadata(pack_dir: Path) -> Dict[str, Any]:
    """Load minimal metadata from a proof pack for packet compilation."""
    pack_dir = Path(pack_dir)
    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        raise ValueError(f"No pack_manifest.json in {pack_dir}")

    manifest = json.loads(manifest_path.read_text())
    receipt_ids = []
    receipt_pack_path = pack_dir / "receipt_pack.jsonl"
    if receipt_pack_path.exists():
        for line in receipt_pack_path.read_text().splitlines():
            line = line.strip()
            if line:
                receipt = json.loads(line)
                receipt_ids.append(receipt.get("receipt_id", ""))

    return {
        "pack_id": manifest.get("pack_id", pack_dir.name),
        "pack_root_sha256": manifest.get("pack_root_sha256", ""),
        "receipt_ids": receipt_ids,
        "manifest": manifest,
        "pack_dir": pack_dir,
    }


# ---------------------------------------------------------------------------
# Questionnaire handling
# ---------------------------------------------------------------------------

def load_questionnaire_json(path: Path) -> Dict[str, Any]:
    """Load a vendorq.question.v1 questionnaire JSON file."""
    data = json.loads(Path(path).read_text())
    if data.get("schema_version") != "vendorq.question.v1":
        raise ValueError(f"Expected schema_version 'vendorq.question.v1', got {data.get('schema_version')!r}")
    if not data.get("questions"):
        raise ValueError("Questionnaire has no questions")
    return data


def questionnaire_from_csv(csv_path: Path) -> Dict[str, Any]:
    """Convert a VendorQ CSV questionnaire to vendorq.question.v1 JSON."""
    import csv
    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "question_id": row["question_id"].strip(),
                "question_text": row["question_text"].strip(),
                "type_hint": row.get("type_hint", "unknown").strip(),
                "required_format": row.get("required_format", "text").strip(),
            })
    if not rows:
        raise ValueError(f"No questions found in {csv_path}")

    questions_bytes = jcs_canonicalize(rows)
    return {
        "schema_version": "vendorq.question.v1",
        "generated_at": _now_iso(),
        "source": str(csv_path.name),
        "questions_hash": _sha256_hex(questions_bytes),
        "questions": rows,
    }


# ---------------------------------------------------------------------------
# Binding validation
# ---------------------------------------------------------------------------

def _validate_binding(binding: Dict[str, Any], pack_refs: Dict[str, str]) -> List[str]:
    """Validate a single claim binding. Returns list of error messages."""
    errors = []

    for field in ("binding_id", "questionnaire_item_id", "claim_type",
                   "binding_status", "evidence_basis", "evidence_refs",
                   "answer_summary", "scope_notes", "missing_evidence"):
        if field not in binding:
            errors.append(f"Missing required field: {field}")

    status = binding.get("binding_status", "")
    basis = binding.get("evidence_basis", "")
    refs = binding.get("evidence_refs", [])

    if status and status not in BINDING_STATUS_VALUES:
        errors.append(f"Invalid binding_status: {status}")
    if basis and basis not in EVIDENCE_BASIS_VALUES:
        errors.append(f"Invalid evidence_basis: {basis}")

    claim_type = binding.get("claim_type", "")
    if claim_type and claim_type not in CLAIM_TYPE_VALUES:
        errors.append(f"Invalid claim_type: {claim_type}")

    # Consistency: basis vs refs
    if basis in ("MACHINE", "MIXED") and not refs:
        errors.append(f"evidence_basis={basis} but evidence_refs is empty")
    if basis == "NONE" and refs:
        errors.append(f"evidence_basis=NONE but evidence_refs is non-empty")

    # PARTIAL must have missing_evidence
    if status == "PARTIAL":
        missing = binding.get("missing_evidence", [])
        if not missing:
            errors.append("binding_status=PARTIAL but missing_evidence is empty")

    # Validate evidence refs against known packs
    for i, ref in enumerate(refs):
        pack_id = ref.get("pack_id", "")
        ref_root = ref.get("pack_root_sha256", "")
        if pack_id not in pack_refs:
            errors.append(f"evidence_refs[{i}]: unknown pack_id '{pack_id}'")
        elif pack_refs[pack_id] != ref_root:
            errors.append(
                f"evidence_refs[{i}]: pack_root_sha256 mismatch for '{pack_id}': "
                f"expected {pack_refs[pack_id][:16]}..., got {ref_root[:16]}..."
            )

    return errors


# ---------------------------------------------------------------------------
# init_packet — scaffold a packet workdir
# ---------------------------------------------------------------------------

def init_packet(
    *,
    questionnaire_path: Path,
    pack_dirs: List[Path],
    output_dir: Path,
    from_csv: bool = False,
) -> Dict[str, Any]:
    """Create a packet workdir with imported questionnaire and stub bindings.

    Returns summary dict with created file paths.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load questionnaire
    if from_csv:
        questionnaire = questionnaire_from_csv(questionnaire_path)
    else:
        questionnaire = load_questionnaire_json(questionnaire_path)

    # Load pack metadata
    packs = []
    for pd in pack_dirs:
        packs.append(_load_pack_metadata(pd))

    # Write questionnaire import (JCS-canonical for deterministic hashing)
    q_bytes = jcs_canonicalize(questionnaire)
    (output_dir / QUESTIONNAIRE_FILE).write_bytes(q_bytes)

    # Generate stub bindings — one UNSUPPORTED/NONE stub per question
    bindings = []
    for q in questionnaire["questions"]:
        binding = {
            "binding_id": _generate_binding_id(),
            "questionnaire_item_id": q["question_id"],
            "claim_type": "PROCESS",  # default, operator should change
            "binding_status": "UNSUPPORTED",
            "evidence_basis": "NONE",
            "evidence_refs": [],
            "answer_summary": "",
            "scope_notes": "",
            "freshness_anchor": _now_iso(),
            "missing_evidence": [f"Evidence needed for: {q['question_text'][:80]}"],
        }
        bindings.append(binding)

    # Write stub bindings as JSONL (JCS-canonical per line)
    binding_lines = []
    for b in bindings:
        binding_lines.append(jcs_canonicalize(b).decode("utf-8"))
    bindings_content = "\n".join(binding_lines) + "\n" if binding_lines else ""
    (output_dir / BINDINGS_FILE).write_text(bindings_content, encoding="utf-8")

    # Write pack reference metadata for the operator
    pack_refs = {}
    for p in packs:
        pack_refs[p["pack_id"]] = {
            "pack_root_sha256": p["pack_root_sha256"],
            "receipt_ids": p["receipt_ids"],
            "source_dir": str(p["pack_dir"]),
        }
    (output_dir / "_pack_references.json").write_text(
        json.dumps(pack_refs, indent=2), encoding="utf-8"
    )

    return {
        "output_dir": str(output_dir),
        "questionnaire_items": len(questionnaire["questions"]),
        "stub_bindings": len(bindings),
        "pack_references": len(packs),
        "pack_ids": [p["pack_id"] for p in packs],
        "files_created": [
            str(output_dir / QUESTIONNAIRE_FILE),
            str(output_dir / BINDINGS_FILE),
            str(output_dir / "_pack_references.json"),
        ],
    }


# ---------------------------------------------------------------------------
# compile_packet — validate, canonicalize, sign, bundle
# ---------------------------------------------------------------------------

def _validate_subject(subject: Dict[str, Any]) -> List[str]:
    """Validate a subject binding. Returns list of errors."""
    errors = []
    st = subject.get("subject_type", "")
    if not st:
        errors.append("subject.subject_type is required")
    elif st not in SUBJECT_TYPE_VALUES:
        errors.append(f"subject.subject_type '{st}' not in {sorted(SUBJECT_TYPE_VALUES)}")
    if not subject.get("subject_id"):
        errors.append("subject.subject_id is required")
    digest = subject.get("subject_digest", "")
    if not digest:
        errors.append("subject.subject_digest is required")
    elif not _SUBJECT_DIGEST_RE.match(digest):
        errors.append(
            f"subject.subject_digest must be 'sha256:<64 hex chars>', got '{digest[:40]}...'"
            if len(digest) > 40 else
            f"subject.subject_digest must be 'sha256:<64 hex chars>', got '{digest}'"
        )
    return errors


def _source_commit_required(subject: Dict[str, Any]) -> bool:
    """Return True when the packet class requires first-class source provenance."""
    return subject.get("subject_type") == "artifact"


def compile_packet(
    *,
    draft_dir: Path,
    pack_dirs: List[Path],
    output_dir: Path,
    bundle: bool = True,
    signer_id: str = DEFAULT_SIGNER_ID,
    keystore: Optional[AssayKeyStore] = None,
    subject: Optional[Dict[str, Any]] = None,
    source_commit: Optional[str] = None,
    policy_id: str = "default",
    freshness_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compile a packet from a draft workdir.

    The draft_dir must contain:
    - questionnaire_import.json (JCS-canonical)
    - claim_bindings.jsonl (operator-authored, one binding per line)

    Subject binding is required. Pass subject dict with:
    - subject_type: "artifact", "run", or "decision"
    - subject_id: stable human/reference identity
    - subject_digest: canonical bytes identity (e.g. git SHA)
    - subject_uri: optional locator

    Returns compilation result dict.
    """
    if subject is None:
        raise ValueError(
            "Subject binding is required. Pass subject={subject_type, subject_id, subject_digest}. "
            "The packet must be about something."
        )
    if _source_commit_required(subject) and not source_commit:
        raise ValueError(
            "source_commit is required for artifact packets. "
            "Provide the source commit provenance that produced the release artifact."
        )
    if source_commit is not None and not str(source_commit).strip():
        raise ValueError("source_commit must be a non-empty string when provided")
    subject_errors = _validate_subject(subject)
    if subject_errors:
        raise ValueError(
            "Invalid subject binding:\n" + "\n".join(f"  - {e}" for e in subject_errors)
        )
    draft_dir = Path(draft_dir)
    output_dir = Path(output_dir)
    ks = keystore or get_default_keystore()

    # 1. Load questionnaire
    q_path = draft_dir / QUESTIONNAIRE_FILE
    if not q_path.exists():
        raise ValueError(f"Missing {QUESTIONNAIRE_FILE} in {draft_dir}")
    questionnaire = json.loads(q_path.read_bytes())
    question_ids = {q["question_id"] for q in questionnaire.get("questions", [])}

    # 2. Load and validate proof packs
    packs = {}
    for pd in pack_dirs:
        meta = _load_pack_metadata(pd)
        packs[meta["pack_id"]] = meta

    pack_root_map = {pid: p["pack_root_sha256"] for pid, p in packs.items()}

    # 3. Load and validate bindings
    bindings_path = draft_dir / BINDINGS_FILE
    if not bindings_path.exists():
        raise ValueError(f"Missing {BINDINGS_FILE} in {draft_dir}")

    bindings = []
    all_errors = []
    for i, line in enumerate(bindings_path.read_text().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            binding = json.loads(line)
        except json.JSONDecodeError as e:
            all_errors.append(f"Line {i+1}: invalid JSON: {e}")
            continue
        errors = _validate_binding(binding, pack_root_map)
        for err in errors:
            all_errors.append(f"Line {i+1} ({binding.get('binding_id', '?')}): {err}")
        bindings.append(binding)

    if all_errors:
        raise ValueError(
            f"Binding validation failed with {len(all_errors)} error(s):\n"
            + "\n".join(f"  - {e}" for e in all_errors)
        )

    # 4. Re-canonicalize bindings (sorted by questionnaire_item_id)
    bindings.sort(key=lambda b: b.get("questionnaire_item_id", ""))
    canonical_lines = []
    for b in bindings:
        canonical_lines.append(jcs_canonicalize(b).decode("utf-8"))
    bindings_bytes = ("\n".join(canonical_lines) + "\n").encode("utf-8") if canonical_lines else b""

    # 5. Re-canonicalize questionnaire
    questionnaire_bytes = jcs_canonicalize(questionnaire)

    # 6. Compute coverage
    bound_ids = {b["questionnaire_item_id"] for b in bindings}
    unbound_ids = question_ids - bound_ids

    status_counts = {}
    basis_counts = {}
    for b in bindings:
        s = b.get("binding_status", "UNKNOWN")
        status_counts[s] = status_counts.get(s, 0) + 1
        basis = b.get("evidence_basis", "UNKNOWN")
        basis_counts[basis] = basis_counts.get(basis, 0) + 1

    coverage = {
        "total_questionnaire_items": len(question_ids),
        "total_bindings": len(bindings),
        "unbound_items": sorted(unbound_ids),
        "status_counts": status_counts,
        "basis_counts": basis_counts,
    }
    coverage_bytes = jcs_canonicalize(coverage)

    # 7. Write output
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / BINDINGS_FILE).write_bytes(bindings_bytes)
    (output_dir / QUESTIONNAIRE_FILE).write_bytes(questionnaire_bytes)
    (output_dir / COVERAGE_FILE).write_bytes(coverage_bytes)

    # 8. Bundle packs if requested
    if bundle:
        packs_out = output_dir / PACKS_DIR
        packs_out.mkdir(exist_ok=True)
        for pid, pmeta in packs.items():
            dest = packs_out / pid
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(pmeta["pack_dir"], dest)

    # 9. Build pack references
    pack_references = []
    for pid, pmeta in packs.items():
        ref = {
            "pack_id": pid,
            "pack_root_sha256": pmeta["pack_root_sha256"],
            "bundled": bundle,
        }
        if bundle:
            ref["bundle_path"] = f"{PACKS_DIR}/{pid}/"
        pack_references.append(ref)

    # 10. Compute packet root (first-principles: content identity)
    # Root covers: subject + questionnaire + bindings + pack references + optional provenance
    # Subject digest is included so the root changes if the subject changes.
    # Two compilations of the same inputs = same root, regardless of timing/signer.
    sorted_pack_roots = sorted(p["pack_root_sha256"] for p in pack_references)
    root_input = {
        "subject_digest": subject["subject_digest"],
        "questionnaire_sha256": _sha256_hex(questionnaire_bytes),
        "bindings_sha256": _sha256_hex(bindings_bytes),
        "pack_references": sorted_pack_roots,
    }
    if source_commit is not None:
        root_input["source_commit"] = str(source_commit)
    packet_root_sha256 = _sha256_hex(jcs_canonicalize(root_input))

    # 11. Build file entries
    file_entries = [
        {
            "path": BINDINGS_FILE,
            "sha256": _sha256_hex(bindings_bytes),
            "bytes": len(bindings_bytes),
        },
        {
            "path": QUESTIONNAIRE_FILE,
            "sha256": _sha256_hex(questionnaire_bytes),
            "bytes": len(questionnaire_bytes),
        },
        {
            "path": COVERAGE_FILE,
            "sha256": _sha256_hex(coverage_bytes),
            "bytes": len(coverage_bytes),
        },
    ]

    # 12. Build unsigned manifest
    ks.ensure_key(signer_id)
    vk = ks.get_verify_key(signer_id)
    pubkey_bytes = vk.encode()

    # Build subject block (integrity-covered — inside unsigned manifest)
    subject_block = {
        "subject_type": subject["subject_type"],
        "subject_id": subject["subject_id"],
        "subject_digest": subject["subject_digest"],
    }
    if subject.get("subject_uri"):
        subject_block["subject_uri"] = subject["subject_uri"]

    # Build admissibility contract
    admissibility = {
        "policy_id": policy_id,
        "subject_digest": subject["subject_digest"],
        "freshness_policy": freshness_policy or {"mode": "advisory"},
    }

    unsigned_manifest = {
        "packet_id": _generate_packet_id(),
        "packet_version": "0.2.0",
        "manifest_version": "1.0.0",
        "schema_version": "compiled_packet.v2",
        "hash_alg": "sha256",
        "subject": subject_block,
        "admissibility": admissibility,
        "questionnaire_id": questionnaire.get("source", "unknown"),
        "questionnaire_sha256": _sha256_hex(questionnaire_bytes),
        "bindings_sha256": _sha256_hex(bindings_bytes),
        "bindings_count": len(bindings),
        "coverage_sha256": _sha256_hex(coverage_bytes),
        "pack_references": pack_references,
        "bundle_mode": "bundled" if bundle else "referenced",
        "files": file_entries,
        "expected_files": KERNEL_FILES.copy(),
        "compiled_at": _now_iso(),
        "compiler_version": _assay_version,
        "signer_id": signer_id,
        "signer_pubkey": base64.b64encode(pubkey_bytes).decode("ascii"),
        "signer_pubkey_sha256": _sha256_hex(pubkey_bytes),
        "signature_alg": "ed25519",
        "signature_scope": "JCS(packet_manifest_excluding_signature_and_packet_root_sha256)",
    }
    if source_commit is not None:
        unsigned_manifest["source_commit"] = str(source_commit)

    # 13. Sign
    canonical_unsigned = jcs_canonicalize(unsigned_manifest)
    signature_b64 = ks.sign_b64(canonical_unsigned, signer_id)

    signed_manifest = {
        **unsigned_manifest,
        "signature": signature_b64,
        "packet_root_sha256": packet_root_sha256,
    }

    # 14. Write manifest and detached signature
    manifest_bytes = json.dumps(signed_manifest, indent=2).encode("utf-8")
    (output_dir / PACKET_MANIFEST_FILE).write_bytes(manifest_bytes)

    sig_raw = base64.b64decode(signature_b64)
    (output_dir / PACKET_SIGNATURE_FILE).write_bytes(sig_raw)

    return {
        "packet_id": signed_manifest["packet_id"],
        "packet_root_sha256": packet_root_sha256,
        "source_commit": source_commit,
        "bindings_count": len(bindings),
        "coverage": coverage,
        "signed": True,
        "bundle_mode": "bundled" if bundle else "referenced",
        "output_dir": str(output_dir),
    }


# ---------------------------------------------------------------------------
# verify_packet — independent verification
# ---------------------------------------------------------------------------

def derive_top_level_verdict(integrity_verdict: str, completeness_verdict: str) -> str:
    """Derive top-level verdict from two-axis verdicts.

    Pure function. Exhaustively specified in PACKET_SEMANTICS_V1.md §3.4.
    Priority: INVALID > TAMPERED > DEGRADED > completeness.
    """
    if integrity_verdict == "INVALID":
        return "INVALID"
    if integrity_verdict == "TAMPERED":
        return "TAMPERED"
    if integrity_verdict == "DEGRADED":
        return "DEGRADED"
    # integrity == INTACT
    if completeness_verdict == "COMPLETE":
        return "PASS"
    return "PARTIAL"


class PacketVerifyError:
    def __init__(self, code: str, message: str, field: str = ""):
        self.code = code
        self.message = message
        self.field = field

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.field:
            d["field"] = self.field
        return d


class PacketVerifyResult:
    def __init__(
        self,
        *,
        integrity_verdict: str = "INTACT",
        completeness_verdict: str = "COMPLETE",
        packet_id: str = "",
        packet_root_sha256: str = "",
        source_commit: str = "",
        errors: Optional[List[PacketVerifyError]] = None,
        warnings: Optional[List[str]] = None,
        pack_results: Optional[List[Dict[str, Any]]] = None,
        coverage: Optional[Dict[str, Any]] = None,
        subject: Optional[Dict[str, Any]] = None,
        admissible: bool = False,
    ):
        self.integrity_verdict = integrity_verdict
        self.completeness_verdict = completeness_verdict
        self.packet_id = packet_id
        self.packet_root_sha256 = packet_root_sha256
        self.source_commit = source_commit
        self.errors = errors or []
        self.warnings = warnings or []
        self.pack_results = pack_results or []
        self.coverage = coverage or {}
        self.subject = subject or {}
        self.admissible = admissible
        self.admissibility_reasons: List[Dict[str, str]] = []

    @property
    def verdict(self) -> str:
        """Derived top-level verdict. See PACKET_SEMANTICS_V1.md §3.3-3.4."""
        return derive_top_level_verdict(self.integrity_verdict, self.completeness_verdict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "packet_verification.v2",
            "packet_id": self.packet_id,
            "packet_root_sha256": self.packet_root_sha256,
            "source_commit": self.source_commit,
            "verified_at": _now_iso(),
            "verifier_id": f"assay@{_assay_version}",
            "verdict": self.verdict,
            "integrity_verdict": self.integrity_verdict,
            "completeness_verdict": self.completeness_verdict,
            "admissible": self.admissible,
            "admissibility_reasons": self.admissibility_reasons,
            "subject": self.subject,
            "pack_results": self.pack_results,
            "coverage": self.coverage,
            "warnings": self.warnings,
            "errors": [e.to_dict() for e in self.errors],
        }


def verify_packet(
    packet_dir: Path,
    *,
    keystore: Optional[AssayKeyStore] = None,
) -> PacketVerifyResult:
    """Verify a compiled packet. Returns verification result.

    Verification steps (per spec §3.1):
    1. Manifest schema validation
    2. File hash verification
    3. Signature verification
    4. Detached signature parity
    5. Packet root invariant
    6. Questionnaire hash
    7. Bindings hash
    8. Coverage hash
    9. Pack reference validation (bundled packs)
    10. Binding reference validation
    11. Coverage completeness
    """
    packet_dir = Path(packet_dir)
    errors: List[PacketVerifyError] = []
    warnings: List[str] = []

    # 1. Load manifest
    manifest_path = packet_dir / PACKET_MANIFEST_FILE
    if not manifest_path.exists():
        return PacketVerifyResult(
            integrity_verdict="INVALID",
            errors=[PacketVerifyError("E_PKT_SCHEMA", f"Missing {PACKET_MANIFEST_FILE}")],
        )

    try:
        manifest = json.loads(manifest_path.read_bytes())
    except json.JSONDecodeError as e:
        return PacketVerifyResult(
            integrity_verdict="INVALID",
            errors=[PacketVerifyError("E_PKT_SCHEMA", f"Invalid JSON in manifest: {e}")],
        )

    packet_id = manifest.get("packet_id", "unknown")
    packet_root = manifest.get("packet_root_sha256", "")
    source_commit = manifest.get("source_commit", "")

    # Basic schema check
    for field in ("packet_id", "schema_version", "hash_alg", "files",
                   "signature", "signature_alg", "signer_pubkey",
                   "signer_pubkey_sha256", "packet_root_sha256"):
        if field not in manifest:
            errors.append(PacketVerifyError("E_PKT_SCHEMA", f"Missing field: {field}"))
    if "source_commit" in manifest and (not isinstance(source_commit, str) or not source_commit.strip()):
        errors.append(PacketVerifyError("E_PKT_SCHEMA", "Invalid field: source_commit"))

    if errors:
        return PacketVerifyResult(
            integrity_verdict="INVALID", packet_id=packet_id,
            packet_root_sha256=packet_root, source_commit=source_commit, errors=errors,
        )

    # 2. File hash verification
    for entry in manifest.get("files", []):
        fpath = packet_dir / entry["path"]
        if not fpath.exists():
            errors.append(PacketVerifyError(
                "E_PKT_TAMPER", f"Missing file: {entry['path']}", field=entry["path"]
            ))
            continue
        actual_hash = _sha256_hex(fpath.read_bytes())
        if actual_hash != entry["sha256"]:
            errors.append(PacketVerifyError(
                "E_PKT_TAMPER",
                f"Hash mismatch for {entry['path']}: expected {entry['sha256'][:16]}..., got {actual_hash[:16]}...",
                field=entry["path"],
            ))

    # 3. Signature verification
    try:
        pubkey_b64 = manifest["signer_pubkey"]
        pubkey_bytes = base64.b64decode(pubkey_b64)

        # Verify pubkey fingerprint
        expected_fp = _sha256_hex(pubkey_bytes)
        if expected_fp != manifest.get("signer_pubkey_sha256", ""):
            errors.append(PacketVerifyError(
                "E_PKT_SIG_INVALID", "signer_pubkey_sha256 does not match signer_pubkey"
            ))

        # Reconstruct unsigned manifest
        unsigned = {k: v for k, v in manifest.items()
                    if k not in ("signature", "packet_root_sha256")}
        canonical_unsigned = jcs_canonicalize(unsigned)

        # Verify Ed25519
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        vk = VerifyKey(pubkey_bytes)
        sig_bytes = base64.b64decode(manifest["signature"])
        try:
            vk.verify(canonical_unsigned, sig_bytes)
        except (BadSignatureError, ValueError):
            errors.append(PacketVerifyError("E_PKT_SIG_INVALID", "Ed25519 signature is invalid"))
    except Exception as e:
        errors.append(PacketVerifyError("E_PKT_SIG_INVALID", f"Signature verification error: {e}"))

    # 4. Detached signature parity
    sig_path = packet_dir / PACKET_SIGNATURE_FILE
    if sig_path.exists():
        detached_sig = sig_path.read_bytes()
        manifest_sig = base64.b64decode(manifest.get("signature", ""))
        if detached_sig != manifest_sig:
            errors.append(PacketVerifyError(
                "E_PKT_SIG_INVALID", "Detached signature does not match manifest signature"
            ))
    else:
        errors.append(PacketVerifyError("E_PKT_TAMPER", f"Missing {PACKET_SIGNATURE_FILE}"))

    # 5. Subject binding check
    subject_block = manifest.get("subject")
    if not subject_block:
        errors.append(PacketVerifyError("E_PKT_SCHEMA", "Missing subject binding"))
    else:
        for field in ("subject_type", "subject_id", "subject_digest"):
            if not subject_block.get(field):
                errors.append(PacketVerifyError(
                    "E_PKT_SCHEMA", f"Missing subject.{field}"
                ))
        st = subject_block.get("subject_type", "")
        if st and st not in SUBJECT_TYPE_VALUES:
            errors.append(PacketVerifyError(
                "E_PKT_SCHEMA", f"Invalid subject_type: {st}"
            ))
        digest = subject_block.get("subject_digest", "")
        if digest and not _SUBJECT_DIGEST_RE.match(digest):
            errors.append(PacketVerifyError(
                "E_PKT_SCHEMA", f"Invalid subject_digest format: must be 'sha256:<64 hex>'"
            ))
        if _source_commit_required(subject_block) and not source_commit:
            errors.append(PacketVerifyError(
                "E_PKT_SCHEMA",
                "Missing required source_commit for artifact packet provenance"
            ))

    # 5b. Admissibility contract check
    admissibility = manifest.get("admissibility")
    if admissibility:
        # Verify subject_digest in admissibility matches subject block
        adm_digest = admissibility.get("subject_digest", "")
        subj_digest = (subject_block or {}).get("subject_digest", "")
        if adm_digest and subj_digest and adm_digest != subj_digest:
            errors.append(PacketVerifyError(
                "E_PKT_TAMPER",
                "admissibility.subject_digest does not match subject.subject_digest"
            ))

    # 6. Packet root invariant (now includes subject_digest)
    subject_digest_for_root = (subject_block or {}).get("subject_digest", "")
    q_sha = manifest.get("questionnaire_sha256", "")
    b_sha = manifest.get("bindings_sha256", "")
    pack_refs = manifest.get("pack_references", [])
    sorted_pack_roots = sorted(ref.get("pack_root_sha256", "") for ref in pack_refs)
    root_input = {
        "subject_digest": subject_digest_for_root,
        "questionnaire_sha256": q_sha,
        "bindings_sha256": b_sha,
        "pack_references": sorted_pack_roots,
    }
    if source_commit:
        root_input["source_commit"] = source_commit
    expected_root = _sha256_hex(jcs_canonicalize(root_input))
    if expected_root != packet_root:
        errors.append(PacketVerifyError(
            "E_PKT_ROOT_INVARIANT",
            f"Packet root mismatch: expected {expected_root[:16]}..., got {packet_root[:16]}..."
        ))

    # 6-8. Content hash cross-checks
    for fname, manifest_key in [
        (QUESTIONNAIRE_FILE, "questionnaire_sha256"),
        (BINDINGS_FILE, "bindings_sha256"),
        (COVERAGE_FILE, "coverage_sha256"),
    ]:
        fpath = packet_dir / fname
        if fpath.exists():
            actual = _sha256_hex(fpath.read_bytes())
            expected = manifest.get(manifest_key, "")
            if actual != expected:
                errors.append(PacketVerifyError(
                    "E_PKT_TAMPER",
                    f"{manifest_key} mismatch: file={actual[:16]}..., manifest={expected[:16]}...",
                    field=fname,
                ))

    # If we already have tamper/sig errors, short-circuit
    if any(e.code in ("E_PKT_TAMPER", "E_PKT_SIG_INVALID", "E_PKT_ROOT_INVARIANT") for e in errors):
        return PacketVerifyResult(
            integrity_verdict="TAMPERED", packet_id=packet_id,
            packet_root_sha256=packet_root, source_commit=source_commit, errors=errors, warnings=warnings,
        )

    # 9. Pack reference validation (bundled packs)
    pack_results = []
    bundle_mode = manifest.get("bundle_mode", "referenced")
    for ref in pack_refs:
        pid = ref.get("pack_id", "unknown")
        pr: Dict[str, Any] = {
            "pack_id": pid,
            "pack_root_sha256": ref.get("pack_root_sha256", ""),
        }
        if bundle_mode == "bundled" and ref.get("bundled"):
            bundle_path = ref.get("bundle_path", f"{PACKS_DIR}/{pid}/")
            pack_path = packet_dir / bundle_path
            if not pack_path.exists():
                pr["pack_present"] = False
                pr["pack_integrity"] = "MISSING"
                pr["errors"] = ["Referenced pack not found in bundle"]
                errors.append(PacketVerifyError(
                    "E_PKT_PACK_MISSING", f"Bundled pack not found: {bundle_path}"
                ))
            else:
                # Verify bundled pack
                from assay.integrity import verify_pack_manifest
                pack_manifest_path = pack_path / "pack_manifest.json"
                if pack_manifest_path.exists():
                    pack_manifest = json.loads(pack_manifest_path.read_bytes())
                    ks = keystore or get_default_keystore()
                    pack_result = verify_pack_manifest(pack_manifest, pack_path, ks)
                    pr["pack_present"] = True
                    if pack_result.passed:
                        pr["pack_integrity"] = "PASS"
                        pr["errors"] = []
                        # Verify pack_root_sha256 matches
                        actual_root = pack_manifest.get("pack_root_sha256", "")
                        if actual_root != ref.get("pack_root_sha256", ""):
                            pr["pack_integrity"] = "FAIL"
                            pr["errors"] = ["pack_root_sha256 mismatch"]
                            errors.append(PacketVerifyError(
                                "E_PKT_REF_MISMATCH",
                                f"Pack {pid}: pack_root_sha256 mismatch"
                            ))
                    else:
                        pr["pack_integrity"] = "FAIL"
                        pr["errors"] = [e.message for e in pack_result.errors[:3]]
                        errors.append(PacketVerifyError(
                            "E_PKT_PACK_INVALID",
                            f"Bundled pack {pid} failed verification"
                        ))
                else:
                    pr["pack_present"] = False
                    pr["pack_integrity"] = "MISSING"
                    pr["errors"] = ["pack_manifest.json not found"]
        else:
            pr["pack_present"] = False
            pr["pack_integrity"] = "NOT_BUNDLED"
            pr["errors"] = []
            warnings.append(f"Pack {pid} is referenced but not bundled — cannot verify")

        pack_results.append(pr)

    # 10. Binding reference validation
    bindings_path = packet_dir / BINDINGS_FILE
    binding_ref_errors = 0
    if bindings_path.exists():
        for i, line in enumerate(bindings_path.read_text().splitlines()):
            line = line.strip()
            if not line:
                continue
            binding = json.loads(line)
            for ref in binding.get("evidence_refs", []):
                rpid = ref.get("pack_id", "")
                known_packs = {r.get("pack_id"): r.get("pack_root_sha256") for r in pack_refs}
                if rpid not in known_packs:
                    binding_ref_errors += 1
                    warnings.append(
                        f"Binding {binding.get('binding_id', '?')}: references unknown pack '{rpid}'"
                    )

    # 11. Coverage completeness
    coverage_path = packet_dir / COVERAGE_FILE
    coverage_data = {}
    if coverage_path.exists():
        coverage_data = json.loads(coverage_path.read_bytes())
        unbound = coverage_data.get("unbound_items", [])
        if unbound:
            warnings.append(f"{len(unbound)} questionnaire item(s) have no binding: {', '.join(unbound[:5])}")

    # Determine two-axis verdicts (per PACKET_SEMANTICS_V1.md)

    # Integrity: is the packet envelope authentic?
    fatal_codes = {"E_PKT_TAMPER", "E_PKT_SIG_INVALID", "E_PKT_ROOT_INVARIANT", "E_PKT_SCHEMA"}
    degrading_codes = {"E_PKT_PACK_MISSING", "E_PKT_PACK_INVALID", "E_PKT_REF_MISMATCH"}

    has_fatal = any(e.code in fatal_codes for e in errors)
    has_degrading = any(e.code in degrading_codes for e in errors)

    if has_fatal:
        integrity_verdict = "TAMPERED"
    elif has_degrading:
        integrity_verdict = "DEGRADED"
    else:
        integrity_verdict = "INTACT"

    # Completeness: how well does the packet answer the questionnaire?
    unbound = coverage_data.get("unbound_items", [])
    status_counts = coverage_data.get("status_counts", {})
    has_unsupported = status_counts.get("UNSUPPORTED", 0) > 0
    has_partial_bindings = status_counts.get("PARTIAL", 0) > 0
    has_unresolvable_refs = binding_ref_errors > 0

    if unbound:
        completeness_verdict = "INCOMPLETE"
    elif has_unsupported or has_partial_bindings or has_unresolvable_refs:
        completeness_verdict = "PARTIAL"
    else:
        completeness_verdict = "COMPLETE"

    # Admissibility: the gate's decision function.
    # Admissible requires ALL of:
    #   1. Integrity is INTACT
    #   2. Subject binding is present and valid
    #   3. Bundle mode is "bundled" (self-contained, offline-verifiable)
    # Completeness is NOT required for admissibility — a packet with
    # UNSUPPORTED bindings is honest, not inadmissible.
    # Freshness is advisory in v1 (schema present, enforcement deferred).
    admissibility_reasons: List[Dict[str, str]] = []

    if integrity_verdict != "INTACT":
        admissibility_reasons.append({
            "code": "INTEGRITY_FAILURE",
            "message": f"Integrity is {integrity_verdict}, must be INTACT",
        })

    if not subject_block or not subject_block.get("subject_digest"):
        admissibility_reasons.append({
            "code": "SUBJECT_BINDING_MISSING",
            "message": "No valid subject binding in manifest",
        })

    if bundle_mode != "bundled":
        admissibility_reasons.append({
            "code": "NOT_SELF_CONTAINED",
            "message": "Packet is not bundled — evidence cannot be verified offline",
        })

    admissible = len(admissibility_reasons) == 0

    result = PacketVerifyResult(
        integrity_verdict=integrity_verdict,
        completeness_verdict=completeness_verdict,
        packet_id=packet_id,
        packet_root_sha256=packet_root,
        source_commit=source_commit,
        errors=errors,
        warnings=warnings,
        pack_results=pack_results,
        coverage=coverage_data,
        subject=subject_block or {},
        admissible=admissible,
    )
    result.admissibility_reasons = admissibility_reasons
    return result
