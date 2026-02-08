#!/usr/bin/env python3
"""
Generate the Assay Conformance Corpus.

Creates 6 canonical Proof Packs with known verification outcomes:
  - 3 good packs (exit 0)
  - 1 claim-fail pack (exit 1)
  - 2 tampered packs (exit 2)

Run from the repo root:
    cd ~/ccio
    python conformance/generate_corpus.py

Output: conformance/corpus_v1/packs/<name>/  (5 files each)
        conformance/corpus_v1/expected_outcomes.json
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from nacl.signing import SigningKey

from assay.claim_verifier import ClaimSpec
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.run_cards import collect_claims_from_cards, get_builtin_card

CORPUS_DIR = Path(__file__).parent / "corpus_v1" / "packs"
CORPUS_SIGNER = "corpus-signer"

# Fixed seed for deterministic receipt IDs (SHA-256 of "assay-corpus-v1")
_CORPUS_SEED = "assay-corpus-v1"
# Fixed timestamp for deterministic corpus generation
_CORPUS_TS = "2026-01-15T12:00:00+00:00"
# Fixed 32-byte seed for deterministic Ed25519 corpus signer key.
# Derived from SHA-256("assay-corpus-v1-signer-key-seed") so any fresh
# environment produces the exact same keypair.
#
# WARNING: This key is TEST-ONLY. It exists solely for conformance corpus
# reproducibility. The seed is public. Never add "corpus-signer" to a
# production signer_policy allowlist. assay doctor will flag this.
_CORPUS_KEY_SEED = hashlib.sha256(b"assay-corpus-v1-signer-key-seed").digest()


def _deterministic_id(prefix: str, seq: int, pack_name: str) -> str:
    """Generate a deterministic receipt ID from pack name + seq."""
    material = f"{_CORPUS_SEED}:{pack_name}:{prefix}:{seq}"
    return f"{prefix}_{seq:04d}_{hashlib.sha256(material.encode()).hexdigest()[:8]}"


def _make_receipt(seq: int, *, pack_name: str = "default", **overrides) -> dict:
    """Create a valid receipt with deterministic content."""
    base = {
        "receipt_id": _deterministic_id("corpus_r", seq, pack_name),
        "type": "model_call",
        "timestamp": datetime(2026, 1, 15, 12, 0, seq, tzinfo=timezone.utc).isoformat(),
        "schema_version": "3.0",
        "seq": seq,
        "provider": "echo",
        "model_id": "echo-test",
        "input_tokens": 10 * (seq + 1),
        "output_tokens": 5 * (seq + 1),
        "total_tokens": 15 * (seq + 1),
        "latency_ms": 1.0,
        "finish_reason": "stop",
    }
    base.update(overrides)
    return base


def _make_guardian(seq: int, *, pack_name: str = "default") -> dict:
    """Create a guardian_verdict receipt."""
    return {
        "receipt_id": _deterministic_id("corpus_g", seq, pack_name),
        "type": "guardian_verdict",
        "timestamp": datetime(2026, 1, 15, 12, 0, seq, tzinfo=timezone.utc).isoformat(),
        "schema_version": "3.0",
        "seq": seq,
        "verdict": "allow",
        "action": "corpus_test",
        "reason": "Conformance corpus generation",
    }


def _get_keystore() -> AssayKeyStore:
    """Get or create corpus keystore with deterministic key.

    The signing key is derived from a fixed seed so any fresh environment
    produces the exact same keypair and therefore the exact same corpus.
    """
    keys_dir = Path(__file__).parent / "corpus_v1" / ".keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    ks = AssayKeyStore(keys_dir=keys_dir)

    # Always write the deterministic key (idempotent, same bytes every time)
    sk = SigningKey(_CORPUS_KEY_SEED)
    (keys_dir / f"{CORPUS_SIGNER}.key").write_bytes(sk.encode())
    (keys_dir / f"{CORPUS_SIGNER}.pub").write_bytes(sk.verify_key.encode())
    return ks


def _build_pack(
    name: str,
    entries: list[dict],
    claims: list[ClaimSpec] | None,
    ks: AssayKeyStore,
) -> Path:
    """Build a Proof Pack to the corpus directory."""
    out_dir = CORPUS_DIR / name
    if out_dir.exists():
        import shutil
        shutil.rmtree(out_dir)

    pack = ProofPack(
        run_id=f"corpus_{name}",
        entries=entries,
        signer_id=CORPUS_SIGNER,
        claims=claims,
        mode="shadow",
    )
    return pack.build(
        out_dir,
        keystore=ks,
        deterministic_ts=_CORPUS_TS,
    )


def generate() -> dict:
    """Generate all corpus packs. Returns expected_outcomes."""
    ks = _get_keystore()

    rc_cards = [get_builtin_card("receipt_completeness")]
    ge_cards = [get_builtin_card("guardian_enforcement")]
    full_cards = rc_cards + ge_cards
    full_claims = collect_claims_from_cards(full_cards)
    rc_claims = collect_claims_from_cards(rc_cards)

    outcomes = {
        "corpus_version": "1.0",
        "assay_version": "1.0.0",
        "generated_at": _CORPUS_TS,
        "entries": [],
    }

    # --- good_01: minimal valid pack (1 model_call + 1 guardian, full claims) ---
    print("Generating good_01: minimal valid pack...")
    entries = [_make_receipt(0, pack_name="good_01"), _make_guardian(1, pack_name="good_01")]
    _build_pack("good_01", entries, full_claims, ks)
    outcomes["entries"].append({
        "name": "good_01",
        "description": "Minimal valid: 1 model_call + 1 guardian_verdict, full claims",
        "expect_exit": 0,
        "run_cards": ["receipt_completeness", "guardian_enforcement"],
        "require_claim_pass": True,
    })

    # --- good_02: multi-receipt pack (4 model_calls + 1 guardian) ---
    print("Generating good_02: multi-receipt pack...")
    entries = [_make_receipt(i, pack_name="good_02") for i in range(4)] + [_make_guardian(4, pack_name="good_02")]
    _build_pack("good_02", entries, full_claims, ks)
    outcomes["entries"].append({
        "name": "good_02",
        "description": "Multi-receipt: 4 model_calls + 1 guardian_verdict",
        "expect_exit": 0,
        "run_cards": ["receipt_completeness", "guardian_enforcement"],
        "require_claim_pass": True,
    })

    # --- good_03: receipt_completeness only (no guardian needed) ---
    print("Generating good_03: receipt_completeness only...")
    entries = [_make_receipt(0, pack_name="good_03"), _make_receipt(1, pack_name="good_03")]
    _build_pack("good_03", entries, rc_claims, ks)
    outcomes["entries"].append({
        "name": "good_03",
        "description": "Receipt completeness only (no guardian_enforcement card)",
        "expect_exit": 0,
        "run_cards": ["receipt_completeness"],
        "require_claim_pass": True,
    })

    # --- claimfail_01: missing guardian (integrity PASS, claims FAIL) ---
    print("Generating claimfail_01: missing guardian verdict...")
    entries = [_make_receipt(0, pack_name="claimfail_01")]
    _build_pack("claimfail_01", entries, full_claims, ks)
    outcomes["entries"].append({
        "name": "claimfail_01",
        "description": "Missing guardian_verdict: integrity PASS, claims FAIL",
        "expect_exit": 1,
        "run_cards": ["receipt_completeness", "guardian_enforcement"],
        "require_claim_pass": True,
    })

    # --- tampered_01: field injection in receipt_pack.jsonl ---
    print("Generating tampered_01: field injection...")
    entries = [_make_receipt(0, pack_name="tampered_01"), _make_guardian(1, pack_name="tampered_01")]
    pack_dir = _build_pack("tampered_01", entries, full_claims, ks)
    receipt_file = pack_dir / "receipt_pack.jsonl"
    lines = receipt_file.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["TAMPERED"] = True
    lines[0] = json.dumps(obj)
    receipt_file.write_text("\n".join(lines) + "\n")
    outcomes["entries"].append({
        "name": "tampered_01",
        "description": "Field injected into first receipt (file hash mismatch)",
        "expect_exit": 2,
        "run_cards": ["receipt_completeness", "guardian_enforcement"],
        "require_claim_pass": True,
    })

    # --- tampered_02: receipt deletion (omission) ---
    print("Generating tampered_02: receipt deletion...")
    entries = [_make_receipt(0, pack_name="tampered_02"), _make_receipt(1, pack_name="tampered_02"), _make_guardian(2, pack_name="tampered_02")]
    pack_dir = _build_pack("tampered_02", entries, full_claims, ks)
    receipt_file = pack_dir / "receipt_pack.jsonl"
    lines = receipt_file.read_text().splitlines()
    receipt_file.write_text("\n".join(lines[1:]) + "\n")
    outcomes["entries"].append({
        "name": "tampered_02",
        "description": "First receipt deleted (omission detection)",
        "expect_exit": 2,
        "run_cards": ["receipt_completeness", "guardian_enforcement"],
        "require_claim_pass": True,
    })

    # Write expected_outcomes.json
    outcomes_path = Path(__file__).parent / "corpus_v1" / "expected_outcomes.json"
    outcomes_path.write_text(json.dumps(outcomes, indent=2) + "\n")
    print(f"\nWrote {len(outcomes['entries'])} entries to {outcomes_path}")

    return outcomes


if __name__ == "__main__":
    generate()
