#!/usr/bin/env python3
"""
Generate the Assay Conformance Corpus.

Creates 10 canonical Proof Packs with known verification outcomes:
  - 3 good packs (exit 0)
  - 1 deny pack: guardian deny verdict (exit 0 -- deny is valid)
  - 1 MCP deny pack: policy-denied tool call (exit 0 -- receipt valid)
  - 1 superseded pack: valid but superseded by newer (exit 0 -- informational)
  - 1 claim-fail pack (exit 1)
  - 1 stale pack: expired validity (exit 1 -- honest freshness failure)
  - 2 tampered packs (exit 2)

Run from the repo root:
    cd ~/assay
    python conformance/generate_corpus.py

Output: conformance/corpus_v1/packs/<name>/  (5 files each)
        conformance/corpus_v1/expected_outcomes.json
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
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
    *,
    valid_until: str | None = None,
    superseded_by: str | None = None,
    deterministic_ts: str | None = None,
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
        valid_until=valid_until,
        superseded_by=superseded_by,
    )
    return pack.build(
        out_dir,
        keystore=ks,
        deterministic_ts=deterministic_ts or _CORPUS_TS,
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

    # --- deny_01: guardian deny verdict (valid pack, deny is a legit verdict) ---
    print("Generating deny_01: guardian deny verdict...")
    entries = [
        _make_receipt(0, pack_name="deny_01"),
        {
            "receipt_id": _deterministic_id("corpus_g", 1, "deny_01"),
            "type": "guardian_verdict",
            "timestamp": datetime(2026, 1, 15, 12, 0, 1, tzinfo=timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 1,
            "verdict": "deny",
            "action": "unsafe_operation",
            "reason": "Violates safety constraint",
        },
    ]
    _build_pack("deny_01", entries, full_claims, ks)
    outcomes["entries"].append({
        "name": "deny_01",
        "description": "Guardian deny verdict: integrity PASS, claims PASS (deny is valid evidence)",
        "expect_exit": 0,
        "run_cards": ["receipt_completeness", "guardian_enforcement"],
        "require_claim_pass": True,
    })

    # --- mcp_deny_01: MCP tool call denied by policy (valid receipt, no forwarding) ---
    print("Generating mcp_deny_01: MCP policy-denied tool call...")
    mcp_entries = [
        {
            "receipt_id": _deterministic_id("corpus_m", 0, "mcp_deny_01"),
            "type": "mcp_tool_call",
            "timestamp": datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 0,
            "invocation_id": _deterministic_id("corpus_inv", 0, "mcp_deny_01"),
            "session_id": "mcp_corpus_session",
            "trace_id": "mcp_corpus_trace",
            "parent_receipt_id": None,
            "server_id": "corpus-server",
            "server_transport": "stdio",
            "tool_name": "delete_user",
            "mcp_request_id": 1,
            "request_observed_at": datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
            "policy_decided_at": datetime(2026, 1, 15, 12, 0, 0, 1000, tzinfo=timezone.utc).isoformat(),
            "response_observed_at": datetime(2026, 1, 15, 12, 0, 0, 2000, tzinfo=timezone.utc).isoformat(),
            "arguments_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "arguments_content": None,
            "result_hash": None,
            "result_content": None,
            "result_is_error": False,
            "outcome": "denied",
            "duration_ms": 0,
            "policy_verdict": "deny",
            "policy_reason": "deny_list",
            "policy_ref": "assay.mcp-policy.yaml",
            "policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "proxy_version": "corpus",
            "integration_source": "assay.mcp_proxy",
        },
        {
            "receipt_id": _deterministic_id("corpus_m", 1, "mcp_deny_01"),
            "type": "mcp_tool_call",
            "timestamp": datetime(2026, 1, 15, 12, 0, 1, tzinfo=timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 1,
            "invocation_id": _deterministic_id("corpus_inv", 1, "mcp_deny_01"),
            "session_id": "mcp_corpus_session",
            "trace_id": "mcp_corpus_trace",
            "parent_receipt_id": None,
            "server_id": "corpus-server",
            "server_transport": "stdio",
            "tool_name": "read_file",
            "mcp_request_id": 2,
            "request_observed_at": datetime(2026, 1, 15, 12, 0, 1, tzinfo=timezone.utc).isoformat(),
            "policy_decided_at": datetime(2026, 1, 15, 12, 0, 1, 1000, tzinfo=timezone.utc).isoformat(),
            "response_observed_at": datetime(2026, 1, 15, 12, 0, 1, 500000, tzinfo=timezone.utc).isoformat(),
            "arguments_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "arguments_content": None,
            "result_hash": "sha256:abc123",
            "result_content": None,
            "result_is_error": False,
            "outcome": "forwarded",
            "duration_ms": 499.0,
            "policy_verdict": "allow",
            "policy_reason": None,
            "policy_ref": "assay.mcp-policy.yaml",
            "policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "proxy_version": "corpus",
            "integration_source": "assay.mcp_proxy",
        },
    ]
    _build_pack("mcp_deny_01", mcp_entries, None, ks)
    outcomes["entries"].append({
        "name": "mcp_deny_01",
        "description": "MCP policy-denied tool call + allowed tool call: integrity PASS (no semantic claims)",
        "expect_exit": 0,
        "run_cards": [],
        "require_claim_pass": False,
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

    # --- stale_01: expired validity (integrity PASS, but pack is stale) ---
    # Timestamps set to 120 days before _CORPUS_TS so the pack is well past
    # any reasonable freshness window. The valid_until field is set to 30 days
    # before _CORPUS_TS, making it unambiguously expired at corpus evaluation
    # time. A conformance verifier using max_age_hours or valid_until checking
    # should flag this as an honest failure (exit 1).
    print("Generating stale_01: expired validity (stale pack)...")
    _stale_base = datetime(2025, 9, 17, 12, 0, 0, tzinfo=timezone.utc)  # ~120 days before corpus TS
    _stale_valid_until = datetime(2025, 12, 16, 12, 0, 0, tzinfo=timezone.utc)  # ~30 days before corpus TS
    stale_entries = [
        _make_receipt(
            0,
            pack_name="stale_01",
            timestamp=datetime(2025, 9, 17, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
        ),
        _make_receipt(
            1,
            pack_name="stale_01",
            timestamp=datetime(2025, 9, 17, 12, 0, 1, tzinfo=timezone.utc).isoformat(),
        ),
        {
            "receipt_id": _deterministic_id("corpus_g", 2, "stale_01"),
            "type": "guardian_verdict",
            "timestamp": datetime(2025, 9, 17, 12, 0, 2, tzinfo=timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 2,
            "verdict": "allow",
            "action": "corpus_test",
            "reason": "Conformance corpus generation (stale scenario)",
        },
    ]
    _build_pack(
        "stale_01",
        stale_entries,
        full_claims,
        ks,
        valid_until=_stale_valid_until.isoformat(),
        deterministic_ts=_stale_base.isoformat(),
    )
    outcomes["entries"].append({
        "name": "stale_01",
        "description": (
            "Stale pack: timestamps 120 days old, valid_until in the past. "
            "Integrity PASS, claims PASS, but freshness check FAIL"
        ),
        "expect_exit": 1,
        "run_cards": ["receipt_completeness", "guardian_enforcement"],
        "require_claim_pass": True,
        # --check-expiry causes verify-pack to check if valid_until is in the
        # past. Since valid_until is 2025-12-16 (well before any evaluation
        # time), this will trigger an honest failure (exit 1).
        "extra_verify_args": ["--check-expiry"],
        "freshness_note": (
            "valid_until is 2025-12-16T12:00:00+00:00, well before corpus "
            "evaluation. Verifiers should flag E_PACK_STALE or equivalent."
        ),
    })

    # --- superseded_01: valid pack that has been superseded by a newer one ---
    # All receipts valid, integrity PASS, claims PASS. The superseded_by field
    # in the attestation points to a fictional replacement pack_id. The pack
    # itself is fully valid (exit 0); the superseded status is informational
    # metadata that downstream consumers may use for credential chain traversal.
    print("Generating superseded_01: valid pack superseded by newer...")
    _superseded_replacement_id = (
        f"pack_deterministic_{hashlib.sha256(b'corpus_superseded_01_replacement').hexdigest()[:8]}"
    )
    superseded_entries = [
        _make_receipt(0, pack_name="superseded_01"),
        _make_receipt(1, pack_name="superseded_01"),
        _make_guardian(2, pack_name="superseded_01"),
    ]
    _build_pack(
        "superseded_01",
        superseded_entries,
        full_claims,
        ks,
        superseded_by=_superseded_replacement_id,
    )
    outcomes["entries"].append({
        "name": "superseded_01",
        "description": (
            "Superseded pack: integrity PASS, claims PASS, but attestation "
            "carries superseded_by pointing to a newer replacement pack. "
            "Exit 0 (pack is valid; superseded status is informational)"
        ),
        "expect_exit": 0,
        "run_cards": ["receipt_completeness", "guardian_enforcement"],
        "require_claim_pass": True,
        "superseded_by": _superseded_replacement_id,
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
