"""Adversarial attack suite: 15 canned attacks that the verifier must catch.

Each test simulates a specific attacker strategy against proof packs or
VendorQ answer payloads. Every attack must produce a deterministic error
code. This suite is the "trust under attack" demo for enterprise buyers.

Attack categories:
  A1-A5:  Receipt chain / sequence attacks
  A6-A8:  Evidence substitution / replay attacks
  A9-A11: Policy bypass attacks
  A12-A15: VendorQ-specific attacks
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from assay.claim_verifier import ClaimSpec
from assay.integrity import (
    E_MANIFEST_TAMPER,
    E_PACK_OMISSION_DETECTED,
    E_PACK_SIG_INVALID,
    E_PACK_STALE,
    E_TIMESTAMP_INVALID,
    verify_pack_manifest,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.vendorq_compile import compile_answers_payload
from assay.vendorq_index import build_evidence_index
from assay.vendorq_lock import write_vendorq_lock
from assay.vendorq_verify import verify_answers_payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _receipt(**overrides):
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
    }
    base.update(overrides)
    return base


def _build_pack(tmp_path, ks, receipts, *, signer="atk-signer", mode="shadow"):
    claims = [
        ClaimSpec(
            claim_id="has_model_calls",
            description="At least one model_call",
            check="receipt_type_present",
            params={"receipt_type": "model_call"},
        ),
    ]
    pack = ProofPack(
        run_id="adversarial-test",
        entries=receipts,
        signer_id=signer,
        claims=claims,
        mode=mode,
    )
    return pack.build(tmp_path / f"pack_{uuid.uuid4().hex[:6]}", keystore=ks)


def _copy(pack_dir, tmp_path, suffix="corrupt"):
    dest = tmp_path / suffix
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(pack_dir, dest)
    return dest


def _verify(pack_dir, ks, **kwargs):
    manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
    return verify_pack_manifest(manifest, pack_dir, ks, **kwargs)


@pytest.fixture
def ks(tmp_path):
    store = AssayKeyStore(keys_dir=tmp_path / "keys")
    store.generate_key("atk-signer")
    return store


@pytest.fixture
def valid_pack(tmp_path, ks):
    receipts = [
        _receipt(seq=i, receipt_id=f"r_{i:04d}")
        for i in range(5)
    ]
    return _build_pack(tmp_path, ks, receipts), ks


# ---------------------------------------------------------------------------
# A1: Dropped step -- remove a receipt from the middle of the chain
# ---------------------------------------------------------------------------

class TestA1DroppedStep:
    """Attacker removes an inconvenient receipt (e.g. a failed model call)
    from receipt_pack.jsonl while keeping the rest intact."""

    def test_dropped_receipt_detected(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy(pack_dir, tmp_path)

        # Remove middle receipt (seq=2)
        rp = corrupt / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        assert len(lines) == 5
        del lines[2]  # drop seq=2
        rp.write_text("\n".join(lines) + "\n")

        result = _verify(corrupt, ks)
        assert not result.passed
        error_codes = {e.code for e in result.errors}
        assert E_MANIFEST_TAMPER in error_codes or E_PACK_OMISSION_DETECTED in error_codes


# ---------------------------------------------------------------------------
# A2: Reordered steps -- shuffle receipts to hide execution order
# ---------------------------------------------------------------------------

class TestA2ReorderedSteps:
    """Attacker reorders receipts to disguise the actual execution sequence."""

    def test_reordered_receipts_detected(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy(pack_dir, tmp_path)

        rp = corrupt / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        # Reverse order
        lines.reverse()
        rp.write_text("\n".join(lines) + "\n")

        result = _verify(corrupt, ks)
        assert not result.passed
        # Reordering changes the file hash
        assert any(e.code == E_MANIFEST_TAMPER for e in result.errors)


# ---------------------------------------------------------------------------
# A3: Receipt injection -- insert a fabricated receipt
# ---------------------------------------------------------------------------

class TestA3ReceiptInjection:
    """Attacker injects a fabricated receipt to inflate evidence."""

    def test_injected_receipt_detected(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy(pack_dir, tmp_path)

        rp = corrupt / "receipt_pack.jsonl"
        fake = json.dumps({
            "receipt_id": "r_fake_injected",
            "type": "model_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 99,
        })
        rp.write_text(rp.read_text() + fake + "\n")

        result = _verify(corrupt, ks)
        assert not result.passed
        error_codes = {e.code for e in result.errors}
        # Hash mismatch or count mismatch
        assert E_MANIFEST_TAMPER in error_codes or E_PACK_OMISSION_DETECTED in error_codes


# ---------------------------------------------------------------------------
# A4: Timestamp rollback -- backdate receipts to appear fresher
# ---------------------------------------------------------------------------

class TestA4TimestampRollback:
    """Attacker changes timestamps on receipts to defeat staleness checks."""

    def test_backdated_receipts_hash_mismatch(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy(pack_dir, tmp_path)

        rp = corrupt / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        modified = []
        for line in lines:
            obj = json.loads(line)
            # Backdate all receipts
            obj["timestamp"] = datetime.now(timezone.utc).isoformat()
            modified.append(json.dumps(obj))
        rp.write_text("\n".join(modified) + "\n")

        result = _verify(corrupt, ks)
        assert not result.passed
        assert any(e.code == E_MANIFEST_TAMPER for e in result.errors)


# ---------------------------------------------------------------------------
# A5: Stale evidence replay -- use a valid old pack as current
# ---------------------------------------------------------------------------

class TestA5StaleEvidenceReplay:
    """Attacker submits an old pack as if it were current."""

    def test_stale_pack_rejected(self, tmp_path, ks):
        # Build a pack with old timestamps
        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        receipts = [
            _receipt(seq=i, receipt_id=f"r_old_{i}", timestamp=old_time)
            for i in range(3)
        ]
        pack_dir = _build_pack(tmp_path, ks, receipts)

        # Verify with max_age_hours=24 -- pack is 48h old
        result = _verify(pack_dir, ks, max_age_hours=24)
        assert not result.passed
        assert any(e.code == E_PACK_STALE for e in result.errors)


# ---------------------------------------------------------------------------
# A5b: Future-dated evidence -- complicit signer embeds future timestamps
# ---------------------------------------------------------------------------

class TestA5bFutureTimestampRejection:
    """Complicit signer embeds receipts dated far in the future.

    Without a future-timestamp bound, an attacker can pre-date evidence
    to appear more recent than it is, or create receipts with timestamps
    that haven't occurred yet. The default max_future_hours=24 should
    catch anything >24h ahead.
    """

    def test_future_timestamp_rejected_by_default(self, tmp_path, ks):
        """Pack with attestation 48h in the future should fail."""
        future_time = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
        receipts = [
            _receipt(seq=i, receipt_id=f"r_future_{i}", timestamp=future_time)
            for i in range(3)
        ]
        pack_dir = _build_pack(tmp_path, ks, receipts)

        # Default max_future_hours=24, pack is 48h in the future
        result = _verify(pack_dir, ks)
        assert not result.passed
        assert any(e.code == E_TIMESTAMP_INVALID for e in result.errors)

    def test_near_future_timestamp_accepted(self, tmp_path, ks):
        """Pack with attestation 1h in the future should pass (within 24h tolerance)."""
        near_future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        receipts = [
            _receipt(seq=i, receipt_id=f"r_nearfut_{i}", timestamp=near_future)
            for i in range(3)
        ]
        pack_dir = _build_pack(tmp_path, ks, receipts)

        result = _verify(pack_dir, ks)
        assert result.passed, f"Near-future pack should pass: {[e.message for e in result.errors]}"

    def test_future_guard_disabled_with_zero(self, tmp_path, ks):
        """max_future_hours=0 disables the guard."""
        future_time = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
        receipts = [
            _receipt(seq=i, receipt_id=f"r_nofut_{i}", timestamp=future_time)
            for i in range(3)
        ]
        pack_dir = _build_pack(tmp_path, ks, receipts)

        result = _verify(pack_dir, ks, max_future_hours=0)
        # With guard disabled, the future timestamp alone shouldn't cause failure
        future_errors = [e for e in result.errors if "future" in e.message.lower()]
        assert len(future_errors) == 0


# ---------------------------------------------------------------------------
# A6: Cross-signer forgery -- sign with wrong key
# ---------------------------------------------------------------------------

class TestA6CrossSignerForgery:
    """Attacker signs a pack with their own key, not the authorized signer.

    At L0 (no lockfile), portable verification uses the embedded pubkey,
    so any signer can produce a valid pack. The signer allowlist is enforced
    at L1+ via the lockfile's signer_policy. This test verifies that:
    (a) L0 passes (by design -- no signer restriction without lockfile)
    (b) Lockfile with allowlist catches the wrong signer fingerprint
    """

    def test_wrong_signer_caught_by_lockfile(self, tmp_path):
        from assay.lockfile import validate_against_lock

        attacker_ks = AssayKeyStore(keys_dir=tmp_path / "attacker_keys")
        attacker_ks.generate_key("atk-signer")

        receipts = [_receipt(seq=i) for i in range(3)]
        pack_dir = _build_pack(tmp_path, attacker_ks, receipts, signer="atk-signer")

        # L0: portable verify passes (embedded pubkey, no signer restriction)
        result_l0 = _verify(pack_dir, attacker_ks)
        assert result_l0.passed, "L0 should pass with any signer"

        # L1: lockfile with allowlist rejects wrong signer
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        # Use a fabricated "legitimate" fingerprint that does NOT match attacker's
        fake_legit_fp = "0" * 64

        lockfile = {
            "lock_version": "1.0",
            "assay_version_min": "0.0.0",
            "pack_format_version": manifest.get("attestation", {}).get("pack_format_version", "0.1.0"),
            "run_cards": [],
            "run_cards_composite_hash": hashlib.sha256(b"[]").hexdigest(),
            "claim_set_hash": manifest.get("claim_set_hash", hashlib.sha256(b"[]").hexdigest()),
            "exit_contract": {"pass": 0, "fail": 1, "tampered": 2},
            "signer_policy": {
                "mode": "allowlist",
                "allowed_fingerprints": [fake_legit_fp],
            },
        }
        result = validate_against_lock(manifest, lockfile)
        assert not result.passed, f"Lockfile should reject wrong signer, got: {result}"
        signer_error = any("signer" in str(e).lower() or "fingerprint" in str(e).lower()
                           for e in result.errors)
        assert signer_error, f"Expected signer rejection, got: {result.errors}"


# ---------------------------------------------------------------------------
# A7: Evidence substitution -- swap receipt_pack.jsonl between two valid packs
# ---------------------------------------------------------------------------

class TestA7EvidenceSubstitution:
    """Attacker swaps receipt contents from a different valid pack."""

    def test_substituted_receipts_detected(self, tmp_path, ks):
        receipts_a = [_receipt(seq=i, receipt_id=f"r_a{i}") for i in range(3)]
        receipts_b = [_receipt(seq=i, receipt_id=f"r_b{i}") for i in range(3)]

        pack_a = _build_pack(tmp_path, ks, receipts_a)
        pack_b = _build_pack(tmp_path, ks, receipts_b)

        # Swap: put pack_b's receipts into pack_a's directory
        corrupt = _copy(pack_a, tmp_path, suffix="swapped")
        shutil.copy(pack_b / "receipt_pack.jsonl", corrupt / "receipt_pack.jsonl")

        result = _verify(corrupt, ks)
        assert not result.passed
        assert any(e.code == E_MANIFEST_TAMPER for e in result.errors)


# ---------------------------------------------------------------------------
# A8: Replayed receipt -- duplicate a receipt across packs
# ---------------------------------------------------------------------------

class TestA8ReplayedReceipt:
    """Attacker duplicates a legitimate receipt into a different pack."""

    def test_replayed_receipt_changes_hash(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy(pack_dir, tmp_path)

        rp = corrupt / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        # Append a duplicate of the first receipt
        lines.append(lines[0])
        rp.write_text("\n".join(lines) + "\n")

        result = _verify(corrupt, ks)
        assert not result.passed
        error_codes = {e.code for e in result.errors}
        assert E_MANIFEST_TAMPER in error_codes or E_PACK_OMISSION_DETECTED in error_codes


# ---------------------------------------------------------------------------
# A9: Manifest receipt count lie -- claim fewer receipts than exist
# ---------------------------------------------------------------------------

class TestA9ReceiptCountLie:
    """Attacker modifies receipt_count_expected in manifest to hide extras."""

    def test_count_mismatch_invalidates_signature(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy(pack_dir, tmp_path)

        mp = corrupt / "pack_manifest.json"
        data = json.loads(mp.read_text())
        data["receipt_count_expected"] = 1  # actual is 5
        mp.write_text(json.dumps(data))

        result = _verify(corrupt, ks)
        assert not result.passed
        # Manifest was modified post-signing
        assert any(e.code == E_PACK_SIG_INVALID for e in result.errors)


# ---------------------------------------------------------------------------
# A10: Attestation integrity lie -- claim PASS when receipts are corrupt
# ---------------------------------------------------------------------------

class TestA10AttestationIntegrityLie:
    """Attacker sets receipt_integrity=PASS in attestation but corrupts receipts."""

    def test_integrity_lie_caught_by_signature(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy(pack_dir, tmp_path)

        # Corrupt receipts
        rp = corrupt / "receipt_pack.jsonl"
        rp.write_text('{"receipt_id":"fake","type":"model_call","timestamp":"2026-01-01T00:00:00Z","schema_version":"3.0"}\n')

        # Try to update manifest hash for receipts (but attestation still says PASS)
        mp = corrupt / "pack_manifest.json"
        data = json.loads(mp.read_text())
        new_hash = hashlib.sha256(rp.read_bytes()).hexdigest()
        for f in data.get("files", []):
            if f["path"] == "receipt_pack.jsonl":
                f["sha256"] = new_hash
                f["bytes"] = len(rp.read_bytes())
        mp.write_text(json.dumps(data))

        result = _verify(corrupt, ks)
        assert not result.passed
        # Manifest modified -> signature invalid
        assert any(e.code == E_PACK_SIG_INVALID for e in result.errors)


# ---------------------------------------------------------------------------
# A11-A15: VendorQ-specific attacks
# Uses the same test pattern as test_vendorq_verify.py:
#   build real pack → build evidence index → compile answers → tamper → verify
# ---------------------------------------------------------------------------

def _vq_base(tmp_path):
    """Build a valid VendorQ test setup: pack + evidence index + answers."""
    ks = AssayKeyStore(keys_dir=tmp_path / "vq_keys")
    ks.generate_key("vq-atk")
    receipts = [
        {
            "receipt_id": "r1",
            "type": "model_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 1,
            "model_id": "gpt-4",
            "provider": "openai",
            "input_tokens": 7,
            "output_tokens": 3,
            "total_tokens": 10,
        }
    ]
    pack = ProofPack(run_id="vq-atk-run", entries=receipts, signer_id="vq-atk")
    pack_dir = pack.build(tmp_path / "vq_pack", keystore=ks)
    idx = build_evidence_index([pack_dir])
    questions = {
        "schema_version": "vendorq.question.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "test",
        "questions": [
            {"question_id": "Q1", "question_text": "Do you produce audit trails?",
             "type_hint": "yes_no", "required_format": "text"},
        ],
        "questions_hash": "a" * 64,
    }
    answers = compile_answers_payload(questions, idx, "conservative")
    return pack_dir, idx, answers


class TestA11UpgradedStatusWithoutEvidence:
    """Attacker upgrades PARTIAL to ANSWERED without adding evidence."""

    def test_vq001_catches_missing_citation(self, tmp_path):
        _pack_dir, idx, answers = _vq_base(tmp_path)
        bad = copy.deepcopy(answers)
        bad["answers"][0]["status"] = "ANSWERED"
        bad["answers"][0]["evidence_refs"] = []
        bad["answers"][0]["missing_evidence_requests"] = []
        report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
        error_codes = {e["code"] for e in report["errors"]}
        assert "VQ001_MISSING_CITATION" in error_codes


class TestA12ProhibitedTermInjection:
    """Attacker injects commitment language to make answers sound stronger."""

    def test_vq005_catches_guarantee(self, tmp_path):
        _pack_dir, idx, answers = _vq_base(tmp_path)
        bad = copy.deepcopy(answers)
        bad["answers"][0]["claim_type"] = "COMMITMENT"
        bad["answers"][0]["details"] = "We guarantee 100% uptime for all AI systems."
        report = verify_answers_payload(bad, idx, policy_name="balanced", strict=True)
        error_codes = {e["code"] for e in report["errors"]}
        assert "VQ005_PROHIBITED_COMMITMENT" in error_codes

    def test_vq005_catches_always(self, tmp_path):
        _pack_dir, idx, answers = _vq_base(tmp_path)
        bad = copy.deepcopy(answers)
        bad["answers"][0]["claim_type"] = "COMMITMENT"
        bad["answers"][0]["details"] = "Our system will always produce accurate results."
        report = verify_answers_payload(bad, idx, policy_name="balanced", strict=True)
        error_codes = {e["code"] for e in report["errors"]}
        assert "VQ005_PROHIBITED_COMMITMENT" in error_codes


class TestA13CommitmentClaimTypeBypass:
    """Attacker uses COMMITMENT claim type under conservative policy."""

    def test_vq010_blocks_commitment_under_conservative(self, tmp_path):
        _pack_dir, idx, answers = _vq_base(tmp_path)
        bad = copy.deepcopy(answers)
        bad["answers"][0]["claim_type"] = "COMMITMENT"
        report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
        error_codes = {e["code"] for e in report["errors"]}
        assert "VQ010_CLAIM_TYPE_POLICY_VIOLATION" in error_codes


class TestA14LockfileHashSwap:
    """Attacker modifies answers after lockfile was pinned."""

    def test_vq003_catches_lock_mismatch(self, tmp_path):
        _pack_dir, idx, answers = _vq_base(tmp_path)
        lock_path = tmp_path / "vendorq.lock"
        lock_payload = write_vendorq_lock(answers, idx, lock_path)

        # Tamper: change the answer after lock was written
        bad = copy.deepcopy(answers)
        bad["answers"][0]["answer_bool"] = True
        bad["answers"][0]["status"] = "ANSWERED"
        bad["answers"][0]["details"] = "Tampered answer to claim full compliance"

        report = verify_answers_payload(bad, idx, policy_name="conservative",
                                        strict=True, lock_payload=lock_payload)
        error_codes = {e["code"] for e in report["errors"]}
        assert "VQ003_PACK_HASH_MISMATCH" in error_codes


class TestA15InsufficientEvidenceWithTrueAssert:
    """Attacker marks INSUFFICIENT_EVIDENCE but sets answer_bool=true."""

    def test_vq008_catches_inconsistent_status(self, tmp_path):
        _pack_dir, idx, answers = _vq_base(tmp_path)
        bad = copy.deepcopy(answers)
        bad["answers"][0]["status"] = "INSUFFICIENT_EVIDENCE"
        bad["answers"][0]["answer_bool"] = True
        bad["answers"][0]["evidence_refs"] = []
        report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
        error_codes = {e["code"] for e in report["errors"]}
        assert "VQ008_ANSWER_STATUS_INVALID_FOR_CONTENT" in error_codes
