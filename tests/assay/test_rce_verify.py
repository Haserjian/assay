"""Tests for the recorded-trace RCE verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from typer.testing import CliRunner

from assay._receipts.canonicalize import prepare_receipt_for_hashing
from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.rce_verify import (
    RCE_REPLAY_RESULT_FILENAME,
    validate_rce_replay_result,
    verify_rce_pack,
    write_rce_replay_result,
)


_TS = "2026-04-06T12:00:00+00:00"
runner = CliRunner()


def _sha256_prefixed(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical_hash(payload: Any) -> str:
    return _sha256_prefixed(jcs_canonicalize(payload))


def _receipt_hash(receipt: Dict[str, Any]) -> str:
    return _sha256_prefixed(jcs_canonicalize(prepare_receipt_for_hashing(receipt)))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _make_keystore(tmp_path: Path) -> AssayKeyStore:
    ks = AssayKeyStore(tmp_path / "keys")
    ks.generate_key("test-signer")
    return ks


def _make_receipt(
    *,
    receipt_id: str,
    receipt_type: str,
    seq: int,
    payload: Dict[str, Any],
    parent_hashes: List[str],
    timestamp: str = _TS,
) -> Dict[str, Any]:
    receipt: Dict[str, Any] = {
        "receipt_id": receipt_id,
        "type": receipt_type,
        "timestamp": timestamp,
        "schema_version": "3.0",
        "seq": seq,
        "proof_tier": "core",
        "parent_hashes": parent_hashes,
        **payload,
    }
    receipt["receipt_hash"] = _receipt_hash(receipt)
    return receipt


def _episode_spec_hash(contract: Dict[str, Any]) -> str:
    replay_normative_environment = {
        "provider": contract["environment"]["provider"],
        "model_id": contract["environment"]["model_id"],
        "tool_versions": contract["environment"]["tool_versions"],
        "container_digest": contract["environment"]["container_digest"],
    }
    return _canonical_hash(
        {
            "inputs": contract["inputs"],
            "replay_script": contract["replay_script"],
            "replay_policy": contract["replay_policy"],
            "environment": replay_normative_environment,
        }
    )


def _build_basic_pack(tmp_path: Path, ks: AssayKeyStore) -> Tuple[Path, Dict[str, Any]]:
    episode_id = "ep_0123456789abcdef01234567"
    input_bytes = json.dumps({"value": 21}, separators=(",", ":")).encode("utf-8")
    input_ref = {
        "ref": "input.json",
        "hash": _sha256_prefixed(input_bytes),
        "media_type": "application/json",
    }
    environment = {
        "provider": "openai",
        "model_id": "gpt-4o",
        "tool_versions": {"assay": "1.20.2"},
        "container_digest": None,
    }
    environment["env_fingerprint_hash"] = _canonical_hash(environment)
    contract: Dict[str, Any] = {
        "schema_version": "rce/0.1",
        "episode_id": episode_id,
        "objective": "Double a structured input",
        "inputs": [input_ref],
        "replay_script": {
            "schema_version": "replay_script/0.1",
            "steps": [
                {
                    "step_id": "s01",
                    "opcode": "LOAD_INPUT",
                    "params": {"ref": "input.json"},
                    "depends_on": [],
                },
                {
                    "step_id": "s02",
                    "opcode": "APPLY_TRANSFORM",
                    "params": {"transform": "double"},
                    "depends_on": ["s01"],
                },
                {
                    "step_id": "s03",
                    "opcode": "EMIT_OUTPUT",
                    "params": {"claim_type": "demo", "output_ref": "s02"},
                    "depends_on": ["s02"],
                },
            ],
        },
        "replay_policy": {
            "replay_basis": "recorded_trace",
            "comparator_tier": "A",
        },
        "environment": environment,
    }

    load_output = {"value": 21}
    transform_output = {"value": 42}
    final_output = {"claim_type": "demo", "value": 42}

    s01_hash = _canonical_hash(load_output)
    s02_hash = _canonical_hash(transform_output)
    s03_hash = _canonical_hash(final_output)
    spec_hash = _episode_spec_hash(contract)
    inputs_hash = _canonical_hash(contract["inputs"])
    script_hash = _canonical_hash(contract["replay_script"])
    outputs_hash = _canonical_hash([{"step_id": "s03", "output_hash": s03_hash}])

    open_receipt = _make_receipt(
        receipt_id="r_ep_open_001",
        receipt_type="rce.episode_open/v0",
        seq=0,
        parent_hashes=[],
        payload={
            "episode_id": episode_id,
            "episode_spec_hash": spec_hash,
            "objective": contract["objective"],
            "inputs_hash": inputs_hash,
            "script_hash": script_hash,
            "env_fingerprint_hash": environment["env_fingerprint_hash"],
            "replay_basis": "recorded_trace",
            "comparator_tier": "A",
            "n_steps": 3,
        },
    )
    step_one = _make_receipt(
        receipt_id="r_ep_step_001",
        receipt_type="rce.episode_step/v0",
        seq=1,
        parent_hashes=[open_receipt["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s01",
            "opcode": "LOAD_INPUT",
            "step_status": "PASS",
            "input_hashes": [],
            "output_hash": s01_hash,
            "output_size_bytes": 12,
            "duration_ms": 1,
            "comparator_tier": "A",
        },
    )
    step_two = _make_receipt(
        receipt_id="r_ep_step_002",
        receipt_type="rce.episode_step/v0",
        seq=2,
        parent_hashes=[step_one["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s02",
            "opcode": "APPLY_TRANSFORM",
            "step_status": "PASS",
            "input_hashes": [s01_hash],
            "output_hash": s02_hash,
            "output_size_bytes": 12,
            "duration_ms": 2,
            "comparator_tier": "A",
            "provider": "openai",
            "model_id": "gpt-4o",
            "system_fingerprint": None,
        },
    )
    step_three = _make_receipt(
        receipt_id="r_ep_step_003",
        receipt_type="rce.episode_step/v0",
        seq=3,
        parent_hashes=[step_two["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s03",
            "opcode": "EMIT_OUTPUT",
            "step_status": "PASS",
            "input_hashes": [s02_hash],
            "output_hash": s03_hash,
            "output_size_bytes": 33,
            "duration_ms": 1,
            "comparator_tier": "A",
        },
    )
    close_receipt = _make_receipt(
        receipt_id="r_ep_close_001",
        receipt_type="rce.episode_close/v0",
        seq=4,
        parent_hashes=[step_three["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "episode_spec_hash": spec_hash,
            "outputs_hash": outputs_hash,
            "n_steps_executed": 3,
            "n_steps_passed": 3,
            "all_steps_passed": True,
            "replay_basis": "recorded_trace",
            "comparator_tier": "A",
        },
    )

    pack_dir = ProofPack(
        run_id="trace_rce_basic",
        entries=[open_receipt, step_one, step_two, step_three, close_receipt],
        signer_id="test-signer",
    ).build(tmp_path / "basic_pack", keystore=ks)

    _write_json(pack_dir / "episode_contract.json", contract)
    _write_json(pack_dir / "recorded_traces" / "s01.json", load_output)
    _write_json(pack_dir / "recorded_traces" / "s02.json", transform_output)
    _write_json(pack_dir / "recorded_traces" / "s03.json", final_output)
    (pack_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (pack_dir / "inputs" / "input.json").write_bytes(input_bytes)
    return pack_dir, contract


def _build_skipped_pack(tmp_path: Path, ks: AssayKeyStore) -> Path:
    episode_id = "ep_89abcdef0123456701234567"
    input_bytes = json.dumps({"value": 21}, separators=(",", ":")).encode("utf-8")
    input_ref = {
        "ref": "input.json",
        "hash": _sha256_prefixed(input_bytes),
        "media_type": "application/json",
    }
    environment = {
        "provider": "openai",
        "model_id": "gpt-4o",
        "tool_versions": {"assay": "1.20.2"},
        "container_digest": None,
    }
    environment["env_fingerprint_hash"] = _canonical_hash(environment)
    contract: Dict[str, Any] = {
        "schema_version": "rce/0.1",
        "episode_id": episode_id,
        "inputs": [input_ref],
        "replay_script": {
            "schema_version": "replay_script/0.1",
            "steps": [
                {"step_id": "s01", "opcode": "LOAD_INPUT", "params": {"ref": "input.json"}, "depends_on": []},
                {
                    "step_id": "s02",
                    "opcode": "ASSERT_HASH",
                    "params": {"target": "s01", "expected_hash": "sha256:" + ("f" * 64)},
                    "depends_on": ["s01"],
                },
                {"step_id": "s03", "opcode": "APPLY_TRANSFORM", "params": {"transform": "double"}, "depends_on": ["s02"]},
                {
                    "step_id": "s04",
                    "opcode": "EMIT_OUTPUT",
                    "params": {"claim_type": "demo", "output_ref": "s03"},
                    "depends_on": ["s03"],
                },
            ],
        },
        "replay_policy": {"replay_basis": "recorded_trace", "comparator_tier": "A"},
        "environment": environment,
    }

    load_output = {"value": 21}
    assert_output = {"assertion_passed": False}
    s01_hash = _canonical_hash(load_output)
    s02_hash = _canonical_hash(assert_output)
    spec_hash = _episode_spec_hash(contract)
    inputs_hash = _canonical_hash(contract["inputs"])
    script_hash = _canonical_hash(contract["replay_script"])
    outputs_hash = _canonical_hash([])

    open_receipt = _make_receipt(
        receipt_id="r_skip_open_001",
        receipt_type="rce.episode_open/v0",
        seq=0,
        parent_hashes=[],
        payload={
            "episode_id": episode_id,
            "episode_spec_hash": spec_hash,
            "inputs_hash": inputs_hash,
            "script_hash": script_hash,
            "env_fingerprint_hash": environment["env_fingerprint_hash"],
            "replay_basis": "recorded_trace",
            "comparator_tier": "A",
            "n_steps": 4,
        },
    )
    step_one = _make_receipt(
        receipt_id="r_skip_step_001",
        receipt_type="rce.episode_step/v0",
        seq=1,
        parent_hashes=[open_receipt["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s01",
            "opcode": "LOAD_INPUT",
            "step_status": "PASS",
            "input_hashes": [],
            "output_hash": s01_hash,
            "output_size_bytes": 12,
            "duration_ms": 1,
            "comparator_tier": "A",
        },
    )
    step_two = _make_receipt(
        receipt_id="r_skip_step_002",
        receipt_type="rce.episode_step/v0",
        seq=2,
        parent_hashes=[step_one["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s02",
            "opcode": "ASSERT_HASH",
            "step_status": "FAIL",
            "input_hashes": [s01_hash],
            "output_hash": s02_hash,
            "output_size_bytes": 27,
            "duration_ms": 1,
            "comparator_tier": "A",
            "assertion_passed": False,
        },
    )
    step_three = _make_receipt(
        receipt_id="r_skip_step_003",
        receipt_type="rce.episode_step/v0",
        seq=3,
        parent_hashes=[step_two["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s03",
            "opcode": "APPLY_TRANSFORM",
            "step_status": "SKIPPED",
            "input_hashes": [],
            "output_hash": None,
            "output_size_bytes": 0,
            "duration_ms": 0,
            "comparator_tier": "A",
        },
    )
    step_four = _make_receipt(
        receipt_id="r_skip_step_004",
        receipt_type="rce.episode_step/v0",
        seq=4,
        parent_hashes=[step_three["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s04",
            "opcode": "EMIT_OUTPUT",
            "step_status": "SKIPPED",
            "input_hashes": [],
            "output_hash": None,
            "output_size_bytes": 0,
            "duration_ms": 0,
            "comparator_tier": "A",
        },
    )
    close_receipt = _make_receipt(
        receipt_id="r_skip_close_001",
        receipt_type="rce.episode_close/v0",
        seq=5,
        parent_hashes=[step_four["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "episode_spec_hash": spec_hash,
            "outputs_hash": outputs_hash,
            "n_steps_executed": 2,
            "n_steps_passed": 1,
            "all_steps_passed": False,
            "replay_basis": "recorded_trace",
            "comparator_tier": "A",
        },
    )

    pack_dir = ProofPack(
        run_id="trace_rce_skipped",
        entries=[open_receipt, step_one, step_two, step_three, step_four, close_receipt],
        signer_id="test-signer",
    ).build(tmp_path / "skipped_pack", keystore=ks)

    _write_json(pack_dir / "episode_contract.json", contract)
    _write_json(pack_dir / "recorded_traces" / "s01.json", load_output)
    _write_json(pack_dir / "recorded_traces" / "s02.json", assert_output)
    (pack_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (pack_dir / "inputs" / "input.json").write_bytes(input_bytes)
    return pack_dir


def _build_failed_dependency_pack(tmp_path: Path, ks: AssayKeyStore) -> Path:
    episode_id = "ep_fedcba987654321001234567"
    input_bytes = json.dumps({"value": 21}, separators=(",", ":")).encode("utf-8")
    input_ref = {
        "ref": "input.json",
        "hash": _sha256_prefixed(input_bytes),
        "media_type": "application/json",
    }
    environment = {
        "provider": "openai",
        "model_id": "gpt-4o",
        "tool_versions": {"assay": "1.20.2"},
        "container_digest": None,
    }
    environment["env_fingerprint_hash"] = _canonical_hash(environment)
    contract: Dict[str, Any] = {
        "schema_version": "rce/0.1",
        "episode_id": episode_id,
        "inputs": [input_ref],
        "replay_script": {
            "schema_version": "replay_script/0.1",
            "steps": [
                {"step_id": "s01", "opcode": "LOAD_INPUT", "params": {"ref": "input.json"}, "depends_on": []},
                {
                    "step_id": "s02",
                    "opcode": "ASSERT_HASH",
                    "params": {"target": "s01", "expected_hash": "sha256:" + ("f" * 64)},
                    "depends_on": ["s01"],
                },
                {"step_id": "s03", "opcode": "APPLY_TRANSFORM", "params": {"transform": "double"}, "depends_on": ["s02"]},
                {
                    "step_id": "s04",
                    "opcode": "EMIT_OUTPUT",
                    "params": {"claim_type": "demo", "output_ref": "s03"},
                    "depends_on": ["s03"],
                },
            ],
        },
        "replay_policy": {"replay_basis": "recorded_trace", "comparator_tier": "A"},
        "environment": environment,
    }

    load_output = {"value": 21}
    assert_output = {"assertion_passed": False}
    transform_output = {"value": 42}
    final_output = {"claim_type": "demo", "value": 42}
    s01_hash = _canonical_hash(load_output)
    s02_hash = _canonical_hash(assert_output)
    s03_hash = _canonical_hash(transform_output)
    s04_hash = _canonical_hash(final_output)
    spec_hash = _episode_spec_hash(contract)
    inputs_hash = _canonical_hash(contract["inputs"])
    script_hash = _canonical_hash(contract["replay_script"])
    outputs_hash = _canonical_hash([{"step_id": "s04", "output_hash": s04_hash}])

    open_receipt = _make_receipt(
        receipt_id="r_block_open_001",
        receipt_type="rce.episode_open/v0",
        seq=0,
        parent_hashes=[],
        payload={
            "episode_id": episode_id,
            "episode_spec_hash": spec_hash,
            "inputs_hash": inputs_hash,
            "script_hash": script_hash,
            "env_fingerprint_hash": environment["env_fingerprint_hash"],
            "replay_basis": "recorded_trace",
            "comparator_tier": "A",
            "n_steps": 4,
        },
    )
    step_one = _make_receipt(
        receipt_id="r_block_step_001",
        receipt_type="rce.episode_step/v0",
        seq=1,
        parent_hashes=[open_receipt["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s01",
            "opcode": "LOAD_INPUT",
            "step_status": "PASS",
            "input_hashes": [],
            "output_hash": s01_hash,
            "output_size_bytes": 12,
            "duration_ms": 1,
            "comparator_tier": "A",
        },
    )
    step_two = _make_receipt(
        receipt_id="r_block_step_002",
        receipt_type="rce.episode_step/v0",
        seq=2,
        parent_hashes=[step_one["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s02",
            "opcode": "ASSERT_HASH",
            "step_status": "FAIL",
            "input_hashes": [s01_hash],
            "output_hash": s02_hash,
            "output_size_bytes": 27,
            "duration_ms": 1,
            "comparator_tier": "A",
            "assertion_passed": False,
        },
    )
    step_three = _make_receipt(
        receipt_id="r_block_step_003",
        receipt_type="rce.episode_step/v0",
        seq=3,
        parent_hashes=[step_two["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s03",
            "opcode": "APPLY_TRANSFORM",
            "step_status": "PASS",
            "input_hashes": [s02_hash],
            "output_hash": s03_hash,
            "output_size_bytes": 12,
            "duration_ms": 1,
            "comparator_tier": "A",
            "provider": "openai",
            "model_id": "gpt-4o",
            "system_fingerprint": None,
        },
    )
    step_four = _make_receipt(
        receipt_id="r_block_step_004",
        receipt_type="rce.episode_step/v0",
        seq=4,
        parent_hashes=[step_three["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "step_id": "s04",
            "opcode": "EMIT_OUTPUT",
            "step_status": "PASS",
            "input_hashes": [s03_hash],
            "output_hash": s04_hash,
            "output_size_bytes": 33,
            "duration_ms": 1,
            "comparator_tier": "A",
        },
    )
    close_receipt = _make_receipt(
        receipt_id="r_block_close_001",
        receipt_type="rce.episode_close/v0",
        seq=5,
        parent_hashes=[step_four["receipt_hash"]],
        payload={
            "episode_id": episode_id,
            "episode_spec_hash": spec_hash,
            "outputs_hash": outputs_hash,
            "n_steps_executed": 4,
            "n_steps_passed": 3,
            "all_steps_passed": False,
            "replay_basis": "recorded_trace",
            "comparator_tier": "A",
        },
    )

    pack_dir = ProofPack(
        run_id="trace_rce_failed_dependency",
        entries=[open_receipt, step_one, step_two, step_three, step_four, close_receipt],
        signer_id="test-signer",
    ).build(tmp_path / "failed_dependency_pack", keystore=ks)

    _write_json(pack_dir / "episode_contract.json", contract)
    _write_json(pack_dir / "recorded_traces" / "s01.json", load_output)
    _write_json(pack_dir / "recorded_traces" / "s02.json", assert_output)
    _write_json(pack_dir / "recorded_traces" / "s03.json", transform_output)
    _write_json(pack_dir / "recorded_traces" / "s04.json", final_output)
    (pack_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (pack_dir / "inputs" / "input.json").write_bytes(input_bytes)
    return pack_dir


class TestRCEVerify:
    def test_match_for_valid_recorded_trace_pack(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        pack_dir, _ = _build_basic_pack(tmp_path, ks)

        receipt, details, exit_code = verify_rce_pack(pack_dir, keystore=ks, issued_at=_TS)

        assert exit_code == 0
        assert receipt["verdict"] == "MATCH"
        assert receipt["receipt_integrity"] == "PASS"
        assert receipt["claim_check"] == "PASS"
        assert receipt["steps_replayed"] == 3
        assert receipt["steps_matched"] == 3
        assert receipt["steps_diverged"] == 0
        assert receipt["divergent_step_ids"] == []
        assert len(receipt["parent_hashes"]) == 1
        assert details["phase"] == 4
        assert validate_rce_replay_result(receipt) == []

    def test_diverge_collects_all_mismatched_steps(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        pack_dir, _ = _build_basic_pack(tmp_path, ks)

        _write_json(pack_dir / "recorded_traces" / "s02.json", {"value": 99})
        _write_json(pack_dir / "recorded_traces" / "s03.json", {"claim_type": "demo", "value": 99})

        receipt, details, exit_code = verify_rce_pack(pack_dir, keystore=ks, issued_at=_TS)

        assert exit_code == 1
        assert receipt["verdict"] == "DIVERGE"
        assert receipt["claim_check"] == "FAIL"
        assert receipt["steps_diverged"] == 2
        assert receipt["divergent_step_ids"] == ["s02", "s03"]
        assert receipt["dispute"]["divergent_steps"][0]["step_id"] == "s02"
        assert receipt["dispute"]["divergent_steps"][1]["step_id"] == "s03"
        assert details["phase"] == 4
        assert len(details["divergent_steps"]) == 2

    def test_integrity_fail_when_contract_hashes_do_not_match_receipts(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        pack_dir, contract = _build_basic_pack(tmp_path, ks)
        contract["replay_script"]["steps"][1]["params"]["transform"] = "triple"
        _write_json(pack_dir / "episode_contract.json", contract)

        receipt, details, exit_code = verify_rce_pack(pack_dir, keystore=ks, issued_at=_TS)

        assert exit_code == 2
        assert receipt["verdict"] == "INTEGRITY_FAIL"
        assert receipt["receipt_integrity"] == "FAIL"
        assert receipt["claim_check"] is None
        assert len(receipt["parent_hashes"]) == 1
        assert details["phase"] == 3
        assert any("script_hash" in error for error in details["errors"])

    def test_skipped_steps_are_excluded_from_replay_comparison(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        pack_dir = _build_skipped_pack(tmp_path, ks)

        receipt, details, exit_code = verify_rce_pack(pack_dir, keystore=ks, issued_at=_TS)

        assert exit_code == 0
        assert receipt["verdict"] == "MATCH"
        assert receipt["steps_replayed"] == 2
        assert receipt["steps_matched"] == 2
        assert receipt["steps_diverged"] == 0
        assert details["errors"] == []

    def test_failed_steps_must_block_dependents(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        pack_dir = _build_failed_dependency_pack(tmp_path, ks)

        receipt, details, exit_code = verify_rce_pack(pack_dir, keystore=ks, issued_at=_TS)

        assert exit_code == 2
        assert receipt["verdict"] == "INTEGRITY_FAIL"
        assert receipt["claim_check"] is None
        assert details["phase"] == 3
        assert any("must be SKIPPED" in error for error in details["errors"])

    def test_writer_materializes_receipt_and_details(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        pack_dir, _ = _build_basic_pack(tmp_path, ks)

        result = write_rce_replay_result(
            pack_dir=pack_dir,
            out_dir=tmp_path / "out",
            keystore=ks,
            issued_at=_TS,
            pretty=True,
        )

        assert result.receipt_path.name == RCE_REPLAY_RESULT_FILENAME
        assert result.receipt_path.exists()
        assert result.details_path.exists()
        assert json.loads(result.receipt_path.read_text())["verdict"] == "MATCH"


class TestRCEVerifyCLI:
    def test_cli_emits_json_and_exit_code(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        pack_dir, _ = _build_basic_pack(tmp_path, ks)

        result = runner.invoke(
            assay_app,
            [
                "rce-verify",
                str(pack_dir),
                "--out-dir",
                str(tmp_path / "out"),
                "--json",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["command"] == "rce-verify"
        assert payload["verdict"] == "MATCH"
