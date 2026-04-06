"""Recorded-trace verifier for Replay-Constrained Episodes.

This module implements the minimal v0 verifier described by the RCE profile:

- Phase 1: script validation
- Phase 2: proof-pack integrity
- Phase 3: artifact and receipt completeness
- Phase 4: recorded-trace comparison

The current Assay proof-pack kernel does not yet wrap replay verifier outputs
into a second signed proof pack. The writer therefore emits a standalone
``rce.replay_result/v0`` receipt JSON plus a machine-readable details sidecar.
The receipt stays structurally aligned to the profile, while
``dispute.replay_pack_root_sha256`` remains ``null`` until replay-bundle
packing is added.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, cast

from jsonschema import Draft7Validator

try:
    from assay import __version__ as _assay_version
except Exception:
    _assay_version = "0.1.0"

from assay._receipts.canonicalize import prepare_receipt_for_hashing
from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.keystore import AssayKeyStore, get_default_keystore
from assay.proof_pack import verify_proof_pack


EPISODE_CONTRACT_FILENAME = "episode_contract.json"
INPUTS_DIRNAME = "inputs"
RECORDED_TRACES_DIRNAME = "recorded_traces"
RCE_REPLAY_RESULT_FILENAME = "rce_replay_result.json"
RCE_REPLAY_DETAILS_FILENAME = "rce_replay_details.json"

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_CONTRACT_SCHEMA = "rce_episode_contract.schema.json"
_REPLAY_RESULT_SCHEMA = "rce_replay_result_v0.1.schema.json"

_OPEN_RECEIPT_TYPE = "rce.episode_open/v0"
_STEP_RECEIPT_TYPE = "rce.episode_step/v0"
_CLOSE_RECEIPT_TYPE = "rce.episode_close/v0"
_REPLAY_RESULT_RECEIPT_TYPE = "rce.replay_result/v0"

_STEP_STATUS_PASS = "PASS"
_STEP_STATUS_FAIL = "FAIL"
_STEP_STATUS_SKIPPED = "SKIPPED"

_VERDICT_MATCH = "MATCH"
_VERDICT_DIVERGE = "DIVERGE"
_VERDICT_INTEGRITY_FAIL = "INTEGRITY_FAIL"

_VALID_STATUSES = {
    _STEP_STATUS_PASS,
    _STEP_STATUS_FAIL,
    _STEP_STATUS_SKIPPED,
}


@dataclass(frozen=True)
class RCEVerifyResult:
    """Materialized verifier output written to disk."""

    verdict: str
    exit_code: int
    receipt: Dict[str, Any]
    details: Dict[str, Any]
    receipt_path: Path
    details_path: Path


@dataclass(frozen=True)
class _PhaseFailure(Exception):
    phase: int
    errors: Tuple[str, ...]
    parent_hashes: Tuple[str, ...] = ()


_contract_validator: Optional[Draft7Validator] = None
_replay_result_validator: Optional[Draft7Validator] = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_prefixed(data: bytes) -> str:
    return f"sha256:{_sha256_hex(data)}"


def _canonical_sha256(value: Any) -> str:
    return _sha256_prefixed(jcs_canonicalize(value))


def _canonical_receipt_hash(receipt: Mapping[str, Any]) -> str:
    return _sha256_prefixed(jcs_canonicalize(prepare_receipt_for_hashing(dict(receipt))))


def _load_schema_validator(schema_name: str) -> Draft7Validator:
    schema_path = _SCHEMA_DIR / schema_name
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return Draft7Validator(schema)


def _contract_validator_instance() -> Draft7Validator:
    global _contract_validator
    if _contract_validator is None:
        _contract_validator = _load_schema_validator(_CONTRACT_SCHEMA)
    return _contract_validator


def _replay_result_validator_instance() -> Draft7Validator:
    global _replay_result_validator
    if _replay_result_validator is None:
        _replay_result_validator = _load_schema_validator(_REPLAY_RESULT_SCHEMA)
    return _replay_result_validator


def _schema_errors(validator: Draft7Validator, payload: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    for error in sorted(validator.iter_errors(dict(payload)), key=lambda item: list(item.path)):
        path = ".".join(str(part) for part in error.absolute_path) or "(root)"
        errors.append(f"{path}: {error.message}")
    return errors


def _safe_relative_path(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValueError(f"Unsafe relative path: {name}")
    return path


def _resolve_under(root: Path, relative: Path) -> Path:
    resolved_root = root.resolve()
    resolved_path = (resolved_root / relative).resolve()
    resolved_path.relative_to(resolved_root)
    return resolved_path


def _json_dict(path: Path) -> Dict[str, Any]:
    return cast(Dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _receipt_type(receipt: Mapping[str, Any]) -> str:
    return str(receipt.get("type") or receipt.get("receipt_type") or "")


def _receipt_payload(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = receipt.get("payload")
    if isinstance(payload, Mapping):
        return cast(Mapping[str, Any], payload)
    return receipt


def _payload_string(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    return str(value) if value is not None else ""


def _as_prefixed_sha256(value: Any, *, field_name: str) -> str:
    text = str(value or "")
    if text.startswith("sha256:"):
        raw = text.split(":", 1)[1]
        if len(raw) == 64 and all(ch in "0123456789abcdef" for ch in raw):
            return text
    elif len(text) == 64 and all(ch in "0123456789abcdef" for ch in text):
        return f"sha256:{text}"
    raise ValueError(f"{field_name} must be sha256:<64 lowercase hex>")


def _compute_episode_spec_hash(contract: Mapping[str, Any]) -> str:
    environment = cast(Mapping[str, Any], contract["environment"])
    replay_normative_environment = {
        "provider": environment.get("provider"),
        "model_id": environment.get("model_id"),
        "tool_versions": environment.get("tool_versions"),
        "container_digest": environment.get("container_digest"),
    }
    replay_normative_view = {
        "inputs": contract.get("inputs"),
        "replay_script": contract.get("replay_script"),
        "replay_policy": contract.get("replay_policy"),
        "environment": replay_normative_environment,
    }
    return _canonical_sha256(replay_normative_view)


def _compute_env_fingerprint_hash(environment: Mapping[str, Any]) -> str:
    env_input = {
        "provider": environment.get("provider"),
        "model_id": environment.get("model_id"),
        "tool_versions": environment.get("tool_versions"),
        "container_digest": environment.get("container_digest"),
    }
    return _canonical_sha256(env_input)


def _compute_inputs_hash(contract: Mapping[str, Any]) -> str:
    return _canonical_sha256(contract.get("inputs"))


def _compute_script_hash(contract: Mapping[str, Any]) -> str:
    return _canonical_sha256(contract.get("replay_script"))


def _compute_outputs_hash(step_payloads: Mapping[str, Mapping[str, Any]]) -> str:
    outputs: List[Dict[str, Any]] = []
    for payload in step_payloads.values():
        if payload.get("opcode") != "EMIT_OUTPUT":
            continue
        if payload.get("step_status") != _STEP_STATUS_PASS:
            continue
        outputs.append(
            {
                "step_id": _payload_string(payload, "step_id"),
                "output_hash": payload.get("output_hash"),
            }
        )
    outputs.sort(key=lambda item: str(item["step_id"]))
    return _canonical_sha256(outputs)


def _verifier_env_hash(verifier_id: str, verifier_version: str) -> str:
    verifier_env = {
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "verifier_id": verifier_id,
        "verifier_version": verifier_version,
    }
    return _canonical_sha256(verifier_env)


def validate_rce_replay_result(receipt: Mapping[str, Any]) -> List[str]:
    """Validate an emitted replay-result receipt."""

    errors = _schema_errors(_replay_result_validator_instance(), receipt)

    verdict = receipt.get("verdict")
    claim_check = receipt.get("claim_check")
    receipt_integrity = receipt.get("receipt_integrity")
    steps_replayed = int(receipt.get("steps_replayed", 0) or 0)
    steps_matched = int(receipt.get("steps_matched", 0) or 0)
    steps_diverged = int(receipt.get("steps_diverged", 0) or 0)
    divergent_step_ids = cast(List[str], receipt.get("divergent_step_ids") or [])
    dispute = receipt.get("dispute")

    if steps_matched + steps_diverged != steps_replayed:
        errors.append("(root): steps_matched + steps_diverged must equal steps_replayed")

    if len(divergent_step_ids) != steps_diverged:
        errors.append("divergent_step_ids: count must match steps_diverged")

    if verdict == _VERDICT_MATCH:
        if receipt_integrity != "PASS":
            errors.append("receipt_integrity: MATCH receipts must have PASS integrity")
        if claim_check != "PASS":
            errors.append("claim_check: MATCH receipts must have PASS claim_check")
        if steps_diverged != 0 or divergent_step_ids:
            errors.append("divergent_step_ids: MATCH receipts must not record divergences")
        if dispute is not None:
            errors.append("dispute: MATCH receipts must not include a dispute payload")

    if verdict == _VERDICT_DIVERGE:
        if receipt_integrity != "PASS":
            errors.append("receipt_integrity: DIVERGE receipts must have PASS integrity")
        if claim_check != "FAIL":
            errors.append("claim_check: DIVERGE receipts must have FAIL claim_check")
        if not isinstance(dispute, Mapping):
            errors.append("dispute: DIVERGE receipts must include a dispute payload")
        else:
            divergent_steps = cast(List[Dict[str, Any]], dispute.get("divergent_steps") or [])
            if not divergent_steps:
                errors.append("dispute.divergent_steps: DIVERGE receipts require at least one divergent step")

    if verdict == _VERDICT_INTEGRITY_FAIL:
        if receipt_integrity != "FAIL":
            errors.append("receipt_integrity: INTEGRITY_FAIL receipts must have FAIL integrity")
        if claim_check is not None:
            errors.append("claim_check: INTEGRITY_FAIL receipts must set claim_check to null")
        if dispute is not None:
            errors.append("dispute: INTEGRITY_FAIL receipts must not include a dispute payload")

    return errors


def _validate_contract(contract: Mapping[str, Any]) -> List[str]:
    errors = _schema_errors(_contract_validator_instance(), contract)
    try:
        environment = cast(Mapping[str, Any], contract["environment"])
    except KeyError:
        return errors

    declared_env_hash = _payload_string(environment, "env_fingerprint_hash")
    computed_env_hash = _compute_env_fingerprint_hash(environment)
    if declared_env_hash != computed_env_hash:
        errors.append(
            "environment.env_fingerprint_hash: declared value does not match computed identity-bearing environment hash"
        )

    return errors


def _graph_validation(contract: Mapping[str, Any]) -> Tuple[List[str], List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    replay_script = cast(Mapping[str, Any], contract["replay_script"])
    raw_steps = cast(List[Dict[str, Any]], replay_script["steps"])
    steps: List[Dict[str, Any]] = [dict(step) for step in raw_steps]
    errors: List[str] = []

    step_ids = [str(step.get("step_id") or "") for step in steps]
    duplicates = sorted({step_id for step_id in step_ids if step_ids.count(step_id) > 1 and step_id})
    if duplicates:
        errors.append(f"replay_script.steps: duplicate step_id values: {', '.join(duplicates)}")

    step_by_id: Dict[str, Dict[str, Any]] = {}
    for step in steps:
        step_id = str(step.get("step_id") or "")
        if step_id and step_id not in step_by_id:
            step_by_id[step_id] = step

    if not step_by_id:
        return errors, [], step_by_id

    inbound: Dict[str, int] = {step_id: 0 for step_id in step_by_id}
    children: Dict[str, List[str]] = defaultdict(list)

    for step in steps:
        step_id = str(step.get("step_id") or "")
        depends_on = cast(List[str], step.get("depends_on") or [])
        for dependency in depends_on:
            if dependency not in step_by_id:
                errors.append(f"replay_script.steps[{step_id}].depends_on: unknown dependency {dependency!r}")
                continue
            inbound[step_id] = inbound.get(step_id, 0) + 1
            children[dependency].append(step_id)

    terminals = [
        step_id
        for step_id in step_by_id
        if not children.get(step_id)
    ]
    if not any(str(step_by_id[step_id].get("opcode")) == "EMIT_OUTPUT" for step_id in terminals):
        errors.append("replay_script.steps: at least one terminal step must use opcode EMIT_OUTPUT")

    queue: deque[str] = deque(sorted(step_id for step_id, count in inbound.items() if count == 0))
    ordered_ids: List[str] = []
    local_inbound = dict(inbound)

    while queue:
        step_id = queue.popleft()
        ordered_ids.append(step_id)
        for child in sorted(children.get(step_id, [])):
            local_inbound[child] -= 1
            if local_inbound[child] == 0:
                queue.append(child)

    if len(ordered_ids) != len(step_by_id):
        errors.append("replay_script.steps: dependency graph contains a cycle")

    ordered_steps = [step_by_id[step_id] for step_id in ordered_ids if step_id in step_by_id]
    return errors, ordered_steps, step_by_id


def _input_artifact_path(pack_dir: Path, ref: str) -> Path:
    return _resolve_under(pack_dir, Path(INPUTS_DIRNAME) / _safe_relative_path(ref))


def _recorded_trace_path(pack_dir: Path, step_id: str) -> Path:
    return _resolve_under(pack_dir, Path(RECORDED_TRACES_DIRNAME) / _safe_relative_path(f"{step_id}.json"))


def _load_manifest(pack_dir: Path) -> Dict[str, Any]:
    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError("pack_manifest.json not found")
    return _json_dict(manifest_path)


def _load_receipts(pack_dir: Path) -> List[Dict[str, Any]]:
    receipt_pack = pack_dir / "receipt_pack.jsonl"
    if not receipt_pack.exists():
        raise FileNotFoundError("receipt_pack.jsonl not found")
    receipts: List[Dict[str, Any]] = []
    for line in receipt_pack.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        receipts.append(cast(Dict[str, Any], json.loads(line)))
    return receipts


def _contract_from_pack(pack_dir: Path) -> Dict[str, Any]:
    contract_path = pack_dir / EPISODE_CONTRACT_FILENAME
    if not contract_path.exists():
        raise FileNotFoundError(f"{EPISODE_CONTRACT_FILENAME} not found")
    return _json_dict(contract_path)


def _build_integrity_fail_receipt(
    *,
    contract: Mapping[str, Any],
    manifest: Optional[Mapping[str, Any]],
    parent_hashes: Sequence[str],
    verifier_id: str,
    verifier_version: str,
    issued_at: str,
) -> Dict[str, Any]:
    receipt: Dict[str, Any] = {
        "type": _REPLAY_RESULT_RECEIPT_TYPE,
        "timestamp": issued_at,
        "schema_version": "3.0",
        "proof_tier": "core",
        "parent_hashes": list(parent_hashes),
        "episode_id": contract.get("episode_id"),
        "episode_spec_hash": _compute_episode_spec_hash(contract),
        "original_pack_root_sha256": _as_prefixed_sha256(
            (manifest or {}).get("pack_root_sha256") or "0" * 64,
            field_name="original_pack_root_sha256",
        ),
        "verdict": _VERDICT_INTEGRITY_FAIL,
        "receipt_integrity": "FAIL",
        "claim_check": None,
        "replay_basis": cast(Mapping[str, Any], contract["replay_policy"]).get("replay_basis"),
        "comparator_tier": cast(Mapping[str, Any], contract["replay_policy"]).get("comparator_tier"),
        "script_hash": _compute_script_hash(contract),
        "steps_replayed": 0,
        "steps_matched": 0,
        "steps_diverged": 0,
        "divergent_step_ids": [],
        "verifier_id": verifier_id,
        "verifier_version": verifier_version,
        "verifier_env_hash": _verifier_env_hash(verifier_id, verifier_version),
        "dispute": None,
    }
    receipt_id_seed = _sha256_hex(jcs_canonicalize(receipt))[:12]
    receipt["receipt_id"] = f"r_rce_replay_{receipt_id_seed}"
    receipt["receipt_hash"] = _canonical_receipt_hash(receipt)
    return receipt


def _expected_step_tier(step_id: str, contract: Mapping[str, Any]) -> str:
    policy = cast(Mapping[str, Any], contract["replay_policy"])
    overrides = cast(Mapping[str, Any], policy.get("comparator_tiers_by_step") or {})
    return str(overrides.get(step_id) or policy.get("comparator_tier") or "")


def _phase_three(
    *,
    pack_dir: Path,
    contract: Mapping[str, Any],
    ordered_steps: Sequence[Mapping[str, Any]],
    receipts: Sequence[Mapping[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Dict[str, Any]], Dict[str, Any]]:
    errors: List[str] = []
    open_receipts = [dict(receipt) for receipt in receipts if _receipt_type(receipt) == _OPEN_RECEIPT_TYPE]
    close_receipts = [dict(receipt) for receipt in receipts if _receipt_type(receipt) == _CLOSE_RECEIPT_TYPE]
    step_receipts = [dict(receipt) for receipt in receipts if _receipt_type(receipt) == _STEP_RECEIPT_TYPE]

    if len(open_receipts) != 1:
        errors.append("receipt_pack: expected exactly one rce.episode_open/v0 receipt")
    if len(close_receipts) != 1:
        errors.append("receipt_pack: expected exactly one rce.episode_close/v0 receipt")

    step_receipts_by_id: Dict[str, Dict[str, Any]] = {}
    for receipt in step_receipts:
        payload = _receipt_payload(receipt)
        step_id = _payload_string(payload, "step_id")
        if not step_id:
            errors.append("receipt_pack: every rce.episode_step/v0 receipt must declare step_id")
            continue
        if step_id in step_receipts_by_id:
            errors.append(f"receipt_pack: duplicate rce.episode_step/v0 receipt for step_id {step_id}")
            continue
        step_receipts_by_id[step_id] = receipt

    if len(step_receipts_by_id) != len(ordered_steps):
        errors.append("receipt_pack: expected exactly one step receipt for each ReplayScript step")

    open_receipt = open_receipts[0] if open_receipts else {}
    close_receipt = close_receipts[0] if close_receipts else {}
    open_payload = _receipt_payload(open_receipt)
    close_payload = _receipt_payload(close_receipt)
    episode_id = _payload_string(contract, "episode_id")

    for input_ref in cast(List[Dict[str, Any]], contract.get("inputs") or []):
        ref = str(input_ref.get("ref") or "")
        if not ref:
            continue
        try:
            path = _input_artifact_path(pack_dir, ref)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not path.exists():
            errors.append(f"inputs/{ref}: input artifact not found")
            continue
        actual_hash = _sha256_prefixed(path.read_bytes())
        declared_hash = _payload_string(input_ref, "hash")
        if declared_hash != actual_hash:
            errors.append(f"inputs/{ref}: declared hash does not match artifact bytes")

    computed_episode_spec_hash = _compute_episode_spec_hash(contract)
    computed_env_hash = _compute_env_fingerprint_hash(cast(Mapping[str, Any], contract["environment"]))
    computed_inputs_hash = _compute_inputs_hash(contract)
    computed_script_hash = _compute_script_hash(contract)

    if open_payload:
        if _payload_string(open_payload, "episode_id") != episode_id:
            errors.append("rce.episode_open/v0: episode_id does not match episode contract")
        if _payload_string(open_payload, "episode_spec_hash") != computed_episode_spec_hash:
            errors.append("rce.episode_open/v0: episode_spec_hash does not match episode contract")
        if _payload_string(open_payload, "env_fingerprint_hash") != computed_env_hash:
            errors.append("rce.episode_open/v0: env_fingerprint_hash does not match episode contract")
        if _payload_string(open_payload, "inputs_hash") != computed_inputs_hash:
            errors.append("rce.episode_open/v0: inputs_hash does not match episode contract")
        if _payload_string(open_payload, "script_hash") != computed_script_hash:
            errors.append("rce.episode_open/v0: script_hash does not match episode contract")
        if _payload_string(open_payload, "replay_basis") != "recorded_trace":
            errors.append("rce.episode_open/v0: replay_basis must be recorded_trace")
        if _payload_string(open_payload, "comparator_tier") != "A":
            errors.append("rce.episode_open/v0: comparator_tier must be A")
        if int(open_payload.get("n_steps", 0) or 0) != len(ordered_steps):
            errors.append("rce.episode_open/v0: n_steps does not match ReplayScript length")

    step_payloads: Dict[str, Dict[str, Any]] = {}
    parsed_traces: Dict[str, Any] = {}
    n_steps_executed = 0
    n_steps_passed = 0

    for step in ordered_steps:
        step_id = str(step.get("step_id") or "")
        receipt = step_receipts_by_id.get(step_id)
        if receipt is None:
            continue
        payload = dict(_receipt_payload(receipt))
        step_payloads[step_id] = payload

        if _payload_string(payload, "episode_id") != episode_id:
            errors.append(f"rce.episode_step/v0[{step_id}]: episode_id does not match episode contract")
        if _payload_string(payload, "opcode") != str(step.get("opcode") or ""):
            errors.append(f"rce.episode_step/v0[{step_id}]: opcode does not match ReplayScript")

        expected_tier = _expected_step_tier(step_id, contract)
        if _payload_string(payload, "comparator_tier") != expected_tier:
            errors.append(f"rce.episode_step/v0[{step_id}]: comparator_tier does not match replay policy")

        status = _payload_string(payload, "step_status")
        if status not in _VALID_STATUSES:
            errors.append(f"rce.episode_step/v0[{step_id}]: invalid step_status {status!r}")
            continue

        if status == _STEP_STATUS_PASS:
            n_steps_passed += 1
        if status != _STEP_STATUS_SKIPPED:
            n_steps_executed += 1

        if status == _STEP_STATUS_SKIPPED:
            if payload.get("output_hash") is not None:
                errors.append(f"rce.episode_step/v0[{step_id}]: SKIPPED steps must set output_hash to null")
            if list(payload.get("input_hashes") or []) != []:
                errors.append(f"rce.episode_step/v0[{step_id}]: SKIPPED steps must set input_hashes to []")
            if int(payload.get("output_size_bytes", 0) or 0) != 0:
                errors.append(f"rce.episode_step/v0[{step_id}]: SKIPPED steps must set output_size_bytes to 0")
            if int(payload.get("duration_ms", 0) or 0) != 0:
                errors.append(f"rce.episode_step/v0[{step_id}]: SKIPPED steps must set duration_ms to 0")
            continue

        output_hash = _payload_string(payload, "output_hash")
        try:
            _as_prefixed_sha256(output_hash, field_name=f"rce.episode_step/v0[{step_id}].output_hash")
        except ValueError as exc:
            errors.append(str(exc))

        for index, input_hash in enumerate(cast(List[Any], payload.get("input_hashes") or [])):
            try:
                _as_prefixed_sha256(
                    input_hash,
                    field_name=f"rce.episode_step/v0[{step_id}].input_hashes[{index}]",
                )
            except ValueError as exc:
                errors.append(str(exc))

        try:
            trace_path = _recorded_trace_path(pack_dir, step_id)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not trace_path.exists():
            errors.append(f"recorded_traces/{step_id}.json: recorded trace not found")
            continue
        try:
            parsed_traces[step_id] = json.loads(trace_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"recorded_traces/{step_id}.json: invalid JSON ({exc.msg})")

    computed_outputs_hash = _compute_outputs_hash(step_payloads)
    if close_payload:
        if _payload_string(close_payload, "episode_id") != episode_id:
            errors.append("rce.episode_close/v0: episode_id does not match episode contract")
        if _payload_string(close_payload, "episode_spec_hash") != computed_episode_spec_hash:
            errors.append("rce.episode_close/v0: episode_spec_hash does not match episode contract")
        if _payload_string(close_payload, "outputs_hash") != computed_outputs_hash:
            errors.append("rce.episode_close/v0: outputs_hash does not match step receipts")
        if int(close_payload.get("n_steps_executed", 0) or 0) != n_steps_executed:
            errors.append("rce.episode_close/v0: n_steps_executed does not match step receipts")
        if int(close_payload.get("n_steps_passed", 0) or 0) != n_steps_passed:
            errors.append("rce.episode_close/v0: n_steps_passed does not match step receipts")
        if bool(close_payload.get("all_steps_passed")) != (n_steps_passed == len(ordered_steps)):
            errors.append("rce.episode_close/v0: all_steps_passed does not match step receipts")
        if _payload_string(close_payload, "replay_basis") != "recorded_trace":
            errors.append("rce.episode_close/v0: replay_basis must be recorded_trace")
        if _payload_string(close_payload, "comparator_tier") != "A":
            errors.append("rce.episode_close/v0: comparator_tier must be A")

    if errors:
        parent_hashes: Tuple[str, ...] = ()
        if close_receipt:
            parent_hashes = (_canonical_receipt_hash(close_receipt),)
        raise _PhaseFailure(phase=3, errors=tuple(errors), parent_hashes=parent_hashes)

    return open_receipt, close_receipt, step_payloads, parsed_traces


def verify_rce_pack(
    pack_dir: Path,
    *,
    keystore: Optional[AssayKeyStore] = None,
    verifier_id: str = "assay-rce-verify-py",
    verifier_version: str = _assay_version,
    issued_at: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any], int]:
    """Verify a Replay-Constrained Episode proof pack.

    The verifier expects the following pack-local artifact layout:

    - ``episode_contract.json``
    - ``inputs/<ref>`` for each contract input ref
    - ``recorded_traces/<step_id>.json`` for each non-SKIPPED step
    """

    pack_path = Path(pack_dir)
    issued = issued_at or _utc_now_iso()
    details: Dict[str, Any] = {
        "phase": 0,
        "errors": [],
        "divergent_steps": [],
        "artifact_layout": {
            "episode_contract": EPISODE_CONTRACT_FILENAME,
            "inputs_dir": INPUTS_DIRNAME,
            "recorded_traces_dir": RECORDED_TRACES_DIRNAME,
        },
    }

    try:
        contract = _contract_from_pack(pack_path)
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        fallback_contract = {
            "schema_version": "rce/0.1",
            "episode_id": "ep_000000000000000000000000",
            "inputs": [],
            "replay_script": {"schema_version": "replay_script/0.1", "steps": []},
            "replay_policy": {"replay_basis": "recorded_trace", "comparator_tier": "A"},
            "environment": {
                "env_fingerprint_hash": "sha256:" + ("0" * 64),
                "provider": "unknown",
                "model_id": "unknown",
                "tool_versions": {},
                "container_digest": None,
            },
        }
        details["phase"] = 1
        details["errors"] = [str(exc)]
        receipt = _build_integrity_fail_receipt(
            contract=fallback_contract,
            manifest=None,
            parent_hashes=(),
            verifier_id=verifier_id,
            verifier_version=verifier_version,
            issued_at=issued,
        )
        return receipt, details, 2

    contract_errors = _validate_contract(contract)
    graph_errors, ordered_steps, _ = _graph_validation(contract)
    if contract_errors or graph_errors:
        details["phase"] = 1
        details["errors"] = [*contract_errors, *graph_errors]
        receipt = _build_integrity_fail_receipt(
            contract=contract,
            manifest=None,
            parent_hashes=(),
            verifier_id=verifier_id,
            verifier_version=verifier_version,
            issued_at=issued,
        )
        return receipt, details, 2

    manifest: Optional[Dict[str, Any]] = None
    try:
        manifest = _load_manifest(pack_path)
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        details["phase"] = 2
        details["errors"] = [str(exc)]
        receipt = _build_integrity_fail_receipt(
            contract=contract,
            manifest=None,
            parent_hashes=(),
            verifier_id=verifier_id,
            verifier_version=verifier_version,
            issued_at=issued,
        )
        return receipt, details, 2

    ks = keystore or get_default_keystore()
    phase_two = verify_proof_pack(manifest, pack_path, ks)
    if not phase_two.passed:
        details["phase"] = 2
        details["errors"] = [f"{error.code}: {error.message}" for error in phase_two.errors]
        receipt = _build_integrity_fail_receipt(
            contract=contract,
            manifest=manifest,
            parent_hashes=(),
            verifier_id=verifier_id,
            verifier_version=verifier_version,
            issued_at=issued,
        )
        return receipt, details, 2

    try:
        receipts = _load_receipts(pack_path)
        _, close_receipt, step_payloads, parsed_traces = _phase_three(
            pack_dir=pack_path,
            contract=contract,
            ordered_steps=ordered_steps,
            receipts=receipts,
        )
    except _PhaseFailure as exc:
        details["phase"] = exc.phase
        details["errors"] = list(exc.errors)
        receipt = _build_integrity_fail_receipt(
            contract=contract,
            manifest=manifest,
            parent_hashes=exc.parent_hashes,
            verifier_id=verifier_id,
            verifier_version=verifier_version,
            issued_at=issued,
        )
        return receipt, details, 2

    close_parent_hash = [_canonical_receipt_hash(close_receipt)]
    divergent_steps: List[Dict[str, Any]] = []
    steps_replayed = 0

    for step in ordered_steps:
        step_id = str(step.get("step_id") or "")
        payload = step_payloads[step_id]
        status = _payload_string(payload, "step_status")
        if status == _STEP_STATUS_SKIPPED:
            continue

        steps_replayed += 1
        expected_input_hashes = [
            cast(str, step_payloads[dependency].get("output_hash"))
            for dependency in cast(List[str], step.get("depends_on") or [])
        ]
        observed_output_hash = _canonical_sha256(parsed_traces[step_id])
        reasons: List[str] = []
        if cast(List[str], payload.get("input_hashes") or []) != expected_input_hashes:
            reasons.append("input hash chain mismatch")
        if observed_output_hash != _payload_string(payload, "output_hash"):
            reasons.append("JCS output hash mismatch")
        if reasons:
            divergent_steps.append(
                {
                    "step_id": step_id,
                    "expected_output_hash": _payload_string(payload, "output_hash"),
                    "observed_output_hash": observed_output_hash,
                    "comparator_tier": _expected_step_tier(step_id, contract),
                    "comparator_detail": "; ".join(reasons),
                }
            )

    verdict = _VERDICT_MATCH if not divergent_steps else _VERDICT_DIVERGE
    claim_check: Optional[str] = "PASS" if verdict == _VERDICT_MATCH else "FAIL"
    dispute: Optional[Dict[str, Any]] = None
    if verdict == _VERDICT_DIVERGE:
        dispute = {
            "divergent_steps": divergent_steps,
            "replay_pack_root_sha256": None,
        }

    receipt = {
        "type": _REPLAY_RESULT_RECEIPT_TYPE,
        "timestamp": issued,
        "schema_version": "3.0",
        "proof_tier": "core",
        "parent_hashes": close_parent_hash,
        "episode_id": contract.get("episode_id"),
        "episode_spec_hash": _compute_episode_spec_hash(contract),
        "original_pack_root_sha256": _as_prefixed_sha256(
            manifest.get("pack_root_sha256") or "0" * 64,
            field_name="original_pack_root_sha256",
        ),
        "verdict": verdict,
        "receipt_integrity": "PASS",
        "claim_check": claim_check,
        "replay_basis": cast(Mapping[str, Any], contract["replay_policy"]).get("replay_basis"),
        "comparator_tier": cast(Mapping[str, Any], contract["replay_policy"]).get("comparator_tier"),
        "script_hash": _compute_script_hash(contract),
        "steps_replayed": steps_replayed,
        "steps_matched": steps_replayed - len(divergent_steps),
        "steps_diverged": len(divergent_steps),
        "divergent_step_ids": [step["step_id"] for step in divergent_steps],
        "verifier_id": verifier_id,
        "verifier_version": verifier_version,
        "verifier_env_hash": _verifier_env_hash(verifier_id, verifier_version),
        "dispute": dispute,
    }
    receipt_id_seed = _sha256_hex(jcs_canonicalize(receipt))[:12]
    receipt["receipt_id"] = f"r_rce_replay_{receipt_id_seed}"
    receipt["receipt_hash"] = _canonical_receipt_hash(receipt)

    validation_errors = validate_rce_replay_result(receipt)
    if validation_errors:
        details["phase"] = 4
        details["errors"] = validation_errors
        fallback = _build_integrity_fail_receipt(
            contract=contract,
            manifest=manifest,
            parent_hashes=close_parent_hash,
            verifier_id=verifier_id,
            verifier_version=verifier_version,
            issued_at=issued,
        )
        return fallback, details, 2

    details["phase"] = 4
    details["errors"] = []
    details["divergent_steps"] = divergent_steps
    return receipt, details, 0 if verdict == _VERDICT_MATCH else 1


def write_rce_replay_result(
    *,
    pack_dir: Path,
    out_dir: Path,
    keystore: Optional[AssayKeyStore] = None,
    verifier_id: str = "assay-rce-verify-py",
    verifier_version: str = _assay_version,
    issued_at: Optional[str] = None,
    overwrite: bool = False,
    pretty: bool = False,
) -> RCEVerifyResult:
    """Verify an RCE pack and write receipt plus details artifacts."""

    output_dir = Path(out_dir)
    if output_dir.exists() and not overwrite:
        raise FileExistsError(
            f"Output directory already exists: {output_dir}. Remove it first or use --overwrite."
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    receipt, details, exit_code = verify_rce_pack(
        pack_dir,
        keystore=keystore,
        verifier_id=verifier_id,
        verifier_version=verifier_version,
        issued_at=issued_at,
    )

    indent = 2 if pretty else None
    receipt_path = output_dir / RCE_REPLAY_RESULT_FILENAME
    details_path = output_dir / RCE_REPLAY_DETAILS_FILENAME
    receipt_path.write_text(json.dumps(receipt, indent=indent), encoding="utf-8")
    details_path.write_text(json.dumps(details, indent=indent), encoding="utf-8")

    return RCEVerifyResult(
        verdict=str(receipt["verdict"]),
        exit_code=exit_code,
        receipt=receipt,
        details=details,
        receipt_path=receipt_path,
        details_path=details_path,
    )


__all__ = [
    "EPISODE_CONTRACT_FILENAME",
    "INPUTS_DIRNAME",
    "RECORDED_TRACES_DIRNAME",
    "RCEVerifyResult",
    "RCE_REPLAY_DETAILS_FILENAME",
    "RCE_REPLAY_RESULT_FILENAME",
    "validate_rce_replay_result",
    "verify_rce_pack",
    "write_rce_replay_result",
]