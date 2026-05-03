from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.derived.backends import DerivedBackend, NativeAssayBackend
from assay.derived.hashing import canonical_hash, stable_id
from assay.derived.models import (
    DERIVED_SCHEMA_VERSION,
    RECEIPT_SCHEMA_VERSION,
    DerivedArtifact,
    IndexUpdatePlan,
)
from assay.derived.planner import apply_derived_context, plan_derived_context
from assay.derived.receipts import make_derivation_receipt
from assay.derived.store import DerivedStore, decode_json, encode_json
from assay.derived.transforms import line_chunk_transform_spec
from assay.derived.verifier import verify_receipt


def test_noop_rerun_creates_no_new_snapshots_or_artifacts(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)

    first = apply_derived_context(root, store)
    assert first.added_count == 1
    snapshot_count = store.count_rows("source_snapshots")
    artifact_count = store.count_rows("derived_artifacts")

    second = apply_derived_context(root, store)

    assert second.added_count == 0
    assert second.updated_count == 0
    assert second.deleted_count == 0
    assert store.count_rows("source_snapshots") == snapshot_count
    assert store.count_rows("derived_artifacts") == artifact_count


def test_file_edit_invalidates_only_that_files_chunks(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    _write(root / "b.py", "print('b')\n")
    store = _store(tmp_path)

    apply_derived_context(root, store)
    before = _artifacts_by_path(store)
    old_a = before["a.py"][0]["artifact_id"]
    old_b = before["b.py"][0]["artifact_id"]

    _write(root / "a.py", "print('a changed')\n")
    plan = apply_derived_context(root, store)
    statuses = _artifact_statuses(store)
    after = _artifacts_by_path(store, status="active")

    assert plan.added_count == 1
    assert plan.updated_count == 1
    assert plan.deleted_count == 0
    assert statuses[old_a] == "stale"
    assert statuses[old_b] == "active"
    assert after["a.py"][0]["artifact_id"] != old_a
    assert after["b.py"][0]["artifact_id"] == old_b


def test_transform_version_change_invalidates_dependent_chunks(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)

    apply_derived_context(root, store)
    old_artifact = _active_artifacts(store)[0]
    new_transform = line_chunk_transform_spec(version="0.2.0")

    plan = apply_derived_context(root, store, transform=new_transform)
    statuses = _artifact_statuses(store)
    active = _active_artifacts(store)

    assert plan.added_count == 1
    assert plan.updated_count == 1
    assert statuses[old_artifact["artifact_id"]] == "stale"
    assert active[0]["transform_id"] == new_transform.transform_id


def test_deleted_file_creates_tombstones(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    _write(root / "b.py", "print('b')\n")
    store = _store(tmp_path)

    apply_derived_context(root, store)
    before = _artifacts_by_path(store)
    old_a = before["a.py"][0]["artifact_id"]
    old_b = before["b.py"][0]["artifact_id"]

    (root / "a.py").unlink()
    plan = apply_derived_context(root, store)
    statuses = _artifact_statuses(store)

    assert plan.deleted_count == 1
    assert plan.updated_count == 0
    assert statuses[old_a] == "tombstoned"
    assert statuses[old_b] == "active"
    assert store.count_rows("artifact_tombstones") == 1


def test_explain_returns_complete_lineage(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)

    apply_derived_context(root, store)
    artifact = _active_artifacts(store)[0]
    explanation = store.explain_artifact(artifact["artifact_id"])

    assert explanation is not None
    assert explanation["artifact"]["artifact_id"] == artifact["artifact_id"]
    assert explanation["source"]["uri"] == "file://a.py"
    assert explanation["source_snapshot"]["content_hash"].startswith("sha256:")
    assert explanation["transform"]["name"] == "line_chunker"
    assert explanation["receipt"]["subject_id"] == artifact["artifact_id"]
    assert explanation["artifact"]["derivation_verification_level"] == "DV1"


def test_verify_recomputes_deterministic_artifact(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)

    apply_derived_context(root, store)
    artifact = _active_artifacts(store)[0]
    result = verify_receipt(store, artifact["receipt_id"])

    assert result.ok
    assert result.derivation_verification_level == "DV2"
    assert result.expected_output_hash == result.actual_output_hash


def test_verify_rejects_mutated_receipt_json(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)
    apply_derived_context(root, store)
    artifact = _active_artifacts(store)[0]

    _mutate_receipt_json(
        store,
        artifact["receipt_id"],
        lambda data: data["metadata"].update({"relative_path": "evil.py"}),
    )
    result = verify_receipt(store, artifact["receipt_id"])

    assert not result.ok
    assert any("canonical receipt payload" in error for error in result.errors)


def test_verify_rejects_receipt_subject_mismatch(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)
    apply_derived_context(root, store)
    artifact = _active_artifacts(store)[0]

    _mutate_receipt_json(
        store,
        artifact["receipt_id"],
        lambda data: data.update({"subject_id": "art_fake"}),
    )
    result = verify_receipt(store, artifact["receipt_id"])

    assert not result.ok
    assert any("subject_id does not match receipts row" in e for e in result.errors)


def test_verify_rejects_artifact_output_hash_mismatch(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)
    apply_derived_context(root, store)
    artifact = _active_artifacts(store)[0]

    with store.connect() as conn:
        conn.execute(
            """
            UPDATE derived_artifacts
            SET output_hash = ?
            WHERE artifact_id = ?
            """,
            ("sha256:" + "0" * 64, artifact["artifact_id"]),
        )
    result = verify_receipt(store, artifact["receipt_id"])

    assert not result.ok
    assert any("output_hash does not match receipt" in e for e in result.errors)


def test_store_initializes_schema_version_metadata(tmp_path: Path) -> None:
    store = _store(tmp_path)

    store.initialize()

    assert store.get_metadata("derived_schema_version") == DERIVED_SCHEMA_VERSION
    assert store.get_metadata("receipt_schema_version") == RECEIPT_SCHEMA_VERSION
    assert store.count_rows("store_metadata") == 2


def test_store_rejects_unversioned_committed_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with store.connect() as conn:
        conn.execute(
            """
            CREATE TABLE sources (
              source_id TEXT PRIMARY KEY,
              source_type TEXT NOT NULL,
              uri TEXT NOT NULL,
              first_seen_at TEXT NOT NULL,
              last_seen_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO sources (
              source_id,
              source_type,
              uri,
              first_seen_at,
              last_seen_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "src_legacy",
                "local_file",
                "file://legacy.py",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ),
        )

    with pytest.raises(RuntimeError, match="unversioned derived store"):
        store.initialize()


def test_downstream_artifact_invalidates_when_input_artifact_tombstoned(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)
    apply_derived_context(root, store)
    source_artifact_row = _active_artifacts(store)[0]
    source_artifact = store.get_artifact(source_artifact_row["artifact_id"])
    assert source_artifact is not None

    dependent_artifact = _add_dependent_fixture_artifact(store, source_artifact)
    assert store.artifact_is_admissible(dependent_artifact.artifact_id)
    dependent_receipt = store.get_artifact(dependent_artifact.artifact_id).receipt_id
    dependent_result = verify_receipt(store, dependent_receipt)
    assert dependent_result.ok
    assert dependent_result.derivation_verification_level == "DV1"

    _tombstone_artifact(store, source_artifact)

    assert store.get_artifact(dependent_artifact.artifact_id).status == "active"
    assert not store.artifact_is_admissible(dependent_artifact.artifact_id)
    invalidated_result = verify_receipt(store, dependent_receipt)
    assert not invalidated_result.ok
    assert any(
        "input artifact is not admissible" in e for e in invalidated_result.errors
    )


def test_native_backend_satisfies_index_backend_protocol(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)
    backend = NativeAssayBackend(store)

    assert isinstance(backend, DerivedBackend)
    assert len(backend.scan(root)) == 1
    plan = backend.apply(root)
    artifact_id = next(
        op["artifact"]["artifact_id"]
        for op in plan.operations
        if op["type"] == "add_artifact"
    )
    receipt_id = store.get_artifact(artifact_id).receipt_id

    assert backend.explain(artifact_id)["artifact"]["artifact_id"] == artifact_id
    assert backend.verify(receipt_id).ok


def test_failed_apply_rolls_back_without_partial_state(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root / "a.py", "print('a')\n")
    store = _store(tmp_path)
    plan = plan_derived_context(root, store)

    with pytest.raises(RuntimeError):
        store.apply_plan(plan, fail_after_operations=3)

    assert store.count_rows("sources") == 0
    assert store.count_rows("source_snapshots") == 0
    assert store.count_rows("derived_artifacts") == 0
    assert store.count_rows("receipts") == 0
    assert store.count_rows("index_update_plans") == 0


def test_top_level_derived_cli_apply_explain_verify(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    db = tmp_path / "derived.sqlite"
    _write(root / "a.py", "print('a')\n")
    runner = CliRunner()

    apply_result = runner.invoke(
        assay_app, ["derived", "apply", str(root), "--db", str(db)]
    )
    assert apply_result.exit_code == 0, apply_result.output
    apply_payload = json.loads(apply_result.output)
    artifact_id = next(
        op["artifact_id"]
        for op in apply_payload["plan"]["operations"]
        if op["type"] == "add_artifact"
    )
    receipt_id = next(
        op["receipt_id"]
        for op in apply_payload["plan"]["operations"]
        if op["type"] == "add_artifact"
    )

    explain_result = runner.invoke(
        assay_app, ["derived", "explain", artifact_id, "--db", str(db)]
    )
    assert explain_result.exit_code == 0, explain_result.output
    assert json.loads(explain_result.output)["explain"]["artifact"]["artifact_id"]

    verify_result = runner.invoke(
        assay_app, ["derived", "verify", receipt_id, "--db", str(db)]
    )
    assert verify_result.exit_code == 0, verify_result.output
    assert json.loads(verify_result.output)["verification"]["ok"] is True


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def _store(tmp_path: Path) -> DerivedStore:
    return DerivedStore(tmp_path / "derived.sqlite")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _mutate_receipt_json(store: DerivedStore, receipt_id: str, mutate) -> None:
    record = store.get_receipt_record(receipt_id)
    assert record is not None
    data = json.loads(record["receipt_json"])
    mutate(data)
    with store.connect() as conn:
        conn.execute(
            "UPDATE receipts SET receipt_json = ? WHERE receipt_id = ?",
            (encode_json(data), receipt_id),
        )


def _add_dependent_fixture_artifact(
    store: DerivedStore, input_artifact
) -> DerivedArtifact:
    transform = store.get_transform(input_artifact.transform_id)
    assert transform is not None
    created_at = "2026-01-01T00:00:00+00:00"
    output_hash = canonical_hash(
        {
            "artifact_type": "fixture_projection",
            "input_artifact_id": input_artifact.artifact_id,
        }
    )
    artifact_id = stable_id(
        "art",
        {
            "artifact_type": "fixture_projection",
            "input_artifact_id": input_artifact.artifact_id,
            "transform_id": input_artifact.transform_id,
            "output_hash": output_hash,
        },
    )
    receipt = make_derivation_receipt(
        kind="derived.artifact.created",
        subject_id=artifact_id,
        source_snapshot_ids=[],
        input_artifact_ids=[input_artifact.artifact_id],
        transform_id=input_artifact.transform_id,
        output_hash=output_hash,
        derivation_verification_level="DV1",
        status="committed",
        created_at=created_at,
        metadata={
            "artifact_type": "fixture_projection",
            "transform": transform.to_dict(),
        },
    )
    artifact = DerivedArtifact(
        artifact_id=artifact_id,
        artifact_type="fixture_projection",
        source_snapshot_id=None,
        input_artifact_ids=(input_artifact.artifact_id,),
        transform_id=input_artifact.transform_id,
        output_hash=output_hash,
        receipt_id=receipt.receipt_id,
        derivation_verification_level="DV1",
        status="active",
        created_at=created_at,
        metadata={"fixture": True},
    )
    plan = IndexUpdatePlan(
        plan_id=stable_id(
            "dplan", {"operation": "add_fixture", "artifact_id": artifact_id}
        ),
        previous_state_hash=None,
        proposed_state_hash=output_hash,
        added_count=1,
        updated_count=0,
        deleted_count=0,
        created_at=created_at,
        root="fixture",
        transform_id=input_artifact.transform_id,
        operations=[
            {
                "type": "add_artifact",
                "artifact": artifact.to_dict(),
                "inputs": [
                    {
                        "artifact_id": artifact_id,
                        "input_artifact_id": input_artifact.artifact_id,
                        "input_role": "fixture_input",
                    }
                ],
                "receipt": receipt.to_dict(),
            }
        ],
    )
    store.apply_plan(plan)
    return artifact


def _tombstone_artifact(store: DerivedStore, artifact) -> None:
    created_at = "2026-01-01T00:00:01+00:00"
    receipt = make_derivation_receipt(
        kind="derived.artifact.tombstoned",
        subject_id=artifact.artifact_id,
        source_snapshot_ids=(
            [artifact.source_snapshot_id] if artifact.source_snapshot_id else []
        ),
        input_artifact_ids=artifact.input_artifact_ids,
        transform_id=artifact.transform_id,
        output_hash=artifact.output_hash,
        derivation_verification_level="DV1",
        status="committed",
        created_at=created_at,
        metadata={"reason": "fixture_tombstone"},
    )
    plan = IndexUpdatePlan(
        plan_id=stable_id(
            "dplan",
            {"operation": "tombstone_fixture", "artifact_id": artifact.artifact_id},
        ),
        previous_state_hash=None,
        proposed_state_hash=artifact.output_hash,
        added_count=0,
        updated_count=0,
        deleted_count=1,
        created_at=created_at,
        root="fixture",
        transform_id=artifact.transform_id,
        operations=[
            {
                "type": "tombstone_artifact",
                "artifact_id": artifact.artifact_id,
                "tombstone": {
                    "artifact_id": artifact.artifact_id,
                    "reason": "fixture_tombstone",
                    "tombstoned_at": created_at,
                    "receipt_id": receipt.receipt_id,
                },
                "receipt": receipt.to_dict(),
            }
        ],
    )
    store.apply_plan(plan)


def _active_artifacts(store: DerivedStore):
    return _artifact_rows(store, status="active")


def _artifacts_by_path(store: DerivedStore, status: str = "active"):
    rows = _artifact_rows(store, status=status)
    by_path = {}
    for row in rows:
        by_path.setdefault(row["relative_path"], []).append(row)
    return by_path


def _artifact_statuses(store: DerivedStore):
    return {
        row["artifact_id"]: row["status"] for row in _artifact_rows(store, status=None)
    }


def _artifact_rows(store: DerivedStore, status=None):
    store.initialize()
    query = """
        SELECT
          da.artifact_id,
          da.status,
          da.receipt_id,
          da.transform_id,
          da.metadata_json,
          ss.source_id,
          ss.snapshot_id
        FROM derived_artifacts da
        JOIN source_snapshots ss
          ON da.source_snapshot_id = ss.snapshot_id
    """
    params = ()
    if status is not None:
        query += " WHERE da.status = ?"
        params = (status,)
    query += " ORDER BY da.artifact_id"
    with store.connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
    parsed = []
    for row in rows:
        metadata = decode_json(row["metadata_json"])
        parsed.append(
            {
                "artifact_id": row["artifact_id"],
                "status": row["status"],
                "receipt_id": row["receipt_id"],
                "transform_id": row["transform_id"],
                "relative_path": metadata["relative_path"],
                "source_id": row["source_id"],
                "snapshot_id": row["snapshot_id"],
            }
        )
    return parsed
