"""SQLite store for Assay receipted derived context."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from assay.derived.models import (
    ArtifactTombstone,
    DERIVED_SCHEMA_VERSION,
    DerivationReceipt,
    DerivedArtifact,
    IndexUpdatePlan,
    RECEIPT_SCHEMA_VERSION,
    Source,
    SourceSnapshot,
    TransformSpec,
)
from assay.derived.receipts import now_iso


def encode_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def decode_json(value: str) -> Any:
    return json.loads(value)


class DerivedStore:
    """Small SQLite adapter for committed derived-context state."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def initialize(self) -> None:
        schema = resources.files("assay.derived").joinpath("schema.sql").read_text()
        with self.connect() as conn:
            conn.executescript(schema)
            self._ensure_schema_metadata(conn)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.initialize()
        conn = self.connect()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def put_plan(self, plan: IndexUpdatePlan) -> None:
        self.initialize()
        with self.connect() as conn:
            self._insert_plan(conn, plan)

    def apply_plan(
        self,
        plan: IndexUpdatePlan,
        *,
        fail_after_operations: Optional[int] = None,
    ) -> None:
        with self.transaction() as conn:
            self._insert_plan(conn, plan)
            applied = 0
            for operation in plan.operations:
                self._apply_operation(conn, operation)
                applied += 1
                if (
                    fail_after_operations is not None
                    and applied >= fail_after_operations
                ):
                    raise RuntimeError("injected derived-context apply failure")

    def get_source(self, source_id: str) -> Optional[Source]:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM sources WHERE source_id = ?", (source_id,)
            ).fetchone()
        return _row_to_source(row) if row else None

    def get_snapshot(self, snapshot_id: str) -> Optional[SourceSnapshot]:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM source_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
        return _row_to_snapshot(row) if row else None

    def has_snapshot(self, snapshot_id: str) -> bool:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM source_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
        return row is not None

    def has_transform(self, transform_id: str) -> bool:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM transforms WHERE transform_id = ?",
                (transform_id,),
            ).fetchone()
        return row is not None

    def get_transform(self, transform_id: str) -> Optional[TransformSpec]:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM transforms WHERE transform_id = ?", (transform_id,)
            ).fetchone()
        return _row_to_transform(row) if row else None

    def get_artifact(self, artifact_id: str) -> Optional[DerivedArtifact]:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM derived_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                return None
            input_rows = conn.execute(
                """
                SELECT input_artifact_id
                FROM artifact_inputs
                WHERE artifact_id = ?
                ORDER BY input_role, input_artifact_id
                """,
                (artifact_id,),
            ).fetchall()
        return _row_to_artifact(
            row, [input_row["input_artifact_id"] for input_row in input_rows]
        )

    def get_receipt(self, receipt_id: str) -> Optional[DerivationReceipt]:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
            ).fetchone()
        return _row_to_receipt(row) if row else None

    def get_receipt_record(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "receipt_id": row["receipt_id"],
            "kind": row["kind"],
            "subject_id": row["subject_id"],
            "derivation_verification_level": row["derivation_verification_level"],
            "status": row["status"],
            "created_at": row["created_at"],
            "receipt_json": row["receipt_json"],
        }

    def get_tombstone(self, artifact_id: str) -> Optional[ArtifactTombstone]:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM artifact_tombstones WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
        return _row_to_tombstone(row) if row else None

    def list_active_artifacts_with_sources(self) -> List[Dict[str, Any]]:
        self.initialize()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                  da.*,
                  ss.source_id AS source_id
                FROM derived_artifacts da
                LEFT JOIN source_snapshots ss
                  ON da.source_snapshot_id = ss.snapshot_id
                WHERE da.status = 'active'
                ORDER BY da.artifact_id
                """
            ).fetchall()
            input_rows = conn.execute(
                """
                SELECT artifact_id, input_artifact_id
                FROM artifact_inputs
                ORDER BY artifact_id, input_role, input_artifact_id
                """
            ).fetchall()
        inputs_by_artifact: Dict[str, List[str]] = {}
        for row in input_rows:
            inputs_by_artifact.setdefault(row["artifact_id"], []).append(
                row["input_artifact_id"]
            )
        records: List[Dict[str, Any]] = []
        for row in rows:
            artifact = _row_to_artifact(
                row, inputs_by_artifact.get(row["artifact_id"], [])
            )
            records.append({"artifact": artifact, "source_id": row["source_id"]})
        return records

    def list_dependent_artifact_ids(self, artifact_id: str) -> List[str]:
        self.initialize()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT artifact_id
                FROM artifact_inputs
                WHERE input_artifact_id = ?
                ORDER BY artifact_id
                """,
                (artifact_id,),
            ).fetchall()
        return [row["artifact_id"] for row in rows]

    def artifact_is_admissible(self, artifact_id: str) -> bool:
        return self._artifact_is_admissible(artifact_id, seen=[])

    def get_metadata(self, key: str) -> Optional[str]:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT value FROM store_metadata WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def explain_artifact(self, artifact_id: str) -> Optional[Dict[str, Any]]:
        artifact = self.get_artifact(artifact_id)
        if artifact is None:
            return None
        snapshot = (
            self.get_snapshot(artifact.source_snapshot_id)
            if artifact.source_snapshot_id
            else None
        )
        source = self.get_source(snapshot.source_id) if snapshot else None
        transform = self.get_transform(artifact.transform_id)
        receipt = self.get_receipt(artifact.receipt_id)
        tombstone = self.get_tombstone(artifact_id)
        return {
            "artifact": artifact.to_dict(),
            "source": source.to_dict() if source else None,
            "source_snapshot": snapshot.to_dict() if snapshot else None,
            "transform": transform.to_dict() if transform else None,
            "receipt": receipt.to_dict() if receipt else None,
            "tombstone": tombstone.to_dict() if tombstone else None,
        }

    def count_rows(self, table: str, *, status: Optional[str] = None) -> int:
        allowed = {
            "sources",
            "source_snapshots",
            "transforms",
            "derived_artifacts",
            "artifact_inputs",
            "receipts",
            "index_update_plans",
            "artifact_tombstones",
            "store_metadata",
        }
        if table not in allowed:
            raise ValueError(f"unsupported table: {table}")
        self.initialize()
        with self.connect() as conn:
            if status is None:
                row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            else:
                row = conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE status = ?",
                    (status,),
                ).fetchone()
        return int(row["n"])

    def _insert_plan(self, conn: sqlite3.Connection, plan: IndexUpdatePlan) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO index_update_plans (
              plan_id,
              previous_state_hash,
              proposed_state_hash,
              added_count,
              updated_count,
              deleted_count,
              created_at,
              plan_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                plan.plan_id,
                plan.previous_state_hash,
                plan.proposed_state_hash,
                plan.added_count,
                plan.updated_count,
                plan.deleted_count,
                plan.created_at,
                encode_json(plan.to_dict()),
            ),
        )

    def _ensure_schema_metadata(self, conn: sqlite3.Connection) -> None:
        expected = {
            "derived_schema_version": DERIVED_SCHEMA_VERSION,
            "receipt_schema_version": RECEIPT_SCHEMA_VERSION,
        }
        updated_at = now_iso()
        for key, value in expected.items():
            row = conn.execute(
                "SELECT value FROM store_metadata WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                if self._has_unversioned_derived_state(conn):
                    raise RuntimeError(
                        "unversioned derived store contains committed state; "
                        "explicit migration is required"
                    )
                conn.execute(
                    """
                    INSERT INTO store_metadata (key, value, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (key, value, updated_at),
                )
            elif row["value"] != value:
                raise RuntimeError(
                    f"unsupported derived store metadata {key}={row['value']}; "
                    f"expected {value}"
                )

    def _has_unversioned_derived_state(self, conn: sqlite3.Connection) -> bool:
        tables = (
            "sources",
            "source_snapshots",
            "transforms",
            "derived_artifacts",
            "receipts",
            "index_update_plans",
            "artifact_tombstones",
        )
        for table in tables:
            row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            if int(row["n"]):
                return True
        return False

    def _artifact_is_admissible(self, artifact_id: str, seen: List[str]) -> bool:
        if artifact_id in seen:
            return False
        artifact = self.get_artifact(artifact_id)
        if artifact is None or artifact.status != "active":
            return False
        if self.get_tombstone(artifact_id) is not None:
            return False
        next_seen = seen + [artifact_id]
        for input_id in artifact.input_artifact_ids:
            if not self._artifact_is_admissible(input_id, next_seen):
                return False
        return True

    def _apply_operation(
        self, conn: sqlite3.Connection, operation: Dict[str, Any]
    ) -> None:
        op_type = operation["type"]
        if op_type == "upsert_source":
            self._upsert_source(conn, operation["source"])
        elif op_type == "add_snapshot":
            self._insert_snapshot(conn, operation["snapshot"])
        elif op_type == "add_transform":
            self._insert_transform(conn, operation["transform"])
        elif op_type == "add_artifact":
            self._insert_artifact(conn, operation["artifact"])
            for artifact_input in operation.get("inputs", []):
                self._insert_artifact_input(conn, artifact_input)
            self._insert_receipt(conn, operation["receipt"])
        elif op_type == "stale_artifact":
            self._mark_artifact_status(conn, operation["artifact_id"], "stale")
            self._insert_receipt(conn, operation["receipt"])
        elif op_type == "tombstone_artifact":
            self._mark_artifact_status(conn, operation["artifact_id"], "tombstoned")
            self._insert_tombstone(conn, operation["tombstone"])
            self._insert_receipt(conn, operation["receipt"])
        else:
            raise ValueError(f"unsupported derived plan operation: {op_type}")

    def _upsert_source(self, conn: sqlite3.Connection, data: Dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO sources (
              source_id,
              source_type,
              uri,
              first_seen_at,
              last_seen_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                data["source_id"],
                data["source_type"],
                data["uri"],
                data["first_seen_at"],
                data["last_seen_at"],
            ),
        )
        conn.execute(
            "UPDATE sources SET last_seen_at = ? WHERE source_id = ?",
            (data["last_seen_at"], data["source_id"]),
        )

    def _insert_snapshot(self, conn: sqlite3.Connection, data: Dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO source_snapshots (
              snapshot_id,
              source_id,
              content_hash,
              size_bytes,
              observed_at,
              metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                data["snapshot_id"],
                data["source_id"],
                data["content_hash"],
                data["size_bytes"],
                data["observed_at"],
                encode_json(data.get("metadata", {})),
            ),
        )

    def _insert_transform(self, conn: sqlite3.Connection, data: Dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO transforms (
              transform_id,
              name,
              version,
              code_hash,
              config_hash,
              runtime_hash
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                data["transform_id"],
                data["name"],
                data["version"],
                data["code_hash"],
                data["config_hash"],
                data.get("runtime_hash"),
            ),
        )

    def _insert_artifact(self, conn: sqlite3.Connection, data: Dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT INTO derived_artifacts (
              artifact_id,
              artifact_type,
              source_snapshot_id,
              transform_id,
              output_hash,
              receipt_id,
              derivation_verification_level,
              status,
              created_at,
              metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
              status = excluded.status,
              receipt_id = excluded.receipt_id,
              derivation_verification_level = excluded.derivation_verification_level,
              metadata_json = excluded.metadata_json
            """,
            (
                data["artifact_id"],
                data["artifact_type"],
                data.get("source_snapshot_id"),
                data["transform_id"],
                data["output_hash"],
                data["receipt_id"],
                data["derivation_verification_level"],
                data["status"],
                data["created_at"],
                encode_json(data.get("metadata", {})),
            ),
        )

    def _insert_artifact_input(
        self, conn: sqlite3.Connection, data: Dict[str, Any]
    ) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO artifact_inputs (
              artifact_id,
              input_artifact_id,
              input_role
            )
            VALUES (?, ?, ?)
            """,
            (data["artifact_id"], data["input_artifact_id"], data["input_role"]),
        )

    def _insert_receipt(self, conn: sqlite3.Connection, data: Dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO receipts (
              receipt_id,
              kind,
              subject_id,
              derivation_verification_level,
              status,
              created_at,
              receipt_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["receipt_id"],
                data["kind"],
                data["subject_id"],
                data["derivation_verification_level"],
                data["status"],
                data["created_at"],
                encode_json(data),
            ),
        )

    def _insert_tombstone(self, conn: sqlite3.Connection, data: Dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO artifact_tombstones (
              artifact_id,
              reason,
              tombstoned_at,
              receipt_id
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                data["artifact_id"],
                data["reason"],
                data["tombstoned_at"],
                data["receipt_id"],
            ),
        )

    def _mark_artifact_status(
        self, conn: sqlite3.Connection, artifact_id: str, status: str
    ) -> None:
        conn.execute(
            "UPDATE derived_artifacts SET status = ? WHERE artifact_id = ?",
            (status, artifact_id),
        )


def _row_to_source(row: sqlite3.Row) -> Source:
    return Source(
        source_id=row["source_id"],
        source_type=row["source_type"],
        uri=row["uri"],
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
    )


def _row_to_snapshot(row: sqlite3.Row) -> SourceSnapshot:
    return SourceSnapshot(
        snapshot_id=row["snapshot_id"],
        source_id=row["source_id"],
        content_hash=row["content_hash"],
        size_bytes=row["size_bytes"],
        observed_at=row["observed_at"],
        metadata=decode_json(row["metadata_json"]),
    )


def _row_to_transform(row: sqlite3.Row) -> TransformSpec:
    return TransformSpec(
        transform_id=row["transform_id"],
        name=row["name"],
        version=row["version"],
        code_hash=row["code_hash"],
        config_hash=row["config_hash"],
        runtime_hash=row["runtime_hash"],
    )


def _row_to_artifact(row: sqlite3.Row, input_ids: List[str]) -> DerivedArtifact:
    return DerivedArtifact(
        artifact_id=row["artifact_id"],
        artifact_type=row["artifact_type"],
        source_snapshot_id=row["source_snapshot_id"],
        input_artifact_ids=tuple(input_ids),
        transform_id=row["transform_id"],
        output_hash=row["output_hash"],
        receipt_id=row["receipt_id"],
        derivation_verification_level=row["derivation_verification_level"],
        status=row["status"],
        created_at=row["created_at"],
        metadata=decode_json(row["metadata_json"]),
    )


def _row_to_receipt(row: sqlite3.Row) -> DerivationReceipt:
    data = decode_json(row["receipt_json"])
    return DerivationReceipt(
        receipt_id=data["receipt_id"],
        kind=data["kind"],
        subject_id=data["subject_id"],
        source_snapshot_ids=tuple(data.get("source_snapshot_ids", [])),
        input_artifact_ids=tuple(data.get("input_artifact_ids", [])),
        transform_id=data.get("transform_id", ""),
        output_hash=data.get("output_hash", ""),
        derivation_verification_level=data["derivation_verification_level"],
        status=data["status"],
        created_at=data["created_at"],
        metadata=data.get("metadata", {}),
    )


def _row_to_tombstone(row: sqlite3.Row) -> ArtifactTombstone:
    return ArtifactTombstone(
        artifact_id=row["artifact_id"],
        reason=row["reason"],
        tombstoned_at=row["tombstoned_at"],
        receipt_id=row["receipt_id"],
    )
