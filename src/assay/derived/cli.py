"""Experimental CLI for Assay receipted derived context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import typer

from assay.derived.planner import apply_derived_context, plan_derived_context
from assay.derived.scanner import scan_repository
from assay.derived.store import DerivedStore
from assay.derived.transforms import (
    DEFAULT_CHUNKER_VERSION,
    DEFAULT_MAX_LINES,
    line_chunk_transform_spec,
)
from assay.derived.verifier import verify_receipt


derived_app = typer.Typer(
    help="Experimental receipted derived context commands.",
    no_args_is_help=True,
)


@derived_app.command("scan")
def scan_command(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
) -> None:
    snapshots = scan_repository(path)
    _emit(
        {
            "status": "ok",
            "root": str(path.resolve()),
            "snapshot_count": len(snapshots),
            "snapshots": [
                _snapshot_output(item.snapshot.to_dict()) for item in snapshots
            ],
        }
    )


@derived_app.command("plan")
def plan_command(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite store path."),
    chunk_lines: int = typer.Option(
        DEFAULT_MAX_LINES, "--chunk-lines", help="Maximum lines per source chunk."
    ),
    chunker_version: str = typer.Option(
        DEFAULT_CHUNKER_VERSION,
        "--chunker-version",
        help="Line chunker transform version.",
    ),
) -> None:
    store = _store_for_path(path, db)
    transform = line_chunk_transform_spec(
        version=chunker_version, max_lines=chunk_lines
    )
    plan = plan_derived_context(path, store, transform=transform, max_lines=chunk_lines)
    store.put_plan(plan)
    _emit(_plan_output(plan, store))


@derived_app.command("apply")
def apply_command(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite store path."),
    chunk_lines: int = typer.Option(
        DEFAULT_MAX_LINES, "--chunk-lines", help="Maximum lines per source chunk."
    ),
    chunker_version: str = typer.Option(
        DEFAULT_CHUNKER_VERSION,
        "--chunker-version",
        help="Line chunker transform version.",
    ),
) -> None:
    store = _store_for_path(path, db)
    transform = line_chunk_transform_spec(
        version=chunker_version, max_lines=chunk_lines
    )
    plan = apply_derived_context(
        path, store, transform=transform, max_lines=chunk_lines
    )
    _emit(_plan_output(plan, store))


@derived_app.command("explain")
def explain_command(
    artifact_id: str = typer.Argument(...),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite store path."),
) -> None:
    store = _store_for_current_dir(db)
    explanation = store.explain_artifact(artifact_id)
    if explanation is None:
        _emit({"status": "missing", "artifact_id": artifact_id})
        raise typer.Exit(1)
    _emit({"status": "ok", "explain": _redact_explanation(explanation)})


@derived_app.command("verify")
def verify_command(
    receipt_id: str = typer.Argument(...),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite store path."),
) -> None:
    store = _store_for_current_dir(db)
    result = verify_receipt(store, receipt_id)
    _emit({"status": "ok" if result.ok else "failed", "verification": result.to_dict()})
    if not result.ok:
        raise typer.Exit(2)


def _store_for_path(path: Path, db: Optional[Path]) -> DerivedStore:
    return DerivedStore((db or _default_db(path)).resolve())


def _store_for_current_dir(db: Optional[Path]) -> DerivedStore:
    return DerivedStore((db or _default_db(Path.cwd())).resolve())


def _default_db(root: Path) -> Path:
    return root.resolve() / ".assay" / "derived.sqlite"


def _emit(data: Dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, default=str))


def _plan_output(plan, store: DerivedStore) -> Dict[str, Any]:
    return {
        "status": "ok",
        "db": str(store.path),
        "plan": {
            "plan_id": plan.plan_id,
            "root": plan.root,
            "previous_state_hash": plan.previous_state_hash,
            "proposed_state_hash": plan.proposed_state_hash,
            "added_count": plan.added_count,
            "updated_count": plan.updated_count,
            "deleted_count": plan.deleted_count,
            "operation_count": len(plan.operations),
            "operations": [_operation_summary(op) for op in plan.operations],
        },
    }


def _operation_summary(operation: Dict[str, Any]) -> Dict[str, Any]:
    op_type = operation["type"]
    summary: Dict[str, Any] = {"type": op_type}
    if op_type == "add_artifact":
        artifact = operation["artifact"]
        summary.update(
            {
                "artifact_id": artifact["artifact_id"],
                "artifact_type": artifact["artifact_type"],
                "source_snapshot_id": artifact["source_snapshot_id"],
                "receipt_id": artifact["receipt_id"],
            }
        )
    elif op_type in {"stale_artifact", "tombstone_artifact"}:
        summary["artifact_id"] = operation["artifact_id"]
        summary["receipt_id"] = operation["receipt"]["receipt_id"]
    elif op_type == "add_snapshot":
        summary["snapshot_id"] = operation["snapshot"]["snapshot_id"]
    elif op_type == "upsert_source":
        summary["source_id"] = operation["source"]["source_id"]
        summary["uri"] = operation["source"]["uri"]
    elif op_type == "add_transform":
        summary["transform_id"] = operation["transform"]["transform_id"]
    return summary


def _snapshot_output(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    metadata = dict(snapshot.get("metadata", {}))
    metadata.pop("content_text", None)
    snapshot = dict(snapshot)
    snapshot["metadata"] = metadata
    return snapshot


def _redact_explanation(explanation: Dict[str, Any]) -> Dict[str, Any]:
    result = json.loads(json.dumps(explanation, default=str))
    source_snapshot = result.get("source_snapshot")
    if source_snapshot:
        source_snapshot["metadata"] = _metadata_preview(
            source_snapshot.get("metadata", {})
        )
    artifact = result.get("artifact")
    if artifact:
        artifact["metadata"] = _metadata_preview(artifact.get("metadata", {}))
    return result


def _metadata_preview(metadata: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(metadata)
    content_text = result.pop("content_text", None)
    chunk_text = result.pop("text", None)
    if isinstance(content_text, str):
        result["content_text_preview"] = _preview(content_text)
    if isinstance(chunk_text, str):
        result["text_preview"] = _preview(chunk_text)
    return result


def _preview(text: str, limit: int = 160) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."
