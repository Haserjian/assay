"""CLI for Assay Immunity Packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import typer

from assay.immunity import (
    ImmunityValidationError,
    build_guardian_caution_signal,
    derive_epigenetic_markers,
    derive_inoculation_pack,
    load_failure_artifact,
    load_immunity_artifact,
    verify_immunity_artifact_file,
    write_immunity_artifacts,
)

immunity_app = typer.Typer(
    help="Derive portable caution artifacts from honest failures.",
    no_args_is_help=True,
)


@immunity_app.command("derive")
def derive_command(
    input_artifact: Path = typer.Argument(
        ...,
        exists=True,
        help="Failure JSON file or proof-pack directory.",
    ),
    out_dir: Path = typer.Option(
        Path("artifacts/immunity"),
        "--out-dir",
        "-o",
        help="Directory for immunity artifacts.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable summary.",
    ),
) -> None:
    """Derive an InoculationPack and EpigeneticMarkers."""
    try:
        artifact = load_failure_artifact(input_artifact)
        pack = derive_inoculation_pack(artifact)
        markers = derive_epigenetic_markers(pack)
        paths = write_immunity_artifacts(pack, markers, out_dir)
    except ImmunityValidationError as exc:
        _emit(
            {
                "status": "error",
                "error": str(exc),
                "input": str(input_artifact),
            },
            output_json=output_json,
        )
        raise typer.Exit(3) from exc

    summary: dict[str, Any] = {
        "status": "ok",
        "pack_id": pack.pack_id,
        "failure_class": pack.failure_class,
        "marker_count": len(markers),
        "inoculation_pack": str(paths["pack"]),
        "markers": [
            {
                "marker_id": marker.marker_id,
                "marker_type": marker.marker_type,
                "recommended_guardian_action": marker.recommended_guardian_action,
                "authority_delta": marker.authority_delta,
                "path": str(paths[marker.marker_id]),
            }
            for marker in markers
        ],
    }
    _emit(summary, output_json=output_json)


@immunity_app.command("verify")
def verify_command(
    artifact_path: Path = typer.Argument(
        ...,
        exists=True,
        help="InoculationPack or EpigeneticMarker JSON file.",
    ),
    source_pack: Optional[Path] = typer.Option(
        None,
        "--source-pack",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Optional source proof-pack directory to bind-check an InoculationPack.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable summary.",
    ),
) -> None:
    """Verify an immunity artifact offline."""
    try:
        result = verify_immunity_artifact_file(
            artifact_path,
            source_pack_dir=source_pack,
        )
    except ImmunityValidationError as exc:
        _emit_verification(
            {
                "status": "error",
                "error": str(exc),
                "path": str(artifact_path),
            },
            output_json=output_json,
        )
        raise typer.Exit(3) from exc

    payload: dict[str, Any] = {
        "status": "ok" if result.valid else "invalid",
        "artifact_id": result.artifact_id,
        "artifact_type": result.artifact_type,
        "errors": result.errors,
        "identity_valid": result.identity_valid,
        "path": str(artifact_path),
        "schema_valid": result.schema_valid,
        "source_bound": result.source_bound,
        "source_pack": str(source_pack) if source_pack else None,
        "stale": result.stale,
        "valid": result.valid,
    }
    _emit_verification(payload, output_json=output_json)
    if not result.valid:
        raise typer.Exit(1)


def _emit(payload: dict[str, Any], *, output_json: bool) -> None:
    if output_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if payload["status"] != "ok":
        typer.echo(f"error: {payload['error']}", err=True)
        return
    typer.echo(f"InoculationPack: {payload['inoculation_pack']}")
    for marker in payload["markers"]:
        typer.echo(
            "EpigeneticMarker: "
            f"{marker['path']} "
            f"({marker['recommended_guardian_action']}, "
            f"authority_delta={marker['authority_delta']})"
        )


def _emit_verification(payload: dict[str, Any], *, output_json: bool) -> None:
    if output_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if payload["status"] == "error":
        typer.echo(f"error: {payload['error']}", err=True)
        return
    if payload["status"] == "invalid":
        typer.echo(
            f"INVALID {payload['artifact_type']} {payload.get('artifact_id') or ''}".rstrip()
        )
        for error in payload["errors"]:
            typer.echo(f"- {error}")
        return
    typer.echo(
        f"VALID {payload['artifact_type']} {payload.get('artifact_id') or ''}".rstrip()
    )


@immunity_app.command("signal")
def signal_command(
    pack_path: Path = typer.Argument(
        ...,
        exists=True,
        help="Verified InoculationPack JSON file.",
    ),
    marker_path: Path = typer.Option(
        ...,
        "--marker",
        exists=True,
        help="Matching EpigeneticMarker JSON file.",
    ),
    source_pack: Path = typer.Option(
        ...,
        "--source-pack",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Source proof-pack directory for binding checks.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable signal.",
    ),
) -> None:
    """Export a source-bound caution-only signal."""
    try:
        result = build_guardian_caution_signal(
            load_immunity_artifact(pack_path),
            load_immunity_artifact(marker_path),
            source_pack_dir=source_pack,
        )
    except ImmunityValidationError as exc:
        payload = {
            "status": "invalid",
            "error": str(exc),
            "pack_path": str(pack_path),
            "marker_path": str(marker_path),
            "source_pack": str(source_pack),
        }
        _emit_signal(payload, output_json=output_json)
        raise typer.Exit(1) from exc

    payload = {
        "status": "ok",
        "signal": result.signal,
        "pack_verification": result.pack_verification.to_dict(),
        "marker_verification": result.marker_verification.to_dict(),
    }
    _emit_signal(payload, output_json=output_json)


def _emit_signal(payload: dict[str, Any], *, output_json: bool) -> None:
    if output_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if payload["status"] != "ok":
        typer.echo(f"invalid: {payload['error']}", err=True)
        return
    signal = payload["signal"]
    typer.echo(
        f"CAUTION {signal['marker_id']} -> {signal['recommended_action']} "
        f"(authority_delta={signal['authority_delta']})"
    )


__all__ = ["immunity_app"]
