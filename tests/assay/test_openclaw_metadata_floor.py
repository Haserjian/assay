"""Tests for the executable OpenClaw metadata-floor checker."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from assay.openclaw_demo import run_openclaw_demo


def _load_metadata_module():
    script_path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "check_openclaw_metadata_floor.py"
    )
    spec = importlib.util.spec_from_file_location(
        "test_openclaw_metadata_floor",
        script_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_metadata_floor_passes_for_clean_demo_artifacts(tmp_path: Path) -> None:
    module = _load_metadata_module()
    result = run_openclaw_demo(tmp_path / "demo")
    openclaw_json_path = tmp_path / "openclaw.json"
    openclaw_json_path.write_text(
        json.dumps(
            {
                "pack_dir": str(result.pack_dir),
                "summary": str(result.summary_path),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    report = module.check_openclaw_metadata_floor_from_openclaw_json(openclaw_json_path)

    assert report.passed is True, report.to_dict()
    assert report.import_status == "clean"
    assert report.entry_count == 4


def test_metadata_floor_passes_for_partial_import_when_reasons_survive(
    tmp_path: Path,
) -> None:
    module = _load_metadata_module()
    result = run_openclaw_demo(
        tmp_path / "demo_partial",
        session_log_lines=[
            {
                "tool": "browser",
                "url": "https://github.com/anthropics/claude-code",
                "content_length": 1024,
            },
            {"tool": "shell_exec", "command": "whoami"},
            {"tool": "browser", "url": "https://evil.com/login"},
            {
                "tool": "browser",
                "url": "https://github.com/login",
                "sensitive_action_attempted": True,
            },
            "not-json",
            "",
        ],
    )

    report = module.check_openclaw_metadata_floor(
        pack_dir=result.pack_dir,
        summary_path=result.summary_path,
    )

    assert report.passed is True, report.to_dict()
    assert report.import_status == "partial"


def test_metadata_floor_holds_when_evidence_source_disappears(tmp_path: Path) -> None:
    module = _load_metadata_module()
    result = run_openclaw_demo(tmp_path / "demo_mutated")
    receipt_pack_path = result.pack_dir / "receipt_pack.jsonl"

    entries = [
        json.loads(line)
        for line in receipt_pack_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    entries[0].pop("evidence_source", None)
    receipt_pack_path.write_text(
        "\n".join(
            json.dumps(entry, separators=(",", ":"), sort_keys=True)
            for entry in entries
        )
        + "\n",
        encoding="utf-8",
    )

    report = module.check_openclaw_metadata_floor(
        pack_dir=result.pack_dir,
        summary_path=result.summary_path,
    )

    assert report.passed is False
    assert any(issue.field == "evidence_source" for issue in report.issues)
