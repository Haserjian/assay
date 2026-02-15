"""Tests for scripts/activation_qa.py harness (Stage 1 PR5)."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _script_path() -> Path:
    return _repo_root() / "scripts" / "activation_qa.py"


def test_activation_harness_succeeds_in_explicit_workdir(tmp_path: Path) -> None:
    """Harness runs all checks and writes expected artifacts."""
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--workdir", str(tmp_path)],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    assert "Activation QA Harness" in proc.stdout
    assert "checks passed" in proc.stdout

    assert (tmp_path / "assay.mcp-policy.yaml").exists()
    assert (tmp_path / ".github" / "workflows" / "assay-verify.yml").exists()


def test_activation_harness_keep_workdir_preserves_temp_dir() -> None:
    """--keep-workdir leaves temp dir behind for inspection."""
    proc = subprocess.run(
        [sys.executable, str(_script_path()), "--keep-workdir"],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr

    m = re.search(r"Work dir:\s*(.+)", proc.stdout)
    assert m, proc.stdout
    wd = Path(m.group(1).strip())
    assert wd.exists()

    # Cleanup temp dir created by the harness.
    shutil.rmtree(wd, ignore_errors=True)
