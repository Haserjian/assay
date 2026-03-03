"""Pilot orchestration — run, verify, and closeout for evidence assessment.

Ports the ccio pilot pipeline as self-contained assay CLI commands.
No ccio imports; calls assay subcommands via subprocess.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BUNDLE_SCHEMA_VERSION = "pilot_bundle_manifest.v1"

REQUIRED_PACK_FILES = frozenset({
    "pack_manifest.json",
    "pack_signature.sig",
    "receipt_pack.jsonl",
    "verify_report.json",
    "verify_transcript.md",
})

STEPS = [
    "preflight",
    "scan",
    "score_before",
    "patch",
    "run",
    "verify_pack",
    "tamper_test",
    "score_after",
    "write_bundle",
]

# --- Claim codes (v1 taxonomy) ---
C_PACK_VERIFY_NOT_PASS = "C_PACK_VERIFY_NOT_PASS"
C_SCORE_BEFORE_MISSING = "C_SCORE_BEFORE_MISSING"
C_SCORE_AFTER_MISSING = "C_SCORE_AFTER_MISSING"
C_SCORE_DELTA_UNAVAILABLE = "C_SCORE_DELTA_UNAVAILABLE"
C_NO_RECEIPTS = "C_NO_RECEIPTS"

# --- Claim codes (v1.3 hardening) ---
C_TRUNCATED_OUTPUT = "C_TRUNCATED_OUTPUT"
C_LOCALITY_UNKNOWN = "C_LOCALITY_UNKNOWN"
C_TIME_AUTHORITY_WEAK = "C_TIME_AUTHORITY_WEAK"

CLAIM_HINTS: dict[str, str] = {
    C_PACK_VERIFY_NOT_PASS: "Run assay verify-pack and ensure exit 0",
    C_SCORE_BEFORE_MISSING: "Run assay score before patching (score/before.json)",
    C_SCORE_AFTER_MISSING: "Run assay score after patching (score/after.json)",
    C_SCORE_DELTA_UNAVAILABLE: "Ensure score/delta.json exists with before/after/delta fields",
    C_NO_RECEIPTS: "Emit at least one receipt (model_call or completeness proof)",
    C_TRUNCATED_OUTPUT: "One or more receipts have finish_reason=='length'; increase token limit or chunk input",
    C_LOCALITY_UNKNOWN: "Receipt missing locality or locality=='unknown'; set local|cloud|hybrid in provider config",
    C_TIME_AUTHORITY_WEAK: "time_authority is local_clock or missing; upgrade to ntp_verified or tsa_anchored",
}

VERIFY_PROFILES: dict[str, dict[str, bool]] = {
    "score-delta": {
        "require_pack_verify_pass": True,
        "require_score_files": True,
        "require_score_delta": True,
        "require_receipts": False,
    },
    "integrity-only": {
        "require_pack_verify_pass": False,
        "require_score_files": False,
        "require_score_delta": False,
        "require_receipts": False,
    },
    "otel-bridge": {
        "require_pack_verify_pass": False,
        "require_score_files": False,
        "require_score_delta": False,
        "require_receipts": True,
    },
}

_DEFAULT_PROFILE_REQS: dict[str, bool] = {
    "require_pack_verify_pass": True,
    "require_score_files": True,
    "require_score_delta": True,
    "require_receipts": False,
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PilotError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PilotConfig:
    test_cmd: str
    mode: str = "high-only"
    allow_empty: bool = False
    allow_dirty: bool = False
    patch: bool = False
    output: str = "pilot_bundle"


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    dry_run: bool = False

    def to_dict(self, *, step: str = "") -> dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "stdout_tail": self.stdout[-1200:] if self.stdout else "",
            "stderr_tail": self.stderr[-1200:] if self.stderr else "",
            "dry_run": self.dry_run,
            "step": step,
        }


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

_CONFIG_KEYS: frozenset[str] = frozenset({
    "mode", "test_cmd", "allow_empty", "allow_dirty",
    "patch", "assay_bin", "output", "repo",
})

_CONFIG_BOOL_KEYS: frozenset[str] = frozenset({
    "allow_empty", "allow_dirty", "patch",
})

_CONFIG_STR_KEYS: frozenset[str] = frozenset({
    "mode", "test_cmd", "assay_bin", "output", "repo",
})


def load_pilot_config(
    config_path: str | None,
    repo_dir: Path,
    *,
    cli_overrides: dict[str, Any] | None = None,
) -> PilotConfig:
    """Load and validate a pilot.yaml config file.

    Precedence: cli_overrides > YAML config > defaults.
    Raises PilotError on invalid config.
    """
    if config_path is not None:
        path = Path(config_path)
        if not path.exists():
            raise PilotError(f"Config file not found: {config_path}")
    else:
        path = repo_dir / "pilot.yaml"
        if not path.exists():
            # No config file — require test_cmd from CLI
            test_cmd = (cli_overrides or {}).get("test_cmd")
            if not test_cmd:
                raise PilotError(
                    "--test-cmd is required when no pilot.yaml exists"
                )
            overrides = dict(cli_overrides) if cli_overrides else {}
            return PilotConfig(**{
                k: v for k, v in overrides.items()
                if k in PilotConfig.__dataclass_fields__ and v is not None
            })

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PilotError(f"Config file must be a YAML mapping: {path}")

    version = raw.pop("version", None)
    if isinstance(version, int):
        version = str(version)
    if version != "1":
        raise PilotError(
            f"Unsupported config version: {version!r} (expected '1')"
        )

    unknown = set(raw.keys()) - _CONFIG_KEYS
    if unknown:
        raise PilotError(f"Unknown config keys: {unknown}")

    # Type validation
    for key in _CONFIG_BOOL_KEYS:
        if key in raw and not isinstance(raw[key], bool):
            raise PilotError(
                f"Config key {key!r} must be boolean (got {type(raw[key]).__name__})"
            )
    for key in _CONFIG_STR_KEYS:
        if key in raw and not isinstance(raw[key], str):
            raise PilotError(
                f"Config key {key!r} must be string (got {type(raw[key]).__name__})"
            )

    # Validate mode
    mode = raw.get("mode", "high-only")
    if mode not in ("high-only", "high+medium"):
        raise PilotError(
            f"Invalid mode {mode!r} — must be 'high-only' or 'high+medium'"
        )

    # Merge: CLI > YAML > defaults
    merged: dict[str, Any] = {}
    for f_name in PilotConfig.__dataclass_fields__:
        cli_val = (cli_overrides or {}).get(f_name)
        if cli_val is not None:
            merged[f_name] = cli_val
        elif f_name in raw:
            merged[f_name] = raw[f_name]

    if "test_cmd" not in merged:
        raise PilotError(
            "--test-cmd is required (via CLI, config file, or YAML)"
        )

    return PilotConfig(**{
        k: v for k, v in merged.items()
        if k in PilotConfig.__dataclass_fields__
    })


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _run_assay(
    args: list[str],
    *,
    cwd: Path,
    dry_run: bool = False,
    timeout: int | None = None,
) -> CommandResult:
    """Run an assay subcommand via subprocess."""
    # Use assay.cli module directly; `python -m assay` fails without assay.__main__.
    command = [sys.executable, "-m", "assay.cli"] + args
    if dry_run:
        return CommandResult(
            command=command,
            returncode=0,
            stdout="[dry-run] command not executed",
            stderr="",
            dry_run=True,
        )
    env = {**os.environ, "PYTHONPATH": ""}
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=command,
            returncode=-1,
            stdout="",
            stderr=f"TIMEOUT: command exceeded {timeout}s limit",
        )
    return CommandResult(
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def _run_cmd(
    command: list[str],
    *,
    cwd: Path,
    dry_run: bool = False,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run an arbitrary command via subprocess."""
    if dry_run:
        return CommandResult(
            command=command,
            returncode=0,
            stdout="[dry-run] command not executed",
            stderr="",
            dry_run=True,
        )
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return CommandResult(
            command=command,
            returncode=127,
            stdout="",
            stderr=f"command not found: {command[0]}",
        )
    return CommandResult(
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _git_is_dirty(repo: Path) -> bool:
    unstaged = subprocess.run(
        ["git", "diff", "--quiet", "HEAD"],
        cwd=str(repo),
        capture_output=True,
        check=False,
    )
    staged = subprocess.run(
        ["git", "diff", "--quiet", "--staged"],
        cwd=str(repo),
        capture_output=True,
        check=False,
    )
    return unstaged.returncode != 0 or staged.returncode != 0


def _git_branch(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    return (proc.stdout or "").strip() or "unknown"


def _git_short_commit(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    return (proc.stdout or "").strip() or "0000000"


# ---------------------------------------------------------------------------
# SHA256 and bundle writing
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_if_exists(src: Path | None, dest: Path) -> bool:
    if src is None or not src.exists():
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(src.read_bytes())
    return True


def _collect_artifacts(output_dir: Path) -> list[dict[str, Any]]:
    artifacts = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(output_dir)
        name = str(rel)
        if name.startswith("."):
            continue
        if name == "manifest.json":
            continue
        artifacts.append({
            "name": name,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        })
    return artifacts


def _compute_score_delta(
    before_path: Path, after_path: Path
) -> dict[str, Any]:
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = json.loads(after_path.read_text(encoding="utf-8"))

    before_raw = before["score"]["raw_score"]
    after_raw = after["score"]["raw_score"]

    breakdown: dict[str, Any] = {}
    for key in before.get("score", {}).get("breakdown", {}):
        bp = before["score"]["breakdown"][key]["points"]
        ap = after.get("score", {}).get("breakdown", {}).get(key, {}).get("points", bp)
        breakdown[key] = {"before": bp, "after": ap, "delta": round(ap - bp, 4)}

    return {
        "before": before_raw,
        "after": after_raw,
        "delta": round(after_raw - before_raw, 4),
        "breakdown": breakdown,
    }


def _env_fingerprint() -> dict[str, Any]:
    uname = os.uname()
    fp: dict[str, Any] = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "uname": {
            "sysname": uname.sysname,
            "nodename": uname.nodename,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        },
    }
    try:
        freeze = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
            check=False,
        )
        fp["pip_freeze_sha256"] = hashlib.sha256(
            freeze.stdout.encode()
        ).hexdigest()
    except FileNotFoundError:
        fp["pip_freeze_sha256"] = "unavailable"
    return fp


def _write_bundle(
    output_dir: Path,
    *,
    repo: Path,
    config: PilotConfig,
    scan_json: Path | None,
    scan_html: Path | None,
    score_before: Path | None,
    score_after: Path | None,
    pack_dir: Path | None,
    verify_summary: dict[str, Any],
    commands_run: list[dict[str, Any]],
    completed: list[str],
    dirty_tree: bool,
) -> Path:
    """Write a complete pilot bundle to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # env fingerprint
    fp = _env_fingerprint()
    (output_dir / "env_fingerprint.json").write_text(
        json.dumps(fp, indent=2) + "\n", encoding="utf-8"
    )

    # scan/
    scan_dir = output_dir / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    _copy_if_exists(scan_json, scan_dir / "gap_report.json")
    _copy_if_exists(scan_html, scan_dir / "gap_report.html")

    # score/
    score_dir = output_dir / "score"
    score_dir.mkdir(parents=True, exist_ok=True)
    _copy_if_exists(score_before, score_dir / "before.json")
    _copy_if_exists(score_after, score_dir / "after.json")

    score_delta: dict[str, Any] | None = None
    if (
        score_before and score_before.exists()
        and score_after and score_after.exists()
    ):
        try:
            score_delta = _compute_score_delta(score_before, score_after)
            (score_dir / "delta.json").write_text(
                json.dumps(score_delta, indent=2) + "\n", encoding="utf-8"
            )
        except (json.JSONDecodeError, KeyError):
            pass

    # proof/ (copy pack)
    proof_dir = output_dir / "proof"
    proof_dir.mkdir(parents=True, exist_ok=True)
    if pack_dir and pack_dir.exists():
        for item in pack_dir.iterdir():
            if item.is_file():
                (proof_dir / item.name).write_bytes(item.read_bytes())

    # verification/
    verify_dir = output_dir / "verification"
    verify_dir.mkdir(parents=True, exist_ok=True)
    (verify_dir / "summary.json").write_text(
        json.dumps(verify_summary, indent=2) + "\n", encoding="utf-8"
    )

    # replay/
    replay_dir = output_dir / "replay"
    replay_dir.mkdir(parents=True, exist_ok=True)
    replay_lines = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    for cmd_entry in commands_run:
        cmd_str = " ".join(cmd_entry.get("command", []))
        if cmd_str:
            replay_lines.append(f"# step: {cmd_entry.get('step', 'unknown')}")
            replay_lines.append(cmd_str)
            replay_lines.append("")
    (replay_dir / "replay.sh").write_text(
        "\n".join(replay_lines) + "\n", encoding="utf-8"
    )
    (replay_dir / "replay.sh").chmod(0o755)

    # Collect artifacts for manifest
    artifacts = _collect_artifacts(output_dir)

    # Pack root sha256
    pack_root_sha256 = ""
    pack_manifest_path = proof_dir / "pack_manifest.json"
    if pack_manifest_path.exists():
        try:
            pm = json.loads(pack_manifest_path.read_text(encoding="utf-8"))
            pack_root_sha256 = pm.get("pack_root_sha256", "")
        except (json.JSONDecodeError, KeyError):
            pass

    # Build manifest
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%S")
    commit = _git_short_commit(repo)
    short_hash = commit[:7] if commit else "0000000"
    bundle_id = f"pilot_{timestamp}_{short_hash}"

    manifest: dict[str, Any] = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_id": bundle_id,
        "created_at_utc": now.isoformat(),
        "repo": str(repo),
        "commit": commit,
        "branch": _git_branch(repo),
        "mode": config.mode,
        "assay_version": "assay-ai (python -m assay.cli)",
        "dirty_tree": dirty_tree,
        "allow_empty": config.allow_empty,
        "steps_completed": completed,
        "artifacts": artifacts,
        "pack_root_sha256": pack_root_sha256,
        "score_delta": score_delta or {},
    }

    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Write final state
    _write_state(output_dir, completed, "complete")

    return output_dir


def _write_state(
    output_dir: Path, completed_steps: list[str], current_step: str
) -> None:
    state = {
        "completed_steps": completed_steps,
        "current_step": current_step,
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / ".state.json").write_text(
        json.dumps(state, indent=2) + "\n", encoding="utf-8"
    )


def _read_state(output_dir: Path) -> dict[str, Any]:
    state_path = output_dir / ".state.json"
    if not state_path.exists():
        return {"completed_steps": [], "current_step": ""}
    return json.loads(state_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# run_pilot — 9-step pipeline
# ---------------------------------------------------------------------------

def run_pilot(
    repo: str | Path,
    config: PilotConfig,
    *,
    dry_run: bool = False,
    resume: bool = False,
) -> dict[str, Any]:
    """Execute the 9-step pilot pipeline. Returns summary dict."""
    repo_path = Path(repo).resolve()
    output_dir = Path(config.output).resolve()

    command_log: list[dict[str, Any]] = []
    completed: list[str] = []

    # Resume support
    if resume:
        state = _read_state(output_dir)
        completed = list(state.get("completed_steps", []))

    def should_skip(step: str) -> bool:
        return step in completed

    def record(result: CommandResult, step: str) -> CommandResult:
        command_log.append(result.to_dict(step=step))
        return result

    # Artifact paths
    scan_json: Path | None = None
    scan_html: Path | None = None
    score_before_path: Path | None = None
    score_after_path: Path | None = None
    pack_dir: Path | None = None
    verify_summary: dict[str, Any] = {}

    work_dir = output_dir / ".work"
    work_dir.mkdir(parents=True, exist_ok=True)

    # --- Step 1: preflight ---
    if not should_skip("preflight"):
        _write_state(output_dir, completed, "preflight")
        if not dry_run:
            try:
                dirty = _git_is_dirty(repo_path)
                if dirty and not config.allow_dirty:
                    raise PilotError(
                        "Working tree is dirty. Use --allow-dirty to proceed."
                    )
            except FileNotFoundError:
                pass  # not a git repo — skip dirty check

        res = record(
            _run_assay(["--help"], cwd=repo_path, dry_run=dry_run),
            "preflight",
        )
        if not dry_run and res.returncode != 0:
            raise PilotError("assay is not available")
        completed.append("preflight")
        _write_state(output_dir, completed, "preflight")

    dirty_tree = False
    if not dry_run:
        try:
            dirty_tree = _git_is_dirty(repo_path)
        except (FileNotFoundError, Exception):
            pass

    # --- Step 2: scan ---
    if not should_skip("scan"):
        _write_state(output_dir, completed, "scan")
        res = record(
            _run_assay(
                ["scan", str(repo_path), "--report"],
                cwd=repo_path,
                dry_run=dry_run,
            ),
            "scan",
        )
        if not dry_run and res.returncode != 0 and not config.allow_empty:
            raise PilotError(f"assay scan failed with exit {res.returncode}")

        gap_json = repo_path / "evidence_gap_report.json"
        gap_html = repo_path / "evidence_gap_report.html"
        if gap_json.exists():
            scan_json = gap_json
        if gap_html.exists():
            scan_html = gap_html

        completed.append("scan")
        _write_state(output_dir, completed, "scan")

    # --- Step 3: score_before ---
    if not should_skip("score_before"):
        _write_state(output_dir, completed, "score_before")
        record(
            _run_assay(
                ["score", str(repo_path)],
                cwd=repo_path,
                dry_run=dry_run,
            ),
            "score_before",
        )
        score_src = repo_path / "evidence_readiness_report.json"
        if score_src.exists():
            score_before_path = work_dir / "before.json"
            shutil.copy2(score_src, score_before_path)

        completed.append("score_before")
        _write_state(output_dir, completed, "score_before")

    # --- Step 4: patch (optional) ---
    if not should_skip("patch"):
        if config.patch:
            _write_state(output_dir, completed, "patch")
            res = record(
                _run_assay(
                    ["patch", str(repo_path), "--yes"],
                    cwd=repo_path,
                    dry_run=dry_run,
                    timeout=120,
                ),
                "patch",
            )
            if not dry_run and res.returncode != 0:
                patch_applied = "Patched " in (res.stdout or "") or "Patched " in (res.stderr or "")
                if res.returncode == -1:
                    raise PilotError("assay patch timed out (120s)")
                if not patch_applied:
                    raise PilotError(f"assay patch failed with exit {res.returncode}")

        completed.append("patch")
        _write_state(output_dir, completed, "patch")

    # --- Step 5: run ---
    if not should_skip("run"):
        _write_state(output_dir, completed, "run")
        pack_output = work_dir / "proof_pack"
        run_args = [
            "run",
            "-c", "receipt_completeness",
            "-o", str(pack_output),
        ]
        if config.allow_empty:
            run_args.append("--allow-empty")
        run_args.append("--")
        run_args.extend(shlex.split(config.test_cmd))
        res = record(
            _run_assay(run_args, cwd=repo_path, dry_run=dry_run),
            "run",
        )
        if not dry_run and res.returncode != 0:
            raise PilotError(f"assay run failed with exit {res.returncode}")
        if pack_output.exists():
            pack_dir = pack_output

        completed.append("run")
        _write_state(output_dir, completed, "run")

    # --- Step 6: verify_pack ---
    if not should_skip("verify_pack"):
        _write_state(output_dir, completed, "verify_pack")
        verify_target = pack_dir or work_dir / "proof_pack"
        res = record(
            _run_assay(
                ["verify-pack", str(verify_target)],
                cwd=repo_path,
                dry_run=dry_run,
            ),
            "verify_pack",
        )
        verify_summary = {
            "pack_verify_exit": res.returncode,
            "status": "PASS" if res.returncode == 0 else "FAIL",
            "stdout_tail": res.stdout[-500:] if res.stdout else "",
        }

        completed.append("verify_pack")
        _write_state(output_dir, completed, "verify_pack")

    # --- Step 7: tamper_test ---
    if not should_skip("tamper_test"):
        _write_state(output_dir, completed, "tamper_test")
        canonical_pack = pack_dir or work_dir / "proof_pack"
        if not dry_run and canonical_pack.exists():
            with tempfile.TemporaryDirectory(prefix="pilot_tamper_") as tmp:
                tampered = Path(tmp) / "tampered_pack"
                shutil.copytree(canonical_pack, tampered)
                receipt_jsonl = tampered / "receipt_pack.jsonl"
                if receipt_jsonl.exists():
                    with receipt_jsonl.open("a", encoding="utf-8") as f:
                        f.write('\n{"tampered":true}\n')
                res = record(
                    _run_assay(
                        ["verify-pack", str(tampered)],
                        cwd=repo_path,
                    ),
                    "tamper_test",
                )
                if res.returncode != 2:
                    raise PilotError(
                        f"Tamper test expected exit 2, got {res.returncode}"
                    )
        else:
            record(
                _run_assay(
                    ["verify-pack", "tampered_dry_run"],
                    cwd=repo_path,
                    dry_run=True,
                ),
                "tamper_test",
            )

        completed.append("tamper_test")
        _write_state(output_dir, completed, "tamper_test")

    # --- Step 8: score_after ---
    if not should_skip("score_after"):
        _write_state(output_dir, completed, "score_after")
        record(
            _run_assay(
                ["score", str(repo_path)],
                cwd=repo_path,
                dry_run=dry_run,
            ),
            "score_after",
        )
        score_src = repo_path / "evidence_readiness_report.json"
        if score_src.exists():
            score_after_path = work_dir / "after.json"
            shutil.copy2(score_src, score_after_path)

        completed.append("score_after")
        _write_state(output_dir, completed, "score_after")

    # --- Step 9: write_bundle ---
    if not should_skip("write_bundle"):
        _write_state(output_dir, completed, "write_bundle")

        if not dry_run:
            _write_bundle(
                output_dir,
                repo=repo_path,
                config=config,
                scan_json=scan_json,
                scan_html=scan_html,
                score_before=score_before_path,
                score_after=score_after_path,
                pack_dir=pack_dir,
                verify_summary=verify_summary,
                commands_run=command_log,
                completed=completed,
                dirty_tree=dirty_tree,
            )

        completed.append("write_bundle")
        _write_state(output_dir, completed, "write_bundle")

    return {
        "output_dir": str(output_dir),
        "steps_completed": completed,
        "commands": command_log,
        "dirty_tree": dirty_tree,
    }


# ---------------------------------------------------------------------------
# verify_pilot_bundle — profile-aware bundle verification
# ---------------------------------------------------------------------------

def _load_manifest(bundle_path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    manifest_path = bundle_path / "manifest.json"
    if not manifest_path.exists():
        return None, ["E_MANIFEST_MISSING"]
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, ["E_SCHEMA_INVALID"]
    if data.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        return None, ["E_SCHEMA_INVALID"]
    return data, []


def _check_integrity(
    bundle_path: Path, manifest: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    for artifact in manifest.get("artifacts", []):
        name = artifact["name"]
        expected_sha = artifact["sha256"]
        artifact_path = bundle_path / name
        if not artifact_path.exists():
            errors.append("E_MANIFEST_TAMPER")
            continue
        actual_sha = sha256_file(artifact_path)
        if actual_sha != expected_sha:
            errors.append("E_MANIFEST_TAMPER")

    proof_dir = bundle_path / "proof"
    for required_file in REQUIRED_PACK_FILES:
        if not (proof_dir / required_file).exists():
            errors.append(f"E_REQUIRED_FILE_MISSING:{required_file}")

    return errors


@dataclass
class ReceiptStats:
    """Quality signals extracted from receipt_pack.jsonl."""
    count: int = 0
    truncated_count: int = 0
    locality_unknown_count: int = 0
    time_authority_weak_count: int = 0


def _inspect_receipts(bundle_path: Path) -> ReceiptStats:
    """Parse receipt_pack.jsonl and extract quality signals."""
    receipt_path = bundle_path / "proof" / "receipt_pack.jsonl"
    if not receipt_path.exists():
        return ReceiptStats()
    stats = ReceiptStats()
    for line in receipt_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        stats.count += 1
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("finish_reason") == "length":
            stats.truncated_count += 1
        loc = r.get("locality")
        if loc is None or loc == "unknown":
            stats.locality_unknown_count += 1
        ta = r.get("time_authority")
        if ta is None or ta == "local_clock":
            stats.time_authority_weak_count += 1
    return stats


def _check_claims(
    bundle_path: Path, *, profile: str | None = None
) -> tuple[list[str], list[str]]:
    """Check profile-aware claims. Returns (fail_codes, warn_codes)."""
    reqs = VERIFY_PROFILES.get(profile, _DEFAULT_PROFILE_REQS) if profile else _DEFAULT_PROFILE_REQS
    codes: list[str] = []
    warn_codes: list[str] = []

    # Inspect receipts (used for both fail and warn checks)
    stats = _inspect_receipts(bundle_path)

    if reqs["require_pack_verify_pass"]:
        summary_path = bundle_path / "verification" / "summary.json"
        failed = False
        if not summary_path.exists():
            failed = True
        else:
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                failed = True
            else:
                if summary.get("pack_verify_exit") != 0:
                    failed = True
        if failed:
            codes.append(C_PACK_VERIFY_NOT_PASS)

    if reqs.get("require_score_files"):
        if not (bundle_path / "score" / "before.json").exists():
            codes.append(C_SCORE_BEFORE_MISSING)
        if not (bundle_path / "score" / "after.json").exists():
            codes.append(C_SCORE_AFTER_MISSING)

    if reqs["require_score_delta"]:
        delta_path = bundle_path / "score" / "delta.json"
        if not delta_path.exists():
            codes.append(C_SCORE_DELTA_UNAVAILABLE)
        else:
            try:
                json.loads(delta_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                codes.append(C_SCORE_DELTA_UNAVAILABLE)

    if reqs["require_receipts"]:
        if stats.count == 0:
            codes.append(C_NO_RECEIPTS)

    # --- Receipt quality warnings (Phase 1: always warn, never fail) ---
    if stats.truncated_count > 0:
        warn_codes.append(C_TRUNCATED_OUTPUT)
    if stats.count > 0 and stats.locality_unknown_count > 0:
        warn_codes.append(C_LOCALITY_UNKNOWN)
    if stats.count > 0 and stats.time_authority_weak_count > 0:
        warn_codes.append(C_TIME_AUTHORITY_WEAK)

    return codes, warn_codes


def verify_pilot_bundle(
    bundle_path: Path, *, profile: str | None = None
) -> tuple[int, list[str], list[str]]:
    """Verify a pilot bundle. Returns (exit_code, error_codes, warn_codes).

    Exit codes:
        0 — integrity pass + claims pass
        1 — integrity pass + claims fail
        2 — integrity/tamper fail
        3 — malformed input
    """
    # Layer 1: Structural
    manifest, structural_errors = _load_manifest(bundle_path)
    if structural_errors:
        return 3, structural_errors, []

    assert manifest is not None

    # Layer 2: Integrity
    integrity_errors = _check_integrity(bundle_path, manifest)
    if integrity_errors:
        return 2, integrity_errors, []

    # Layer 3: Claims (profile-aware)
    claims_errors, warn_codes = _check_claims(bundle_path, profile=profile)
    if claims_errors:
        return 1, claims_errors, warn_codes

    return 0, [], warn_codes


def _run_self_test(bundle_path: Path) -> tuple[int, list[str]]:
    """Copy bundle to temp, mutate critical files, verify detection."""
    mutations = [
        "manifest.json",
        "proof/receipt_pack.jsonl",
        "proof/pack_manifest.json",
        "verification/summary.json",
    ]
    failures: list[str] = []

    for target in mutations:
        with tempfile.TemporaryDirectory(prefix="pilot_selftest_") as tmp:
            tmp_bundle = Path(tmp) / "bundle"
            shutil.copytree(bundle_path, tmp_bundle)

            target_path = tmp_bundle / target
            if not target_path.exists():
                failures.append(f"SKIP:{target} (not present)")
                continue

            with target_path.open("a", encoding="utf-8") as f:
                f.write('\n{"selftest_tamper": true}\n')

            exit_code, _errors, _warns = verify_pilot_bundle(tmp_bundle)
            if target == "manifest.json":
                if exit_code not in (2, 3):
                    failures.append(
                        f"FAIL:{target} expected exit 2 or 3, got {exit_code}"
                    )
            else:
                if exit_code != 2:
                    failures.append(
                        f"FAIL:{target} expected exit 2, got {exit_code}"
                    )

    if failures:
        return 1, failures
    return 0, []


# ---------------------------------------------------------------------------
# run_pilot_closeout — closeout orchestration
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _extract_bundle_id(bundle_path: Path) -> str:
    manifest = _load_json(bundle_path / "manifest.json")
    if manifest and isinstance(manifest.get("bundle_id"), str) and manifest["bundle_id"].strip():
        return manifest["bundle_id"]
    pack_manifest = _load_json(bundle_path / "proof" / "pack_manifest.json")
    if pack_manifest and isinstance(pack_manifest.get("pack_id"), str) and pack_manifest["pack_id"].strip():
        return pack_manifest["pack_id"]
    return "unknown"


def _extract_scores(bundle_path: Path) -> tuple[float | None, float | None, float | None]:
    before_score: float | None = None
    after_score: float | None = None
    delta_score: float | None = None

    before_path = bundle_path / "score" / "before.json"
    if before_path.exists():
        try:
            data = json.loads(before_path.read_text(encoding="utf-8"))
            before_score = data.get("score", {}).get("raw_score")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    after_path = bundle_path / "score" / "after.json"
    if after_path.exists():
        try:
            data = json.loads(after_path.read_text(encoding="utf-8"))
            after_score = data.get("score", {}).get("raw_score")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    delta_path = bundle_path / "score" / "delta.json"
    if delta_path.exists():
        try:
            data = json.loads(delta_path.read_text(encoding="utf-8"))
            delta_score = data.get("delta")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    return before_score, after_score, delta_score


def _extract_verify(bundle_path: Path) -> tuple[str, int | None]:
    summary_path = bundle_path / "verification" / "summary.json"
    if not summary_path.exists():
        return "unknown", None
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
        exit_code = data.get("pack_verify_exit")
        status = data.get("status", "unknown")
        return status, exit_code
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "unknown", None


def _verify_exit_to_status(exit_code: int | None) -> str:
    if exit_code is None:
        return "unknown"
    if exit_code == 0:
        return "pass"
    if exit_code == 1:
        return "claims_fail"
    if exit_code == 2:
        return "integrity_fail"
    return "malformed"


def run_pilot_closeout(
    bundle_path: Path,
    *,
    repo: str | None = None,
    dry_run: bool = False,
    json_output: Path | None = None,
    log_path: Path | None = None,
) -> dict[str, Any]:
    """Execute the closeout pipeline. Returns closeout row dict.

    Raises PilotError on integrity/structural failures.
    """
    bundle_path = bundle_path.resolve()
    if not bundle_path.is_dir():
        raise PilotError(f"Bundle path does not exist: {bundle_path}")

    # --- Extract metadata ---
    manifest = _load_json(bundle_path / "manifest.json")
    has_manifest = (bundle_path / "manifest.json").exists()

    bundle_id = _extract_bundle_id(bundle_path)
    before_score, after_score, delta_score = _extract_scores(bundle_path)
    verify_status_str, verify_exit_extracted = _extract_verify(bundle_path)
    receipt_count = _inspect_receipts(bundle_path).count

    # Determine pilot type
    if before_score is not None or after_score is not None:
        pilot_type = "score-delta"
    elif receipt_count > 0:
        pilot_type = "otel-bridge"
    else:
        pilot_type = "integrity-only"

    # Repo fallback
    if not repo:
        if manifest and isinstance(manifest.get("repo"), str) and manifest["repo"].strip():
            repo = manifest["repo"]
        else:
            repo = "unknown"

    commit = None
    if manifest and isinstance(manifest.get("commit"), str) and manifest["commit"].strip():
        commit = manifest["commit"]

    mode = None
    if manifest and isinstance(manifest.get("mode"), str):
        mode = manifest["mode"]

    # Assay version
    assay_version = "unknown"
    if manifest and isinstance(manifest.get("assay_version"), str):
        m = _SEMVER_RE.search(manifest["assay_version"])
        assay_version = m.group(0) if m else manifest["assay_version"]

    # --- Verify (profile-aware) ---
    verify_exit: int
    claim_codes: list[str] = []
    verify_warns: list[str] = []
    if has_manifest:
        verify_exit, verify_errors, verify_warns = verify_pilot_bundle(bundle_path, profile=pilot_type)
        if verify_exit in (2, 3):
            raise PilotError(
                f"Bundle verification failed (exit {verify_exit}): {', '.join(verify_errors)}"
            )
        if verify_exit == 1:
            claim_codes = verify_errors
    else:
        verify_exit = verify_exit_extracted if verify_exit_extracted is not None else 0

    # --- Self-test ---
    tamper_exit: int | None = None
    if has_manifest:
        st_code, _st_errors = _run_self_test(bundle_path)
        tamper_exit = st_code

    # --- Build row ---
    row: dict[str, Any] = {
        "repo": repo,
        "bundle_id": bundle_id,
        "pilot_type": pilot_type,
        "commit": commit,
        "mode": mode,
        "verify_exit": verify_exit,
        "verify_status": _verify_exit_to_status(verify_exit),
        "verify_claim_codes": claim_codes if claim_codes else None,
        "verify_claim_count": len(claim_codes) if claim_codes else 0,
        "verify_warn_codes": verify_warns if verify_warns else None,
        "verify_warn_count": len(verify_warns) if verify_warns else 0,
        "tamper_exit": tamper_exit,
        "score_before": before_score,
        "score_after": after_score,
        "score_delta": delta_score,
        "receipt_count": receipt_count,
        "assay_version": assay_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Write row as JSON for downstream consumers
    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        tmp = json_output.with_suffix(".tmp")
        tmp.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, json_output)

    # --- JSONL log ---
    if log_path and not dry_run:
        _upsert_jsonl(log_path, row)

    return row


def _upsert_jsonl(log_path: Path, row: dict[str, Any]) -> None:
    """Upsert a row into a JSONL file by bundle_id."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    # Upsert by bundle_id
    bundle_id = row.get("bundle_id", "")
    found = False
    for i, existing in enumerate(rows):
        if existing.get("bundle_id") == bundle_id:
            rows[i] = row
            found = True
            break
    if not found:
        rows.append(row)

    log_path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )
