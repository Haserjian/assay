from __future__ import annotations

import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app

runner = CliRunner()


def test_claim_gate_diff_cli_blocks_unsupported_claim_escalation(
    tmp_path: Path,
) -> None:
    _run(["git", "init"], tmp_path)
    _run(["git", "checkout", "-b", "main"], tmp_path)
    _run(["git", "config", "user.email", "test@example.com"], tmp_path)
    _run(["git", "config", "user.name", "Assay Test"], tmp_path)

    (tmp_path / "README.md").write_text(
        "# Demo Agent\n\n"
        "This experimental prototype may help evaluate agent workflows.\n",
        encoding="utf-8",
    )
    (tmp_path / "assay.claims.yml").write_text(
        "schema_version: assay.claim_policy.v0\n"
        "default_verdict: NEEDS_REVIEW\n"
        "blocked_transitions:\n"
        "  prototype_to_production:\n"
        "    severity: high\n"
        "    requires:\n"
        "      - production_deployment_receipt\n"
        "  possible_to_guaranteed:\n"
        "    severity: high\n"
        "    requires:\n"
        "      - direct_evidence\n",
        encoding="utf-8",
    )
    _run(["git", "add", "README.md", "assay.claims.yml"], tmp_path)
    _run(["git", "commit", "-m", "initial"], tmp_path)

    (tmp_path / "README.md").write_text(
        "# Demo Agent\n\n"
        "This production-ready framework guarantees safe autonomous agent execution.\n",
        encoding="utf-8",
    )
    _run(["git", "add", "README.md"], tmp_path)
    _run(["git", "commit", "-m", "claim escalation"], tmp_path)

    result = runner.invoke(
        assay_app,
        [
            "claim-gate",
            "diff",
            "--repo",
            str(tmp_path),
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--policy",
            "assay.claims.yml",
            "--out",
            "claim_gate_report.json",
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["verdict"] == "BLOCK"
    assert payload["summary"]["blocking_transitions"] == 2
    assert (tmp_path / "claim_gate_report.json").exists()


def test_claim_gate_diff_cli_does_not_accept_spoofed_evidence_filename(
    tmp_path: Path,
) -> None:
    _init_repo(tmp_path)

    (tmp_path / "README.md").write_text(
        "This may help evaluate agent workflows.\n",
        encoding="utf-8",
    )
    (tmp_path / "assay.claims.yml").write_text(
        "schema_version: assay.claim_policy.v0\n"
        "default_verdict: NEEDS_REVIEW\n"
        "blocked_transitions:\n"
        "  possible_to_guaranteed:\n"
        "    severity: high\n"
        "    requires:\n"
        "      - direct_evidence\n"
        "evidence_paths:\n"
        "  direct_evidence:\n"
        "    - evidence/direct_evidence.json\n",
        encoding="utf-8",
    )
    _run(["git", "add", "README.md", "assay.claims.yml"], tmp_path)
    _run(["git", "commit", "-m", "initial"], tmp_path)

    (tmp_path / "README.md").write_text(
        "This guarantees safe autonomous agent execution.\n",
        encoding="utf-8",
    )
    (tmp_path / "notes_direct_evidence_placeholder.txt").write_text(
        "not configured evidence\n",
        encoding="utf-8",
    )
    _run(
        [
            "git",
            "add",
            "README.md",
            "notes_direct_evidence_placeholder.txt",
        ],
        tmp_path,
    )
    _run(["git", "commit", "-m", "spoofed evidence filename"], tmp_path)

    result = runner.invoke(
        assay_app,
        [
            "claim-gate",
            "diff",
            "--repo",
            str(tmp_path),
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--policy",
            "assay.claims.yml",
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["verdict"] == "BLOCK"
    assert payload["transitions"][0]["evidence_found"] == []


def test_claim_gate_diff_cli_detects_rename_plus_edit_transition(
    tmp_path: Path,
) -> None:
    _init_repo(tmp_path)

    (tmp_path / "old.md").write_text(
        "This prototype may help evaluate agent workflows.\n",
        encoding="utf-8",
    )
    (tmp_path / "assay.claims.yml").write_text(
        "schema_version: assay.claim_policy.v0\n"
        "default_verdict: NEEDS_REVIEW\n"
        "blocked_transitions:\n"
        "  prototype_to_production:\n"
        "    severity: high\n"
        "    requires:\n"
        "      - production_deployment_receipt\n",
        encoding="utf-8",
    )
    _run(["git", "add", "old.md", "assay.claims.yml"], tmp_path)
    _run(["git", "commit", "-m", "initial"], tmp_path)

    _run(["git", "mv", "old.md", "README.md"], tmp_path)
    (tmp_path / "README.md").write_text(
        "This production-ready framework may help evaluate agent workflows.\n",
        encoding="utf-8",
    )
    _run(["git", "add", "README.md"], tmp_path)
    _run(["git", "commit", "-m", "rename and escalate"], tmp_path)

    result = runner.invoke(
        assay_app,
        [
            "claim-gate",
            "diff",
            "--repo",
            str(tmp_path),
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--policy",
            "assay.claims.yml",
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["verdict"] == "BLOCK"
    assert {item["transition_class"] for item in payload["transitions"]} == {
        "prototype_to_production",
    }
    assert payload["transitions"][0]["file"] == "README.md"
    assert payload["transitions"][0]["before_span"]["text"] == (
        "This prototype may help evaluate agent workflows."
    )


def test_claim_gate_diff_cli_uses_repo_relative_policy_path_in_json(
    tmp_path: Path,
) -> None:
    _init_repo(tmp_path)

    (tmp_path / "README.md").write_text(
        "This may help evaluate agent workflows.\n",
        encoding="utf-8",
    )
    (tmp_path / "assay.claims.yml").write_text(
        "schema_version: assay.claim_policy.v0\n"
        "default_verdict: NEEDS_REVIEW\n"
        "blocked_transitions:\n"
        "  possible_to_guaranteed:\n"
        "    severity: high\n"
        "    requires:\n"
        "      - direct_evidence\n",
        encoding="utf-8",
    )
    _run(["git", "add", "README.md", "assay.claims.yml"], tmp_path)
    _run(["git", "commit", "-m", "initial"], tmp_path)

    (tmp_path / "README.md").write_text(
        "This guarantees safe autonomous agent execution.\n",
        encoding="utf-8",
    )
    _run(["git", "add", "README.md"], tmp_path)
    _run(["git", "commit", "-m", "claim escalation"], tmp_path)

    result = runner.invoke(
        assay_app,
        [
            "claim-gate",
            "diff",
            "--repo",
            str(tmp_path),
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--policy",
            str(tmp_path / "assay.claims.yml"),
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["subject"]["policy"] == "assay.claims.yml"


def _init_repo(cwd: Path) -> None:
    _run(["git", "init"], cwd)
    _run(["git", "checkout", "-b", "main"], cwd)
    _run(["git", "config", "user.email", "test@example.com"], cwd)
    _run(["git", "config", "user.name", "Assay Test"], cwd)


def _run(args: list[str], cwd: Path) -> None:
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
