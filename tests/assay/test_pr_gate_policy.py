"""Tests for the Assay PR Gate policy evaluator."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.pr_gate.policy import (
    compute_policy_sha256,
    evaluate_policy,
    load_policy,
)

runner = CliRunner()

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "docs" / "examples" / "pr-gate-v0" / "assay-policy.yml"


def _policy() -> Dict[str, Any]:
    return load_policy(POLICY_PATH)


def _evidence(
    *,
    changed_files: Optional[List[str]] = None,
    observed_checks: Optional[List[Dict[str, Any]]] = None,
    integrity_status: str = "PASS",
    signer_trusted: bool = True,
) -> Dict[str, Any]:
    return {
        "schema_version": "assay.pr_gate.evidence.v0.1",
        "subject": {
            "repo": "Haserjian/assay",
            "pr_number": 123,
            "base_sha": "base",
            "head_sha": "head",
            "diff_sha256": "sha256:" + "a" * 64,
        },
        "integrity_status": integrity_status,
        "signer_trusted": signer_trusted,
        "changed_files": [
            {
                "path": path,
                "status": "modified",
                "sha256_after": "sha256:" + "b" * 64,
            }
            for path in (changed_files or ["src/app.py"])
        ],
        "observed_checks": observed_checks
        if observed_checks is not None
        else [
            {
                "name": "tests",
                "provider": "github_checks",
                "head_sha": "head",
                "conclusion": "success",
                "observed_at": "2026-05-08T12:00:00Z",
            }
        ],
        "policy": {
            "profile": "coding_pr_v0",
            "policy_sha256": "sha256:" + "c" * 64,
        },
    }


class TestPrGatePolicyEvaluator:
    def test_clean_pr_passes(self) -> None:
        decision = evaluate_policy(_evidence(), _policy())

        assert decision == {
            "overall_decision": "PASS",
            "recommended_action": "proceed",
            "reasons": [],
            "check_observations": [
                {
                    "name": "tests",
                    "status": "OBSERVED_PASS",
                    "head_sha": "head",
                    "conclusion": "success",
                    "observed_at": "2026-05-08T12:00:00Z",
                }
            ],
            "channels": {
                "integrity": "PASS",
                "claim": "PASS",
                "replay": "NOT_RUN",
                "trust_policy": "PASS",
            },
        }

    def test_risk_path_touched_needs_review(self) -> None:
        decision = evaluate_policy(
            _evidence(changed_files=["auth/session.py"]),
            _policy(),
        )

        assert decision["overall_decision"] == "NEEDS_REVIEW"
        assert decision["recommended_action"] == "require_human_approval"
        assert decision["channels"]["claim"] == "PASS"
        assert decision["channels"]["trust_policy"] == "NEEDS_REVIEW"
        assert decision["check_observations"] == [
            {
                "name": "tests",
                "status": "OBSERVED_PASS",
                "head_sha": "head",
                "conclusion": "success",
                "observed_at": "2026-05-08T12:00:00Z",
            }
        ]
        assert decision["reasons"] == [
            {
                "rule": "risk_path_touched",
                "path": "auth/session.py",
                "matched_pattern": "auth/**",
            }
        ]

    def test_required_check_missing_needs_review(self) -> None:
        decision = evaluate_policy(
            _evidence(observed_checks=[]),
            _policy(),
        )

        assert decision["overall_decision"] == "NEEDS_REVIEW"
        assert decision["recommended_action"] == "rerun_required_check"
        assert decision["channels"]["claim"] == "NOT_EVALUATED"
        assert decision["channels"]["trust_policy"] == "NEEDS_REVIEW"
        assert decision["reasons"] == [
            {
                "rule": "required_check_missing",
                "check": "tests",
                "observation_status": "NOT_OBSERVED_YET",
                "head_sha": "head",
            }
        ]
        assert decision["check_observations"] == [
            {
                "name": "tests",
                "status": "NOT_OBSERVED_YET",
                "head_sha": "head",
            }
        ]

    def test_required_check_failed_blocks(self) -> None:
        decision = evaluate_policy(
            _evidence(
                observed_checks=[
                    {
                        "name": "tests",
                        "provider": "github_checks",
                        "head_sha": "head",
                        "conclusion": "failure",
                        "observed_at": "2026-05-08T12:00:00Z",
                    }
                ]
            ),
            _policy(),
        )

        assert decision["overall_decision"] == "BLOCK"
        assert decision["recommended_action"] == "block_required_check_failed"
        assert decision["channels"]["claim"] == "FAIL"
        assert decision["channels"]["trust_policy"] == "BLOCK"
        assert decision["reasons"] == [
            {
                "rule": "required_check_failed",
                "check": "tests",
                "conclusion": "failure",
                "observation_status": "OBSERVED_FAIL",
                "head_sha": "head",
            }
        ]
        assert decision["check_observations"] == [
            {
                "name": "tests",
                "status": "OBSERVED_FAIL",
                "head_sha": "head",
                "conclusion": "failure",
                "observed_at": "2026-05-08T12:00:00Z",
            }
        ]

    def test_integrity_failed_blocks_before_other_rules(self) -> None:
        decision = evaluate_policy(
            _evidence(
                changed_files=["auth/session.py"],
                integrity_status="FAIL",
            ),
            _policy(),
        )

        assert decision["overall_decision"] == "BLOCK"
        assert decision["recommended_action"] == "block_integrity_failed"
        assert decision["channels"]["integrity"] == "FAIL"
        assert decision["channels"]["trust_policy"] == "BLOCK"
        assert decision["reasons"][0] == {
            "rule": "integrity_failed",
            "integrity": "FAIL",
        }

    def test_untrusted_signer_blocks(self) -> None:
        decision = evaluate_policy(
            _evidence(signer_trusted=False),
            _policy(),
        )

        assert decision["overall_decision"] == "BLOCK"
        assert decision["recommended_action"] == "block_untrusted_signer"
        assert decision["channels"]["trust_policy"] == "BLOCK"
        assert decision["reasons"] == [{"rule": "untrusted_signer"}]

    def test_check_without_matching_head_sha_does_not_support_claim(self) -> None:
        decision = evaluate_policy(
            _evidence(
                observed_checks=[
                    {
                        "name": "tests",
                        "provider": "github_checks",
                        "conclusion": "success",
                        "observed_at": "2026-05-08T12:00:00Z",
                    },
                    {
                        "name": "tests",
                        "provider": "github_checks",
                        "head_sha": "other",
                        "conclusion": "success",
                        "observed_at": "2026-05-08T12:00:00Z",
                    },
                ]
            ),
            _policy(),
        )

        assert decision["overall_decision"] == "NEEDS_REVIEW"
        assert decision["recommended_action"] == "rerun_required_check"
        assert decision["channels"]["claim"] == "NOT_EVALUATED"
        assert decision["reasons"] == [
            {
                "rule": "required_check_missing",
                "check": "tests",
                "observation_status": "NOT_OBSERVED_YET",
                "head_sha": "head",
            }
        ]
        assert decision["check_observations"] == [
            {
                "name": "tests",
                "status": "NOT_OBSERVED_YET",
                "head_sha": "head",
            }
        ]

    def test_check_without_conclusion_does_not_fail_claim(self) -> None:
        decision = evaluate_policy(
            _evidence(
                observed_checks=[
                    {
                        "name": "tests",
                        "provider": "github_checks",
                        "head_sha": "head",
                        "observed_at": "2026-05-08T12:00:00Z",
                    }
                ]
            ),
            _policy(),
        )

        assert decision["overall_decision"] == "NEEDS_REVIEW"
        assert decision["recommended_action"] == "rerun_required_check"
        assert decision["channels"]["claim"] == "NOT_EVALUATED"
        assert decision["reasons"] == [
            {
                "rule": "required_check_missing",
                "check": "tests",
                "observation_status": "OBSERVED_PENDING",
                "head_sha": "head",
            }
        ]
        assert decision["check_observations"] == [
            {
                "name": "tests",
                "status": "OBSERVED_PENDING",
                "head_sha": "head",
                "observed_at": "2026-05-08T12:00:00Z",
            }
        ]

    def test_mismatched_check_name_is_reported_without_overclaiming(self) -> None:
        decision = evaluate_policy(
            _evidence(
                observed_checks=[
                    {
                        "name": "Prepare",
                        "provider": "github_checks",
                        "head_sha": "head",
                        "conclusion": "success",
                        "observed_at": "2026-05-08T12:00:00Z",
                    }
                ]
            ),
            _policy(),
        )

        assert decision["overall_decision"] == "NEEDS_REVIEW"
        assert decision["channels"]["claim"] == "NOT_EVALUATED"
        assert decision["reasons"] == [
            {
                "rule": "required_check_missing",
                "check": "tests",
                "observation_status": "NAME_MISMATCH_POSSIBLE",
                "head_sha": "head",
                "observed_check_names": ["Prepare"],
            }
        ]
        assert decision["check_observations"] == [
            {
                "name": "tests",
                "status": "NAME_MISMATCH_POSSIBLE",
                "head_sha": "head",
                "observed_check_names": ["Prepare"],
            }
        ]

    def test_multiple_reasons_are_deterministically_ordered(self) -> None:
        policy = _policy()
        policy["required_checks"] = ["tests", "lint"]

        decision = evaluate_policy(
            _evidence(
                changed_files=["auth/session.py", ".github/workflows/ci.yml"],
                signer_trusted=False,
                observed_checks=[
                    {
                        "name": "tests",
                        "provider": "github_checks",
                        "head_sha": "head",
                        "conclusion": "failure",
                        "observed_at": "2026-05-08T12:00:00Z",
                    }
                ],
            ),
            policy,
        )

        assert decision["overall_decision"] == "BLOCK"
        assert decision["recommended_action"] == "block_untrusted_signer"
        assert [reason["rule"] for reason in decision["reasons"]] == [
            "untrusted_signer",
            "required_check_failed",
            "required_check_missing",
            "risk_path_touched",
            "risk_path_touched",
        ]
        assert decision["reasons"][3]["path"] == ".github/workflows/ci.yml"
        assert decision["reasons"][4]["path"] == "auth/session.py"

    def test_policy_hash_uses_jcs_not_yaml_bytes(self) -> None:
        policy_a = {"profile": "coding_pr_v0", "risk_paths": ["auth/**"]}
        policy_b = {"risk_paths": ["auth/**"], "profile": "coding_pr_v0"}

        assert compute_policy_sha256(policy_a) == compute_policy_sha256(policy_b)


class TestPrGatePolicyCLI:
    def test_evaluate_writes_decision_json(self, tmp_path: Path) -> None:
        evidence_path = tmp_path / "evidence.json"
        out_path = tmp_path / "decision.json"
        evidence_path.write_text(json.dumps(_evidence(changed_files=["auth/session.py"])))

        result = runner.invoke(
            assay_app,
            [
                "pr-gate",
                "evaluate",
                "--evidence",
                str(evidence_path),
                "--policy",
                str(POLICY_PATH),
                "--out",
                str(out_path),
            ],
        )

        assert result.exit_code == 0, result.output
        decision = json.loads(out_path.read_text(encoding="utf-8"))
        assert decision["overall_decision"] == "NEEDS_REVIEW"
        assert decision["recommended_action"] == "require_human_approval"
