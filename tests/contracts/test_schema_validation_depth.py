"""
Schema-validation-depth parity tests.

These fixtures are manifest-only probes that exercise the schema gate before
any pack file I/O. They are shared decision-pressure vectors for the next
chapter of manifest/attestation parity work.

Parity rule:
- exact_parity: TS rejects at the same structural boundary with the same
  effective rejection class
- equivalent_structural_parity: TS rejects at an explicitly accepted canonical
  structural boundary
- mismatch: anything else, including a later rejection for a different reason
"""

from __future__ import annotations

import json
from pathlib import Path

from assay.integrity import E_MANIFEST_TAMPER, verify_pack_manifest

VECTORS_DIR = Path(__file__).resolve().parent / "vectors" / "pack-schema-depth"
FIXTURE_FILE = VECTORS_DIR / "schema-depth-fixtures.json"
CANONICAL_FAILURE_STAGE = "validate_schema"
ACCEPTED_PARITY_CATEGORIES = {"exact_parity", "equivalent_structural_parity"}


class TestSchemaValidationDepthParity:
    @classmethod
    def _fixtures(cls) -> dict:
        return json.loads(FIXTURE_FILE.read_text(encoding="utf-8"))

    @staticmethod
    def _first_failed_stage(result) -> str | None:
        for stage in result.stages:
            if stage.status == "fail":
                return stage.stage
        return None

    @classmethod
    def _classify_parity(cls, result) -> str:
        if result.passed:
            return "mismatch"

        first_fail_stage = cls._first_failed_stage(result)
        if first_fail_stage == CANONICAL_FAILURE_STAGE and any(
            error.code == E_MANIFEST_TAMPER for error in result.errors
        ):
            return "exact_parity"

        if first_fail_stage in {"validate_schema", "validate_shape"} and any(
            error.code == E_MANIFEST_TAMPER for error in result.errors
        ):
            return "equivalent_structural_parity"

        return "mismatch"

    def test_fixture_count(self):
        data = self._fixtures()
        assert len(data["fixtures"]) == 7

    def test_python_schema_gate_rejects_all_fixtures(self):
        data = self._fixtures()
        target = data["acceptance_target"]

        for fixture in data["fixtures"]:
            pack_dir = VECTORS_DIR / fixture["name"]
            manifest = json.loads((pack_dir / "pack_manifest.json").read_text(encoding="utf-8"))

            result = verify_pack_manifest(manifest, pack_dir, keystore=None)
            parity_category = self._classify_parity(result)

            assert parity_category in ACCEPTED_PARITY_CATEGORIES, (
                f"[{fixture['name']}] parity={parity_category}, "
                f"stage={self._first_failed_stage(result)}, "
                f"errors={[(error.code, error.field) for error in result.errors]}"
            )
            assert not result.passed, f"[{fixture['name']}] expected fail, got pass"
            assert any(
                error.code == target["expected_error_code"] for error in result.errors
            ), (
                f"[{fixture['name']}] expected {target['expected_error_code']}, "
                f"got: {[(error.code, error.field) for error in result.errors]}"
            )

            schema_stage = next(
                (stage for stage in result.stages if stage.stage == target["expected_fail_stage"]),
                None,
            )
            assert schema_stage is not None, (
                f"[{fixture['name']}] missing {target['expected_fail_stage']} stage: "
                f"{[(stage.stage, stage.status) for stage in result.stages]}"
            )
            assert schema_stage.status == "fail", (
                f"[{fixture['name']}] expected {target['expected_fail_stage']} to fail, "
                f"got {schema_stage.status}"
            )
            assert result.receipt_count == 0
            assert result.head_hash is None
            assert len(result.stages) == 1
