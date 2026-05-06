from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "assay-receipt.yml"
SCRIPT_PATH = ROOT / "scripts" / "assay_emit_receipt.py"


def _workflow_text() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _load_receipt_script():
    spec = importlib.util.spec_from_file_location(
        "assay_emit_receipt",
        SCRIPT_PATH,
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _extract_block(text: str, marker: str) -> str:
    index = text.index(marker)
    next_step = text.find("\n      - name:", index + 1)
    if next_step == -1:
        return text[index:]
    return text[index:next_step]


def test_receipt_workflow_uses_script_contract_defaults() -> None:
    workflow = _workflow_text()
    script = _load_receipt_script()

    assert f'ASSAY_PYTEST_COMMAND: "{script.DEFAULT_PYTEST_COMMAND}"' in workflow
    assert f'ASSAY_PROOF_TIER: "{script.DEFAULT_PROOF_TIER}"' in workflow


def test_receipt_workflow_emits_receipt_from_expected_pytest_artifacts() -> None:
    workflow = _workflow_text()
    block = _extract_block(workflow, "Emit Assay receipt")

    assert "python scripts/assay_emit_receipt.py" in block
    assert '--pytest-exit-code "$(cat pytest-exit-code.txt)"' in block
    assert "--out receipt.json" in block
    for artifact in ("results.xml", "pytest.log", "pytest-exit-code.txt"):
        assert f"--artifact {artifact}" in block

    assert 'echo "ok" > receipt-status.txt' in block
    assert 'echo "failed" > receipt-status.txt' in block


def test_receipt_workflow_signs_and_verifies_receipt_with_cosign() -> None:
    workflow = _workflow_text()

    assert "sigstore/cosign-installer@v4.0.0" in workflow

    sign_block = _extract_block(workflow, "Sign receipt with GitHub OIDC")
    assert "cosign sign-blob" in sign_block
    assert "--bundle receipt.json.sigstore.json" in sign_block
    assert "\n            receipt.json\n" in sign_block
    assert 'echo "ok" > signature-status.txt' in sign_block
    assert 'echo "failed" > signature-status.txt' in sign_block

    verify_block = _extract_block(workflow, "Verify receipt signature")
    assert 'CERT_ID="https://github.com/${GITHUB_WORKFLOW_REF}"' in verify_block
    assert "cosign verify-blob receipt.json" in verify_block
    assert "--bundle receipt.json.sigstore.json" in verify_block
    assert '--certificate-identity "$CERT_ID"' in verify_block
    assert (
        '--certificate-oidc-issuer "https://token.actions.githubusercontent.com"'
        in verify_block
    )
    assert 'echo "ok" > verification-status.txt' in verify_block
    assert 'echo "failed" > verification-status.txt' in verify_block


def test_receipt_workflow_uploads_complete_evidence_pack() -> None:
    workflow = _workflow_text()
    block = _extract_block(workflow, "Upload evidence pack")

    assert "actions/upload-artifact@v4" in block
    assert "name: assay-evidence" in block
    assert "if-no-files-found: warn" in block
    for artifact in (
        "receipt.json",
        "receipt.json.sigstore.json",
        "results.xml",
        "pytest.log",
        "pytest-exit-code.txt",
        "receipt-status.txt",
        "signature-status.txt",
        "verification-status.txt",
    ):
        assert artifact in block


def test_receipt_workflow_enforces_pipeline_status_and_pytest_exit() -> None:
    workflow = _workflow_text()
    block = _extract_block(workflow, "Enforce evidence pipeline and pytest result")

    for status_file in (
        "receipt-status.txt",
        "signature-status.txt",
        "verification-status.txt",
        "upload-status.txt",
    ):
        assert f"require_status {status_file} ok" in block

    for artifact in (
        "receipt.json",
        "receipt.json.sigstore.json",
        "results.xml",
        "pytest.log",
        "pytest-exit-code.txt",
    ):
        assert f"test -s {artifact}" in block

    assert 'exit "$(cat pytest-exit-code.txt)"' in block
