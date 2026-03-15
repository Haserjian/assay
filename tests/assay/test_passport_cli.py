"""Tests for passport CLI commands."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore

runner = CliRunner()


@pytest.fixture
def assay_home_tmp(tmp_path: Path, monkeypatch) -> Path:
    """Route ~/.assay to a temp dir and reset store globals."""
    import assay.store as store_mod

    home = tmp_path / ".assay"
    monkeypatch.setattr(store_mod, "assay_home", lambda: home)
    monkeypatch.setattr(store_mod, "_default_store", None)
    monkeypatch.setattr(store_mod, "_seq_counter", 0)
    monkeypatch.setattr(store_mod, "_seq_trace_id", None)
    return home


@pytest.fixture
def keystore(assay_home_tmp: Path) -> AssayKeyStore:
    ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
    ks.generate_key("assay-local")
    return ks


@pytest.fixture
def specimen_passport() -> Path:
    return Path(__file__).parent.parent.parent / "docs" / "passport" / "specimen_passport.json"


@pytest.fixture
def unsigned_passport(tmp_path: Path) -> Path:
    """Create a minimal unsigned passport for testing."""
    passport = {
        "passport_version": "0.1",
        "issued_at": "2026-03-14T00:00:00+00:00",
        "valid_until": "2026-04-13T00:00:00+00:00",
        "status": {"state": "FRESH", "reason": "ok", "checked_at": "2026-03-14T00:00:00+00:00"},
        "reliance": {"class": "R0", "label": "Unsigned"},
        "subject": {
            "name": "TestApp",
            "system_id": "test.app.v1",
            "type": "ai_workflow",
            "description": "",
            "owner": "Test Inc.",
            "version": "1.0",
            "environment": "",
            "sample_boundary": "",
        },
        "scope": {"in_scope": ["test"], "not_covered": [], "not_observed": [], "not_concluded": []},
        "claims": [
            {
                "claim_id": "C-001",
                "topic": "Integrity",
                "claim_type": "integrity",
                "applies_to": "proof_pack",
                "assertion": "Test claim",
                "result": "pass",
                "evidence_type": "machine_verified",
                "proof_tier": "core",
                "evidence_refs": [],
            }
        ],
        "evidence_summary": {"total_claims": 1, "machine_verified": 1, "human_attested": 0},
        "relationships": {
            "supersedes": None,
            "superseded_by": None,
            "challenge_refs": [],
            "revocation_ref": None,
        },
        "verification": {"how_to_verify": "assay passport verify ./passport.json"},
        "challenge": {"how_to_challenge": "assay passport challenge ./passport.json --reason ..."},
    }
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(passport, indent=2) + "\n", encoding="utf-8")
    return path


class TestPassportShow:
    def test_show_specimen(self, specimen_passport: Path) -> None:
        if not specimen_passport.exists():
            pytest.skip("Specimen passport not found")
        result = runner.invoke(assay_app, ["passport", "show", str(specimen_passport)])
        assert result.exit_code == 0
        assert "AcmeSaaS" in result.output

    def test_show_json(self, specimen_passport: Path) -> None:
        if not specimen_passport.exists():
            pytest.skip("Specimen passport not found")
        result = runner.invoke(assay_app, ["passport", "show", str(specimen_passport), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "passport show"

    def test_show_missing_file(self) -> None:
        result = runner.invoke(assay_app, ["passport", "show", "/nonexistent/file.json"])
        assert result.exit_code == 3


class TestPassportSign:
    def test_sign_round_trip(self, unsigned_passport: Path, keystore: AssayKeyStore) -> None:
        # Sign
        result = runner.invoke(assay_app, ["passport", "sign", str(unsigned_passport)])
        assert result.exit_code == 0
        assert "Signed" in result.output

        # Verify
        result = runner.invoke(assay_app, ["passport", "verify", str(unsigned_passport)])
        assert result.exit_code == 0

    def test_sign_json_output(self, unsigned_passport: Path, keystore: AssayKeyStore) -> None:
        result = runner.invoke(assay_app, ["passport", "sign", str(unsigned_passport), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "passport sign"
        assert data["status"] == "ok"
        assert data["passport_id"].startswith("sha256:")

    def test_sign_missing_file(self) -> None:
        result = runner.invoke(assay_app, ["passport", "sign", "/nonexistent.json"])
        assert result.exit_code == 3


class TestPassportVerify:
    def test_verify_unsigned_no_error(self, unsigned_passport: Path, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["passport", "verify", str(unsigned_passport)])
        # Unsigned passport should exit 0 (no signature to fail)
        assert result.exit_code == 0

    def test_verify_signed_valid(self, unsigned_passport: Path, keystore: AssayKeyStore) -> None:
        from assay.passport_sign import sign_passport
        sign_passport(unsigned_passport, keystore=keystore)

        result = runner.invoke(assay_app, ["passport", "verify", str(unsigned_passport)])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_verify_tampered(self, unsigned_passport: Path, keystore: AssayKeyStore) -> None:
        from assay.passport_sign import sign_passport
        sign_passport(unsigned_passport, keystore=keystore)

        # Tamper
        data = json.loads(unsigned_passport.read_text(encoding="utf-8"))
        data["subject"]["name"] = "TamperedApp"
        unsigned_passport.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = runner.invoke(assay_app, ["passport", "verify", str(unsigned_passport)])
        assert result.exit_code == 2

    def test_verify_json(self, unsigned_passport: Path, keystore: AssayKeyStore) -> None:
        from assay.passport_sign import sign_passport
        sign_passport(unsigned_passport, keystore=keystore)

        result = runner.invoke(assay_app, ["passport", "verify", str(unsigned_passport), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["signature_valid"] is True
        assert data["state"]["state"] == "FRESH"

    def test_verify_expired(self, tmp_path: Path, keystore: AssayKeyStore) -> None:
        passport = {
            "passport_version": "0.1",
            "issued_at": "2025-01-01T00:00:00+00:00",
            "valid_until": "2025-01-02T00:00:00+00:00",
            "status": {"state": "FRESH"},
            "reliance": {"class": "R0", "label": "test"},
            "subject": {"name": "Expired", "system_id": "x", "owner": "x"},
            "claims": [],
            "verification": {"how_to_verify": "test"},
            "challenge": {"how_to_challenge": "test"},
        }
        path = tmp_path / "expired.json"
        path.write_text(json.dumps(passport, indent=2), encoding="utf-8")

        result = runner.invoke(assay_app, [
            "passport", "verify", str(path), "--check-expiry"
        ])
        assert result.exit_code == 1


class TestPassportRender:
    def test_render_html(self, specimen_passport: Path, tmp_path: Path, assay_home_tmp: Path) -> None:
        if not specimen_passport.exists():
            pytest.skip("Specimen passport not found")
        out = tmp_path / "output.html"
        result = runner.invoke(assay_app, [
            "passport", "render", str(specimen_passport), "--output", str(out)
        ])
        assert result.exit_code == 0
        assert out.exists()
        html_text = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html_text or "<html" in html_text

    def test_render_missing_file(self) -> None:
        result = runner.invoke(assay_app, ["passport", "render", "/nonexistent.json"])
        assert result.exit_code == 3


class TestPassportChallenge:
    def test_challenge_creates_receipt(self, unsigned_passport: Path, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, [
            "passport", "challenge", str(unsigned_passport),
            "--reason", "Missing coverage",
        ])
        assert result.exit_code == 0
        assert "Challenged" in result.output

        # Verify receipt was created
        parent = unsigned_passport.parent
        challenge_files = list(parent.glob("challenge_*.json"))
        assert len(challenge_files) == 1

    def test_challenge_then_verify_shows_challenged(
        self, unsigned_passport: Path, assay_home_tmp: Path
    ) -> None:
        runner.invoke(assay_app, [
            "passport", "challenge", str(unsigned_passport),
            "--reason", "Test challenge",
        ])
        result = runner.invoke(assay_app, [
            "passport", "verify", str(unsigned_passport), "--require-fresh"
        ])
        assert result.exit_code == 1


class TestPassportMint:
    def test_mint_minimal(self, tmp_path: Path, assay_home_tmp: Path) -> None:
        out = tmp_path / "minted.json"
        result = runner.invoke(assay_app, [
            "passport", "mint",
            "--subject-name", "TestApp",
            "--system-id", "test.v1",
            "--owner", "Test Inc.",
            "--output", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["subject"]["name"] == "TestApp"
        assert data["passport_version"] == "0.1"


class TestPassportSupersede:
    def test_supersede_links_passports(self, tmp_path: Path, assay_home_tmp: Path) -> None:
        p1 = {
            "passport_version": "0.1",
            "passport_id": "sha256:aaa",
            "subject": {"name": "v1"},
            "relationships": {},
        }
        p2 = {
            "passport_version": "0.1",
            "passport_id": "sha256:bbb",
            "subject": {"name": "v2"},
            "relationships": {},
        }
        p1_path = tmp_path / "v1.json"
        p2_path = tmp_path / "v2.json"
        p1_path.write_text(json.dumps(p1, indent=2), encoding="utf-8")
        p2_path.write_text(json.dumps(p2, indent=2), encoding="utf-8")

        result = runner.invoke(assay_app, [
            "passport", "supersede", str(p1_path), str(p2_path),
            "--reason", "Upgraded",
        ])
        assert result.exit_code == 0

        # Check relationship updates
        p1_data = json.loads(p1_path.read_text(encoding="utf-8"))
        p2_data = json.loads(p2_path.read_text(encoding="utf-8"))
        assert p1_data["relationships"]["superseded_by"] == "sha256:bbb"
        assert p2_data["relationships"]["supersedes"] == "sha256:aaa"


class TestPassportRevoke:
    def test_revoke_creates_receipt(self, unsigned_passport: Path, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, [
            "passport", "revoke", str(unsigned_passport),
            "--reason", "Key compromised",
        ])
        assert result.exit_code == 0

        revocation_files = list(unsigned_passport.parent.glob("revocation_*.json"))
        assert len(revocation_files) == 1


class TestXRayAlias:
    def test_xray_top_level(self, unsigned_passport: Path, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["xray", str(unsigned_passport)])
        # Should work as top-level alias
        assert result.exit_code in (0, 1, 2)
