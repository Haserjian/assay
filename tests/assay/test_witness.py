"""Tests for witness bundle generation and verification.

Covers:
  - Bundle schema structure
  - D12 invariant check
  - Pack root mismatch detection
  - Schema version check
  - Token verification (mocked openssl)
  - Missing token/cert detection
  - Rekor not-yet-implemented path
  - CLI commands (witness, verify-witness)
  - --require-witness in verify-pack
  - Round-trip: generate -> verify (offline, mocked)
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.witness import (
    SCHEMA_VERSION,
    WitnessError,
    request_rfc3161_witness,
    verify_witness_bundle,
    verify_witness_from_pack,
    _read_pack_root,
)

runner = CliRunner()

FAKE_PACK_ROOT = "a" * 64
FAKE_ATT_SHA = "a" * 64  # D12: same as pack_root


@pytest.fixture
def keystore(tmp_path):
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("test")
    return ks


@pytest.fixture
def pack_dir(keystore, tmp_path):
    """Build a minimal pack and return its directory."""
    pp = ProofPack(run_id="witness-test", entries=[], signer_id="test")
    return pp.build(tmp_path / "pack", keystore=keystore)


@pytest.fixture
def pack_root(pack_dir):
    """Return pack_root_sha256 from the test pack."""
    return _read_pack_root(pack_dir)


def _make_bundle(
    pack_root: str,
    attestation_sha: str = None,
    schema_version: str = SCHEMA_VERSION,
    witness_type: str = "rfc3161",
    query_b64: str = "dGVzdC1xdWVyeQ==",  # "test-query"
    token_b64: str = "dGVzdC10b2tlbg==",  # "test-token"
    ca_cert_b64: str = "dGVzdC1jYQ==",      # "test-ca"
    tsa_cert_b64: str = "dGVzdC10c2E=",     # "test-tsa"
    **overrides,
) -> dict:
    """Build a minimal witness bundle dict for testing."""
    bundle = {
        "schema_version": schema_version,
        "witness_type": witness_type,
        "pack_root_sha256": pack_root,
        "attestation_sha256": attestation_sha or pack_root,
        "tsa_url": "https://freetsa.org/tsr",
        "query_b64": query_b64,
        "token_b64": token_b64,
        "ca_cert_b64": ca_cert_b64,
        "tsa_cert_b64": tsa_cert_b64,
        "nonce": "deadbeef" * 4,
        "gen_time": "2026-03-04T12:00:00+00:00",
        "issued_at": "2026-03-04T12:00:01+00:00",
        "verified_at": None,
    }
    bundle.update(overrides)
    return bundle


class TestVerifyWitnessBundle:
    def test_verify_uses_queryfile_when_query_present(self, pack_root):
        """When query_b64 is present, verify should use -queryfile path."""
        bundle = _make_bundle(pack_root)
        seen: list[list[str]] = []

        def mock_run(cmd, **kwargs):
            seen.append(cmd)
            mock = MagicMock()
            mock.returncode = 0
            mock.stderr = b""
            return mock

        with patch("assay.witness.subprocess.run", side_effect=mock_run):
            result = verify_witness_bundle(bundle, pack_root)

        assert result.passed
        verify_cmds = [cmd for cmd in seen if "ts" in cmd and "-verify" in cmd]
        assert verify_cmds, "expected openssl ts -verify to be called"
        verify_cmd = verify_cmds[-1]
        assert "-queryfile" in verify_cmd
        assert "-digest" not in verify_cmd

    def test_verify_uses_digest_when_query_missing(self, pack_root):
        """Legacy bundles without query_b64 should still verify via -digest."""
        bundle = _make_bundle(pack_root, query_b64="")
        seen: list[list[str]] = []

        def mock_run(cmd, **kwargs):
            seen.append(cmd)
            mock = MagicMock()
            mock.returncode = 0
            mock.stderr = b""
            return mock

        with patch("assay.witness.subprocess.run", side_effect=mock_run):
            result = verify_witness_bundle(bundle, pack_root)

        assert result.passed
        verify_cmds = [cmd for cmd in seen if "ts" in cmd and "-verify" in cmd]
        assert verify_cmds, "expected openssl ts -verify to be called"
        verify_cmd = verify_cmds[-1]
        assert "-digest" in verify_cmd
        assert "-queryfile" not in verify_cmd

    def test_valid_bundle_with_passing_openssl(self, pack_dir, pack_root):
        """Valid bundle with openssl verification succeeding."""
        bundle = _make_bundle(pack_root)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = verify_witness_bundle(bundle, pack_root)

        assert result.passed
        assert result.errors == []
        assert result.gen_time == "2026-03-04T12:00:00+00:00"

    def test_d12_invariant_violation(self, pack_root):
        """attestation_sha256 != pack_root_sha256 should fail."""
        bundle = _make_bundle(pack_root, attestation_sha="b" * 64)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = verify_witness_bundle(bundle, pack_root)

        assert not result.passed
        assert any("D12" in e for e in result.errors)

    def test_pack_root_mismatch(self, pack_root):
        """Bundle references different pack than expected."""
        bundle = _make_bundle("c" * 64)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = verify_witness_bundle(bundle, pack_root)

        assert not result.passed
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_wrong_schema_version(self, pack_root):
        """Unknown schema version should fail."""
        bundle = _make_bundle(pack_root, schema_version="99.0.0")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = verify_witness_bundle(bundle, pack_root)

        assert not result.passed
        assert any("schema_version" in e.lower() for e in result.errors)

    def test_missing_token(self, pack_root):
        """Missing token_b64 should fail."""
        bundle = _make_bundle(pack_root, token_b64="")
        result = verify_witness_bundle(bundle, pack_root)
        assert not result.passed
        assert any("token_b64" in e.lower() for e in result.errors)

    def test_missing_certs(self, pack_root):
        """Missing ca_cert_b64 or tsa_cert_b64 should fail."""
        bundle = _make_bundle(pack_root, ca_cert_b64="", tsa_cert_b64="")
        result = verify_witness_bundle(bundle, pack_root)
        assert not result.passed
        assert any("ca_cert_b64" in e.lower() or "tsa_cert_b64" in e.lower() for e in result.errors)

    def test_openssl_verification_failure(self, pack_root):
        """openssl ts -verify returning non-zero should fail."""
        bundle = _make_bundle(pack_root)

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"Verification: FAILED"

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = verify_witness_bundle(bundle, pack_root)

        assert not result.passed
        assert any("verification failed" in e.lower() for e in result.errors)

    def test_unknown_witness_type(self, pack_root):
        """Unknown witness type should fail."""
        bundle = _make_bundle(pack_root, witness_type="unknown")
        result = verify_witness_bundle(bundle, pack_root)
        assert not result.passed
        assert any("unknown" in e.lower() for e in result.errors)

    def test_rekor_not_implemented(self, pack_root):
        """Rekor type should report not-yet-implemented."""
        bundle = _make_bundle(pack_root, witness_type="rekor")
        result = verify_witness_bundle(bundle, pack_root)
        assert not result.passed
        assert any("not yet implemented" in e.lower() for e in result.errors)


class TestVerifyWitnessFromPack:
    def test_missing_bundle_file(self, pack_dir, pack_root):
        """Missing witness_bundle.json should fail."""
        result = verify_witness_from_pack(pack_dir)
        assert not result.passed
        assert any("not found" in e.lower() for e in result.errors)

    def test_with_bundle_on_disk(self, pack_dir, pack_root):
        """Bundle on disk with passing openssl should verify."""
        bundle = _make_bundle(pack_root)
        bundle_path = pack_dir / "witness_bundle.json"
        bundle_path.write_text(json.dumps(bundle, indent=2) + "\n")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = verify_witness_from_pack(pack_dir)

        assert result.passed

    def test_explicit_bundle_path(self, pack_dir, pack_root, tmp_path):
        """Explicit bundle path should be used instead of default."""
        bundle = _make_bundle(pack_root)
        custom_path = tmp_path / "custom_witness.json"
        custom_path.write_text(json.dumps(bundle, indent=2) + "\n")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = verify_witness_from_pack(pack_dir, bundle_path=custom_path)

        assert result.passed

    def test_invalid_bundle_json(self, pack_dir):
        """Malformed witness bundle JSON should fail cleanly."""
        bundle_path = pack_dir / "witness_bundle.json"
        bundle_path.write_text("{not-json\n")
        result = verify_witness_from_pack(pack_dir)
        assert not result.passed
        assert any("invalid witness bundle json" in e.lower() for e in result.errors)


class TestGenerateWitnessBundle:
    """Test generate_witness_bundle with mocked network + openssl."""

    def test_generate_writes_file(self, pack_dir, pack_root):
        """generate_witness_bundle should write witness_bundle.json."""
        from assay.witness import generate_witness_bundle

        fake_token = b"\x30\x03\x02\x01\x00"  # minimal DER
        fake_ca = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
        fake_tsa = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"

        # Mock openssl ts -query
        mock_query = MagicMock()
        mock_query.returncode = 0
        mock_query.stderr = b""

        # Mock openssl ts -reply (for gen_time extraction)
        mock_reply = MagicMock()
        mock_reply.returncode = 1  # fail is fine, gen_time will be None
        mock_reply.stderr = b""
        mock_reply.stdout = b""

        # Mock for nonce extraction from query text
        mock_query_text = MagicMock()
        mock_query_text.returncode = 0
        mock_query_text.stdout = b"Nonce: 0x44C02FF2BD956A61\n"
        mock_query_text.stderr = b""

        def mock_run(cmd, **kwargs):
            if "ts" in cmd and "-query" in cmd and "-text" in cmd:
                # openssl ts -query -in ... -text (nonce extraction)
                return mock_query_text
            if "ts" in cmd and "-query" in cmd:
                # Write a fake query file
                out_idx = cmd.index("-out")
                Path(cmd[out_idx + 1]).write_bytes(b"fake-query")
                return mock_query
            if "ts" in cmd and "-reply" in cmd:
                return mock_reply
            return mock_query

        def mock_urlopen(req, **kwargs):
            resp = MagicMock()
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            if "tsr" in url:
                resp.read.return_value = fake_token
            elif "cacert" in url:
                resp.read.return_value = fake_ca
            elif "tsa.crt" in url:
                resp.read.return_value = fake_tsa
            else:
                resp.read.return_value = fake_token
            return resp

        with patch("assay.witness.subprocess.run", side_effect=mock_run), \
             patch("assay.witness.urlopen", side_effect=mock_urlopen):
            bundle = generate_witness_bundle(pack_dir)

        assert (pack_dir / "witness_bundle.json").exists()
        assert bundle["witness_type"] == "rfc3161"
        assert bundle["pack_root_sha256"] == pack_root
        assert bundle["attestation_sha256"] == pack_root  # D12
        assert bundle["token_b64"] != ""
        assert bundle["schema_version"] == SCHEMA_VERSION

    def test_generate_rekor_not_implemented(self, pack_dir):
        """Rekor witness type should raise WitnessError."""
        from assay.witness import generate_witness_bundle

        with pytest.raises(WitnessError, match="not yet implemented"):
            generate_witness_bundle(pack_dir, witness_type="rekor")

    def test_request_wraps_network_errors(self):
        """Non-WitnessError network failures should be wrapped as WitnessError."""
        with patch("assay.witness._openssl_ts_query") as mock_query, \
             patch("assay.witness._fetch_url", side_effect=RuntimeError("network down")):
            mock_query.return_value = "0xABCD"  # nonce
            with pytest.raises(WitnessError, match="RFC 3161 witness request failed"):
                request_rfc3161_witness(FAKE_PACK_ROOT)

    def test_generate_custom_output_path(self, pack_dir, pack_root, tmp_path):
        """Custom output path should be respected."""
        from assay.witness import generate_witness_bundle

        fake_token = b"\x30\x03\x02\x01\x00"
        fake_cert = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"

        def mock_run(cmd, **kwargs):
            r = MagicMock()
            r.stderr = b""
            r.stdout = b""
            if "ts" in cmd and "-query" in cmd and "-text" in cmd:
                r.returncode = 0
                r.stdout = b"Nonce: 0xABCD\n"
                return r
            if "-query" in cmd:
                r.returncode = 0
                out_idx = cmd.index("-out")
                Path(cmd[out_idx + 1]).write_bytes(b"fake-query")
                return r
            r.returncode = 1
            return r

        def mock_urlopen(req, **kwargs):
            resp = MagicMock()
            resp.read.return_value = fake_token if "tsr" in (req.full_url if hasattr(req, 'full_url') else str(req)) else fake_cert
            return resp

        custom = tmp_path / "custom" / "witness.json"

        with patch("assay.witness.subprocess.run", side_effect=mock_run), \
             patch("assay.witness.urlopen", side_effect=mock_urlopen):
            generate_witness_bundle(pack_dir, output_path=custom)

        assert custom.exists()
        loaded = json.loads(custom.read_text())
        assert loaded["pack_root_sha256"] == pack_root


class TestWitnessRoundTrip:
    """Generate then verify (all mocked)."""

    def test_generate_then_verify(self, pack_dir, pack_root):
        """generate -> verify should pass when openssl approves."""
        from assay.witness import generate_witness_bundle

        fake_token = b"\x30\x03\x02\x01\x00"
        fake_cert = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"

        def mock_run_gen(cmd, **kwargs):
            r = MagicMock()
            r.stderr = b""
            r.stdout = b""
            if "ts" in cmd and "-query" in cmd and "-text" in cmd:
                r.returncode = 0
                r.stdout = b"Nonce: 0xABCD\n"
                return r
            if "-query" in cmd:
                r.returncode = 0
                out_idx = cmd.index("-out")
                Path(cmd[out_idx + 1]).write_bytes(b"fake-query")
                return r
            r.returncode = 1
            return r

        def mock_urlopen(req, **kwargs):
            resp = MagicMock()
            resp.read.return_value = fake_token if "tsr" in (req.full_url if hasattr(req, 'full_url') else str(req)) else fake_cert
            return resp

        with patch("assay.witness.subprocess.run", side_effect=mock_run_gen), \
             patch("assay.witness.urlopen", side_effect=mock_urlopen):
            generate_witness_bundle(pack_dir)

        # Now verify
        mock_verify = MagicMock()
        mock_verify.returncode = 0
        mock_verify.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_verify):
            result = verify_witness_from_pack(pack_dir)

        assert result.passed
        assert result.errors == []


class TestWitnessCli:
    """CLI integration tests (mocked network)."""

    @pytest.fixture
    def isolated_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        return tmp_path

    @pytest.fixture
    def cli_pack(self, tmp_path, isolated_home):
        signer_id = "assay-local"
        keys_dir = isolated_home / ".assay" / "keys"
        ks = AssayKeyStore(keys_dir=keys_dir)
        ks.generate_key(signer_id)

        pack_dir = tmp_path / "proof_pack_cli"
        pp = ProofPack(run_id="witness-cli-test", entries=[], signer_id=signer_id)
        built = pp.build(pack_dir, keystore=ks)
        return built

    def test_witness_command_missing_pack(self, isolated_home, tmp_path):
        """witness command with missing pack should exit 2."""
        result = runner.invoke(
            assay_app,
            ["witness", str(tmp_path / "nonexistent")],
        )
        assert result.exit_code == 2

    def test_verify_witness_command_missing_bundle(self, cli_pack):
        """verify-witness with no bundle file should exit 2."""
        result = runner.invoke(
            assay_app,
            ["verify-witness", str(cli_pack)],
        )
        assert result.exit_code == 2

    def test_verify_witness_command_missing_pack(self, tmp_path):
        """verify-witness with missing pack should fail cleanly (no traceback)."""
        result = runner.invoke(
            assay_app,
            ["verify-witness", str(tmp_path / "missing-pack")],
        )
        assert result.exit_code == 2

    def test_verify_witness_command_with_valid_bundle(self, cli_pack):
        """verify-witness with valid bundle should exit 0."""
        manifest = json.loads((cli_pack / "pack_manifest.json").read_text())
        pack_root = manifest["pack_root_sha256"]

        bundle = _make_bundle(pack_root)
        (cli_pack / "witness_bundle.json").write_text(
            json.dumps(bundle, indent=2) + "\n"
        )

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = runner.invoke(
                assay_app,
                ["verify-witness", str(cli_pack)],
            )

        assert result.exit_code == 0


class TestRequireWitness:
    """--require-witness in verify-pack."""

    @pytest.fixture
    def isolated_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        return tmp_path

    @pytest.fixture
    def cli_pack(self, tmp_path, isolated_home):
        signer_id = "assay-local"
        keys_dir = isolated_home / ".assay" / "keys"
        ks = AssayKeyStore(keys_dir=keys_dir)
        ks.generate_key(signer_id)

        pack_dir = tmp_path / "proof_pack_req"
        pp = ProofPack(run_id="require-witness-test", entries=[], signer_id=signer_id)
        built = pp.build(pack_dir, keystore=ks)
        return built

    def test_require_witness_fails_without_bundle(self, cli_pack):
        """--require-witness without a witness_bundle.json should fail."""
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(cli_pack), "--require-witness"],
        )
        assert result.exit_code == 2

    def test_require_witness_passes_with_valid_bundle(self, cli_pack):
        """--require-witness with valid bundle should pass."""
        manifest = json.loads((cli_pack / "pack_manifest.json").read_text())
        pack_root = manifest["pack_root_sha256"]

        bundle = _make_bundle(pack_root)
        (cli_pack / "witness_bundle.json").write_text(
            json.dumps(bundle, indent=2) + "\n"
        )

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with patch("assay.witness.subprocess.run", return_value=mock_result):
            result = runner.invoke(
                assay_app,
                ["verify-pack", str(cli_pack), "--require-witness"],
            )

        assert result.exit_code == 0, result.stdout

    def test_no_require_witness_ignores_missing(self, cli_pack):
        """Without --require-witness, missing bundle should not affect result."""
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(cli_pack)],
        )
        assert result.exit_code == 0
