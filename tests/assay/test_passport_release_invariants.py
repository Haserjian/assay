"""Release invariants for the passport public surface.

These tests assert that the outward-facing passport loop remains intact:
- Gallery regenerates cleanly
- Expected artifact set exists
- README references the seeded gallery
- Demo command exits 0
- Version surface is consistent
- ROADMAP tracks current version
- Sensitive paths are gitignored
- Command count claims match reality

If any of these fail, the public referee loop is broken.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
README = REPO_ROOT / "README.md"
GALLERY_DIR = REPO_ROOT / "docs" / "passport" / "gallery"
GENERATOR = REPO_ROOT / "docs" / "passport" / "generate_gallery.py"
GITIGNORE = REPO_ROOT / ".gitignore"
ROADMAP = REPO_ROOT / "docs" / "ROADMAP.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"


# ---------------------------------------------------------------------------
# README surface
# ---------------------------------------------------------------------------

class TestReadmePassportSection:
    """README must reference the passport surface honestly."""

    def test_passport_section_exists(self):
        text = README.read_text(encoding="utf-8")
        assert "## Passports:" in text, "README missing Passport section heading"

    def test_gallery_link_present(self):
        text = README.read_text(encoding="utf-8")
        assert "docs/passport/gallery/" in text, (
            "README must link to the seeded referee gallery"
        )

    def test_truth_boundary_present(self):
        text = README.read_text(encoding="utf-8")
        assert "What this proves today" in text, (
            "README passport section must include truth boundary"
        )
        assert "What is future scope" in text, (
            "README passport section must include future scope disclaimer"
        )

    def test_no_overclaim_scanning(self):
        """README must not claim arbitrary trust-surface scanning."""
        text = README.read_text(encoding="utf-8")
        # Extract just the passport section
        start = text.find("## Passports:")
        end = text.find("## AI Decision Credentials")
        passport_section = text[start:end] if start != -1 and end != -1 else ""

        overclaims = [
            "scan any vendor",
            "scan your vendor",
            "paste any trust page",
            "AI trust score",
            "trust rating",
            "automated compliance",
        ]
        for phrase in overclaims:
            assert phrase.lower() not in passport_section.lower(), (
                f"README passport section contains forbidden overclaim: '{phrase}'"
            )

    def test_command_count_framing(self):
        """README must acknowledge all 12 commands, not just the featured subset."""
        text = README.read_text(encoding="utf-8")
        assert "12 commands" in text, (
            "README must state '12 commands' to match actual passport CLI surface"
        )


# ---------------------------------------------------------------------------
# Gallery artifacts
# ---------------------------------------------------------------------------

class TestGalleryArtifacts:
    """Gallery directory must contain the expected artifact set."""

    def test_gallery_dir_exists(self):
        assert GALLERY_DIR.is_dir(), "docs/passport/gallery/ must exist"

    def test_passport_v1_exists(self):
        assert (GALLERY_DIR / "passport_v1.json").is_file()

    def test_passport_v2_exists(self):
        assert (GALLERY_DIR / "passport_v2.json").is_file()

    def test_passport_v1_html_exists(self):
        assert (GALLERY_DIR / "passport_v1.html").is_file()

    def test_xray_report_exists(self):
        assert (GALLERY_DIR / "xray_v1.html").is_file()

    def test_trust_diff_exists(self):
        assert (GALLERY_DIR / "trust_diff.html").is_file()

    def test_manifest_exists(self):
        assert (GALLERY_DIR / "GALLERY.md").is_file()

    def test_challenge_receipt_exists(self):
        challenge_files = list(GALLERY_DIR.glob("challenge_*.json"))
        assert len(challenge_files) >= 1, "Gallery must contain a challenge receipt"

    def test_supersession_receipt_exists(self):
        sup_files = list(GALLERY_DIR.glob("supersession_*.json"))
        assert len(sup_files) >= 1, "Gallery must contain a supersession receipt"

    def test_v1_is_signed(self):
        data = json.loads((GALLERY_DIR / "passport_v1.json").read_text())
        assert "signature" in data, "Gallery v1 passport must be signed"
        assert "passport_id" in data, "Gallery v1 passport must have content-addressed ID"

    def test_v2_is_signed(self):
        data = json.loads((GALLERY_DIR / "passport_v2.json").read_text())
        assert "signature" in data, "Gallery v2 passport must be signed"

    def test_v1_v2_different_ids(self):
        d1 = json.loads((GALLERY_DIR / "passport_v1.json").read_text())
        d2 = json.loads((GALLERY_DIR / "passport_v2.json").read_text())
        assert d1["passport_id"] != d2["passport_id"], (
            "v1 and v2 must have different passport IDs"
        )

    def test_challenge_receipt_is_signed(self):
        ch = list(GALLERY_DIR.glob("challenge_*.json"))
        data = json.loads(ch[0].read_text())
        assert "signature" in data, "Gallery challenge receipt must be signed"
        assert "event_id" in data, "Gallery challenge receipt must have event_id"

    def test_artifact_count(self):
        """Gallery should have exactly 8 artifacts (7 generated + GALLERY.md)."""
        files = [f for f in GALLERY_DIR.iterdir() if f.is_file()]
        assert len(files) == 8, (
            f"Expected 8 gallery artifacts, got {len(files)}: "
            f"{sorted(f.name for f in files)}"
        )


# ---------------------------------------------------------------------------
# Gallery regeneration
# ---------------------------------------------------------------------------

class TestGalleryRegeneration:
    """Gallery must regenerate cleanly from scratch."""

    def test_regenerates_cleanly(self):
        """Generate gallery into a temp dir and verify artifact set."""
        import sys
        sys.path.insert(0, str(REPO_ROOT / "src"))

        # Import and run the generator
        import importlib.util
        spec = importlib.util.spec_from_file_location("generate_gallery", GENERATOR)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        tmp = Path(tempfile.mkdtemp(prefix="assay_gallery_test_"))
        try:
            mod.generate(tmp)

            # Check expected artifacts
            assert (tmp / "passport_v1.json").is_file()
            assert (tmp / "passport_v2.json").is_file()
            assert (tmp / "passport_v1.html").is_file()
            assert (tmp / "xray_v1.html").is_file()
            assert (tmp / "trust_diff.html").is_file()
            assert len(list(tmp.glob("challenge_*.json"))) >= 1
            assert len(list(tmp.glob("supersession_*.json"))) >= 1

            # Verify structural correctness
            d1 = json.loads((tmp / "passport_v1.json").read_text())
            d2 = json.loads((tmp / "passport_v2.json").read_text())
            assert d1["passport_id"] != d2["passport_id"]
            assert "signature" in d1
            assert "signature" in d2
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Demo command
# ---------------------------------------------------------------------------

class TestDemoCommand:
    """assay passport demo must complete without error."""

    def test_demo_exits_zero(self):
        from typer.testing import CliRunner
        from assay.commands import assay_app

        tmp = Path(tempfile.mkdtemp(prefix="assay_demo_test_"))
        try:
            runner = CliRunner()
            result = runner.invoke(assay_app, [
                "passport", "demo", "--output-dir", str(tmp),
            ])
            assert result.exit_code == 0, (
                f"Demo exited {result.exit_code}:\n{result.output}"
            )
            assert "Verify checks integrity;" in result.output
            assert "status checks reliance posture" in result.output
            assert "This is diagnostic quality" in result.output
            # Verify the demo produced artifacts
            assert (tmp / "passport_v1.json").is_file()
            assert (tmp / "passport_v2.json").is_file()
            assert (tmp / "trust_diff.html").is_file()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Version surface consistency
# ---------------------------------------------------------------------------

class TestVersionSurface:
    """Package version must be consistent across all surfaces."""

    def _pyproject_version(self) -> str:
        import re
        text = PYPROJECT.read_text(encoding="utf-8")
        m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert m, "pyproject.toml must contain a version field"
        return m.group(1)

    def test_runtime_version_matches_pyproject(self):
        """Runtime __version__ must match pyproject.toml."""
        import assay
        pyproject_ver = self._pyproject_version()
        assert assay.__version__ == pyproject_ver, (
            f"assay.__version__ ({assay.__version__}) != "
            f"pyproject.toml ({pyproject_ver}). "
            f"Reinstall editable: pip install -e ."
        )

    def test_version_not_dev_sentinel(self):
        """Installed package must not report dev sentinel."""
        import assay
        assert assay.__version__ != "0.0.0-dev", (
            "assay.__version__ is '0.0.0-dev' — package not installed. "
            "Run: pip install -e ."
        )

    def test_roadmap_version_matches_pyproject(self):
        """ROADMAP 'As of' version must match pyproject.toml."""
        import re
        pyproject_ver = self._pyproject_version()
        roadmap_text = ROADMAP.read_text(encoding="utf-8")
        m = re.search(r"\*\*As of\*\*:\s*v([\d.]+)", roadmap_text)
        assert m, "ROADMAP must contain '**As of**: vX.Y.Z'"
        assert m.group(1) == pyproject_ver, (
            f"ROADMAP version ({m.group(1)}) != pyproject.toml ({pyproject_ver})"
        )


# ---------------------------------------------------------------------------
# Sensitive path protection
# ---------------------------------------------------------------------------

class TestSensitivePathProtection:
    """Sensitive paths must be gitignored to prevent accidental exposure."""

    def test_commercial_docs_ignored(self):
        """docs/commercial/ must be in .gitignore."""
        text = GITIGNORE.read_text(encoding="utf-8")
        assert "docs/commercial/" in text, (
            "docs/commercial/ must be in .gitignore — "
            "contains DM templates, outreach trackers, launch strategy"
        )

    def test_assay_runtime_state_ignored(self):
        """.assay/ must be in .gitignore."""
        text = GITIGNORE.read_text(encoding="utf-8")
        assert ".assay/" in text, ".assay/ runtime state must be gitignored"

    def test_evidence_gap_reports_ignored(self):
        """evidence_gap_report.* must be in .gitignore."""
        text = GITIGNORE.read_text(encoding="utf-8")
        assert "evidence_gap_report" in text, (
            "evidence_gap_report.* must be gitignored"
        )


# ---------------------------------------------------------------------------
# Command count consistency
# ---------------------------------------------------------------------------

class TestCommandCount:
    """Passport CLI must have the claimed number of commands."""

    def test_passport_has_12_commands(self):
        """assay passport must expose exactly 12 subcommands.

        Uses Typer's registered_commands/registered_groups rather than
        parsing help output, because help text wrapping is presentation
        and the app object is the authority surface.
        """
        from assay.passport_commands import passport_app

        # Count registered commands directly from the Typer app object
        commands = list(passport_app.registered_commands)
        groups = list(passport_app.registered_groups)
        total = len(commands) + len(groups)
        assert total == 12, (
            f"Expected 12 passport commands, found {total}. "
            f"Commands: {[c.name or c.callback.__name__ for c in commands]}"
        )
