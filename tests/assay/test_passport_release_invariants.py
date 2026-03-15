"""Release invariants for the passport public surface.

These tests assert that the outward-facing passport loop remains intact:
- Gallery regenerates cleanly
- Expected artifact set exists
- README references the seeded gallery
- Demo command exits 0

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
            # Verify the demo produced artifacts
            assert (tmp / "passport_v1.json").is_file()
            assert (tmp / "passport_v2.json").is_file()
            assert (tmp / "trust_diff.html").is_file()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
