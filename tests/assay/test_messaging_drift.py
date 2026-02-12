"""Drift guard: key claims must be consistent across all public-facing files.

This test prevents the exact problem we fixed by hand: README says "28",
posts say "21", report says something else. If a number, command, or link
diverges across files, this test fails.

Checked artifacts:
  - README.md
  - scripts/scan_study/posts/hn.md
  - scripts/scan_study/posts/reddit.md
  - scripts/scan_study/posts/discord.md
  - scripts/scan_study/results/report.md
  - src/assay/__init__.py
  - pyproject.toml
  - docs/index.html (landing page)
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------

README = REPO_ROOT / "README.md"
LANDING_PAGE = REPO_ROOT / "docs" / "index.html"
HN_POST = REPO_ROOT / "scripts" / "scan_study" / "posts" / "hn.md"
REDDIT_POST = REPO_ROOT / "scripts" / "scan_study" / "posts" / "reddit.md"
DISCORD_POST = REPO_ROOT / "scripts" / "scan_study" / "posts" / "discord.md"
SCAN_REPORT = REPO_ROOT / "scripts" / "scan_study" / "results" / "report.md"
INIT_PY = REPO_ROOT / "src" / "assay" / "__init__.py"
PYPROJECT = REPO_ROOT / "pyproject.toml"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Version consistency
# ---------------------------------------------------------------------------

class TestVersionConsistency:
    """__init__.py __version__ must match pyproject.toml version."""

    def test_init_matches_pyproject(self):
        init_text = _read(INIT_PY)
        match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
        assert match, "__version__ not found in __init__.py"
        init_version = match.group(1)

        pyproject_text = _read(PYPROJECT)
        match2 = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text, re.MULTILINE)
        assert match2, "version not found in pyproject.toml"
        pyproject_version = match2.group(1)

        assert init_version == pyproject_version, (
            f"Version mismatch: __init__.py={init_version}, "
            f"pyproject.toml={pyproject_version}"
        )


# ---------------------------------------------------------------------------
# Scan study numbers
# ---------------------------------------------------------------------------

class TestScanStudyNumbers:
    """The "202 high-confidence" and "21 projects" numbers must match everywhere."""

    FILES_WITH_202 = [README, HN_POST, SCAN_REPORT]

    @pytest.mark.parametrize("path", FILES_WITH_202, ids=lambda p: p.name)
    def test_202_high_confidence_present(self, path):
        text = _read(path)
        assert "202" in text, f"{path.name} doesn't mention 202 high-confidence sites"

    def test_project_count_consistent(self):
        """Every file that mentions a project count should use the same number."""
        project_counts = {}
        for path in [README, HN_POST, SCAN_REPORT]:
            text = _read(path)
            # Match patterns like "across 21 projects", "across 21 repos"
            matches = re.findall(r"across\s+(\d+)\s+(?:project|repo)", text)
            if matches:
                project_counts[path.name] = set(matches)

        if not project_counts:
            pytest.skip("No project count references found")

        all_counts = set()
        for counts in project_counts.values():
            all_counts.update(counts)

        assert len(all_counts) == 1, (
            f"Project count divergence: {project_counts}"
        )


# ---------------------------------------------------------------------------
# Exit code messaging
# ---------------------------------------------------------------------------

class TestExitCodeMessaging:
    """Exit code descriptions must be consistent across posts."""

    def test_exit_0_mentioned(self):
        """All posts should reference exit 0 as pass/authentic."""
        for path in [HN_POST, REDDIT_POST]:
            text = _read(path).lower()
            assert "exit" in text and "0" in text, (
                f"{path.name} doesn't mention exit code 0"
            )

    def test_exit_2_mentioned(self):
        """All posts should reference exit 2 as tampered."""
        for path in [HN_POST, REDDIT_POST]:
            text = _read(path).lower()
            assert "exit" in text and "2" in text, (
                f"{path.name} doesn't mention exit code 2"
            )

    def test_no_stale_exit_code_descriptions(self):
        """Exit codes should not claim wrong semantics."""
        for path in [HN_POST, REDDIT_POST, DISCORD_POST]:
            text = _read(path)
            # Exit 0 should never be described as "fail" or "tampered"
            # Exit 2 should never be described as "pass"
            # (Simple heuristic: "exit 0" near "fail" or "exit 2" near "pass")
            lines = text.split("\n")
            for line in lines:
                lower = line.lower()
                if "exit 0" in lower or "exit code 0" in lower:
                    assert "fail" not in lower or "claim" in lower, (
                        f"Suspicious exit 0 description in {path.name}: {line.strip()}"
                    )


# ---------------------------------------------------------------------------
# Key commands
# ---------------------------------------------------------------------------

class TestKeyCommands:
    """Commands referenced in posts must be valid."""

    def test_scan_report_flag_present(self):
        """Posts that reference --report should use the right flag."""
        for path in [HN_POST, REDDIT_POST, DISCORD_POST]:
            text = _read(path)
            if "--report" in text:
                assert "assay scan" in text, (
                    f"{path.name} mentions --report but not 'assay scan'"
                )

    def test_demo_challenge_present_in_posts(self):
        """All posts should reference demo-challenge."""
        for path in [HN_POST, REDDIT_POST, DISCORD_POST]:
            text = _read(path)
            assert "demo-challenge" in text, (
                f"{path.name} doesn't mention demo-challenge"
            )

    def test_verify_pack_present_in_posts(self):
        """All posts should reference verify-pack."""
        for path in [HN_POST, REDDIT_POST, DISCORD_POST]:
            text = _read(path)
            assert "verify-pack" in text, (
                f"{path.name} doesn't mention verify-pack"
            )

    def test_pip_install_command_consistent(self):
        """pip install command should use the same package name everywhere."""
        package_names = set()
        for path in [README, HN_POST, REDDIT_POST, DISCORD_POST]:
            text = _read(path)
            matches = re.findall(r"pip install\s+([\w-]+)", text)
            package_names.update(matches)

        # Filter out dev/test extras
        package_names = {p for p in package_names if "assay" in p.lower()}
        assert len(package_names) == 1, (
            f"Inconsistent package names in pip install: {package_names}"
        )


# ---------------------------------------------------------------------------
# Link freshness
# ---------------------------------------------------------------------------

class TestLinkConsistency:
    """Links should not point to pinned commit SHAs (use branch refs)."""

    def test_no_pinned_blob_shas_in_posts(self):
        """Post links should use /blob/main/ not /blob/<sha>/."""
        sha_pattern = re.compile(r"/blob/[0-9a-f]{7,40}/")
        for path in [HN_POST, REDDIT_POST, DISCORD_POST]:
            text = _read(path)
            matches = sha_pattern.findall(text)
            assert not matches, (
                f"{path.name} has pinned SHA links: {matches}. "
                f"Use /blob/main/ instead."
            )

    def test_github_links_point_to_correct_org(self):
        """All GitHub links should point to Haserjian/assay."""
        for path in [README, HN_POST, REDDIT_POST, DISCORD_POST]:
            text = _read(path)
            gh_links = re.findall(r"github\.com/(\w+)/(\w+)", text)
            for org, repo in gh_links:
                if repo.startswith("assay"):
                    assert org == "Haserjian", (
                        f"{path.name} links to {org}/{repo}, expected Haserjian/"
                    )


# ---------------------------------------------------------------------------
# Landing page drift guard
# ---------------------------------------------------------------------------

class TestLandingPage:
    """Landing page must stay consistent with runtime behavior."""

    def test_exit_code_table_has_four_rows(self):
        text = _read(LANDING_PAGE)
        assert "Four exit codes" in text, (
            "Landing page heading should say 'Four exit codes'"
        )

    def test_exit_code_3_present(self):
        text = _read(LANDING_PAGE)
        assert "exit-3" in text or "exit-code exit-3" in text, (
            "Landing page exit code table missing exit code 3"
        )

    def test_faq_mentions_all_four_exit_codes(self):
        text = _read(LANDING_PAGE)
        # The FAQ answer about verify-pack should mention all 4 exit codes
        assert "1 = claims failed" in text, (
            "FAQ verify-pack answer missing exit code 1"
        )
        assert "3 = bad input" in text, (
            "FAQ verify-pack answer missing exit code 3"
        )

    def test_completeness_contract_section_exists(self):
        text = _read(LANDING_PAGE)
        assert "Completeness Contract" in text, (
            "Landing page missing Completeness Contract section"
        )

    def test_coverage_contract_in_ci_card(self):
        text = _read(LANDING_PAGE)
        assert "coverage_contract" in text, (
            "Landing page CI card should reference coverage_contract"
        )

    def test_gap_map_has_30_repos(self):
        text = _read(LANDING_PAGE)
        # GAP_DATA array entries
        repo_count = text.count("{repo:")
        assert repo_count == 30, (
            f"Landing page Gap Map has {repo_count} repos, expected 30"
        )

    def test_stats_bar_says_30(self):
        text = _read(LANDING_PAGE)
        assert "30" in text and "AI projects scanned" in text, (
            "Landing page stats bar should show 30 AI projects scanned"
        )
