"""
Shared update-check logic for assay version and assay doctor.

Single source of truth for PyPI version comparison, timeout behavior,
error semantics, and prerelease policy.

Prerelease policy (explicit):
  - Stable installs (no pre/dev segment) are NOT nudged toward prereleases.
    1.20.1 will not prompt if latest on PyPI is 1.21.0rc1.
  - Prerelease installs ARE nudged toward any newer version, including
    newer prereleases and stable releases.
  Rationale: production users should not be surprised by rc/alpha nudges;
  users who opted into a prerelease already accept that posture.

UpdateStatus semantics:
  available  — product question: is there an update worth installing?
  checked    — proof question:   did comparison actually complete?
  reason     — audit question:   why did we land here?

Reason vocabulary (machine-readable):
  up_to_date          — checked, no newer eligible version
  update_available    — checked, newer eligible version found
  prerelease_ignored  — checked, newer version exists but is prerelease (stable install)
  version_unavailable — installed version could not be imported
  pypi_unreachable    — network failure or timeout
  parse_failed        — version string(s) could not be parsed by packaging.version
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

UpdateReason = Literal[
    "up_to_date",
    "update_available",
    "prerelease_ignored",
    "version_unavailable",
    "pypi_unreachable",
    "parse_failed",
]


@dataclass(frozen=True)
class UpdateStatus:
    installed: Optional[str]
    latest: Optional[str]
    available: bool           # True only when checked=True and eligible update exists
    checked: bool             # True only when both versions parsed and compared
    message: str
    reason: UpdateReason      # machine-readable; see UpdateReason vocabulary
    update_command: str = "pipx upgrade assay-ai"


def check_for_update(timeout: float = 3.0) -> UpdateStatus:
    """
    Check PyPI for a newer version of assay-ai.

    Returns an UpdateStatus. Never raises — all failures produce
    available=False, checked=False with a reason string.
    """
    try:
        from assay import __version__ as installed
    except ImportError:
        return UpdateStatus(
            installed=None,
            latest=None,
            available=False,
            checked=False,
            message="Version unavailable — skipping update check",
            reason="version_unavailable",
        )

    try:
        import urllib.request
        import json as _json

        with urllib.request.urlopen(
            "https://pypi.org/pypi/assay-ai/json", timeout=timeout
        ) as resp:
            latest = _json.loads(resp.read())["info"]["version"]
    except Exception:
        return UpdateStatus(
            installed=installed,
            latest=None,
            available=False,
            checked=False,
            message="PyPI unreachable — skipping update check",
            reason="pypi_unreachable",
        )

    try:
        from packaging.version import Version, InvalidVersion

        v_installed = Version(installed)
        v_latest = Version(latest)
    except Exception:
        return UpdateStatus(
            installed=installed,
            latest=latest,
            available=False,
            checked=False,
            message="Could not parse version strings — skipping update check",
            reason="parse_failed",
        )

    # Prerelease policy: stable installs skip prerelease nudges.
    if not v_installed.is_prerelease and v_latest.is_prerelease:
        return UpdateStatus(
            installed=installed,
            latest=latest,
            available=False,
            checked=True,
            message=f"No newer eligible update ({installed}); newer prerelease ignored",
            reason="prerelease_ignored",
        )

    if v_latest > v_installed:
        return UpdateStatus(
            installed=installed,
            latest=latest,
            available=True,
            checked=True,
            message=f"Update available: {installed} → {latest}",
            reason="update_available",
        )

    return UpdateStatus(
        installed=installed,
        latest=latest,
        available=False,
        checked=True,
        message=f"assay-ai is up to date ({installed})",
        reason="up_to_date",
    )
