"""
Tests for Assay health checks.
"""
from __future__ import annotations


from assay.health import (
    GraceConfig,
    GraceStatus,
    is_grace_window,
    check_grace_status,
    format_grace_status,
)


class TestGraceWindow:
    """Tests for grace window detection."""

    def test_in_grace_when_all_conditions_met(self) -> None:
        """All conditions met = in grace window."""
        result = is_grace_window(
            coherence=0.85,      # >= 0.75
            tension=0.15,        # <= 0.25
            tension_derivative=-0.01,  # <= 0
            dignity=0.25,        # >= 0.15
            volatility=0.10,     # <= 0.35
        )

        assert result is True

    def test_not_in_grace_low_coherence(self) -> None:
        """Low coherence = not in grace."""
        result = is_grace_window(
            coherence=0.50,      # < 0.75
            tension=0.15,
            tension_derivative=-0.01,
            dignity=0.25,
            volatility=0.10,
        )

        assert result is False

    def test_not_in_grace_high_tension(self) -> None:
        """High tension = not in grace."""
        result = is_grace_window(
            coherence=0.85,
            tension=0.40,        # > 0.25
            tension_derivative=-0.01,
            dignity=0.25,
            volatility=0.10,
        )

        assert result is False

    def test_not_in_grace_increasing_tension(self) -> None:
        """Increasing tension = not in grace."""
        result = is_grace_window(
            coherence=0.85,
            tension=0.15,
            tension_derivative=0.05,  # > 0
            dignity=0.25,
            volatility=0.10,
        )

        assert result is False

    def test_not_in_grace_low_dignity(self) -> None:
        """Dignity below floor = not in grace."""
        result = is_grace_window(
            coherence=0.85,
            tension=0.15,
            tension_derivative=-0.01,
            dignity=0.10,        # < 0.15
            volatility=0.10,
        )

        assert result is False

    def test_not_in_grace_high_volatility(self) -> None:
        """High volatility = not in grace."""
        result = is_grace_window(
            coherence=0.85,
            tension=0.15,
            tension_derivative=-0.01,
            dignity=0.25,
            volatility=0.50,     # > 0.35
        )

        assert result is False

    def test_custom_config(self) -> None:
        """Custom config changes thresholds."""
        strict_config = GraceConfig(
            c_hi=0.90,
            t_lo=0.10,
            d_floor=0.30,
            v_max=0.20,
        )

        # Would pass default config, fails strict config
        result = is_grace_window(
            coherence=0.85,
            tension=0.15,
            tension_derivative=-0.01,
            dignity=0.25,
            volatility=0.25,
            cfg=strict_config,
        )

        assert result is False


class TestGraceStatus:
    """Tests for detailed grace status."""

    def test_check_grace_status_returns_details(self) -> None:
        """check_grace_status returns individual check results."""
        status = check_grace_status(
            coherence=0.85,
            tension=0.40,  # Fails
            tension_derivative=-0.01,
            dignity=0.25,
            volatility=0.10,
        )

        assert isinstance(status, GraceStatus)
        assert status.in_grace is False
        assert status.coherence_ok is True
        assert status.tension_ok is False  # This one failed
        assert status.tension_decreasing is True
        assert status.dignity_ok is True
        assert status.volatility_ok is True

    def test_format_grace_status(self) -> None:
        """format_grace_status produces readable output."""
        status = GraceStatus(
            in_grace=True,
            coherence_ok=True,
            tension_ok=True,
            tension_decreasing=True,
            dignity_ok=True,
            volatility_ok=True,
        )

        output = format_grace_status(status)

        assert "GRACE WINDOW" in output
        assert "[+]" in output
