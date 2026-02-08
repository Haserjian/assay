"""
Assay health checks.

Grace window detection: identifies when the system is in a stable,
low-friction state where risky actions might be safer.

This is a measurable condition, not a mystical state.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, NamedTuple, Optional


def clamp(value: float, min_val: float = 0.0, max_val: float = 1.0) -> float:
    """Clamp value to [min_val, max_val] range."""
    return max(min_val, min(max_val, value))


@dataclass
class GraceConfig:
    """
    Configuration for grace window detection.

    Default values are conservative — adjust based on your domain.
    """
    c_hi: float = 0.75      # Minimum coherence threshold
    t_lo: float = 0.25      # Maximum tension threshold
    d_floor: float = 0.15   # Minimum dignity threshold (Clause 0)
    v_max: float = 0.35     # Maximum volatility
    window_size: int = 3    # Hysteresis window (must be in grace for N checks)
    require_unanimous: bool = True  # All window checks must pass


class GraceStatus(NamedTuple):
    """Detailed grace window status with individual checks."""
    in_grace: bool
    coherence_ok: bool
    tension_ok: bool
    tension_decreasing: bool
    dignity_ok: bool
    volatility_ok: bool


def is_grace_window(
    coherence: float,
    tension: float,
    tension_derivative: float,
    dignity: float,
    volatility: float,
    cfg: Optional[GraceConfig] = None,
) -> bool:
    """
    Detect when system is in a stable, low-friction state.

    Grace window conditions:
    - Coherence high (system is internally consistent)
    - Tension low AND decreasing (conflicts are resolving)
    - Dignity above floor (no harm externalization)
    - Volatility low (state is stable)

    Args:
        coherence: Current coherence score (0.0-1.0)
        tension: Current tension score (0.0-1.0)
        tension_derivative: Rate of change of tension (negative = decreasing)
        dignity: Current dignity score (0.0-1.0)
        volatility: Current volatility (0.0-1.0)
        cfg: Optional configuration override

    Returns:
        True if all grace window conditions are met

    Example:
        >>> is_grace_window(0.85, 0.15, -0.02, 0.20, 0.10)
        True

        >>> is_grace_window(0.85, 0.40, 0.05, 0.20, 0.10)  # Tension too high
        False
    """
    if cfg is None:
        cfg = GraceConfig()

    return (
        coherence >= cfg.c_hi
        and tension <= cfg.t_lo
        and tension_derivative <= 0
        and dignity >= cfg.d_floor
        and volatility <= cfg.v_max
    )


def check_grace_status(
    coherence: float,
    tension: float,
    tension_derivative: float,
    dignity: float,
    volatility: float,
    cfg: Optional[GraceConfig] = None,
) -> GraceStatus:
    """
    Get detailed grace window status with individual check results.

    Useful for diagnostics — shows which conditions are failing.

    Args:
        Same as is_grace_window

    Returns:
        GraceStatus with individual check results
    """
    if cfg is None:
        cfg = GraceConfig()

    coherence_ok = coherence >= cfg.c_hi
    tension_ok = tension <= cfg.t_lo
    tension_decreasing = tension_derivative <= 0
    dignity_ok = dignity >= cfg.d_floor
    volatility_ok = volatility <= cfg.v_max

    in_grace = all([
        coherence_ok,
        tension_ok,
        tension_decreasing,
        dignity_ok,
        volatility_ok,
    ])

    return GraceStatus(
        in_grace=in_grace,
        coherence_ok=coherence_ok,
        tension_ok=tension_ok,
        tension_decreasing=tension_decreasing,
        dignity_ok=dignity_ok,
        volatility_ok=volatility_ok,
    )


def format_grace_status(status: GraceStatus) -> str:
    """Format grace status for CLI display."""
    def check(ok: bool, label: str) -> str:
        mark = "+" if ok else "-"
        return f"[{mark}] {label}"

    lines = [
        check(status.coherence_ok, "Coherence high"),
        check(status.tension_ok, "Tension low"),
        check(status.tension_decreasing, "Tension decreasing"),
        check(status.dignity_ok, "Dignity above floor"),
        check(status.volatility_ok, "Volatility low"),
    ]

    verdict = "GRACE WINDOW" if status.in_grace else "NOT IN GRACE"
    return f"{verdict}\n" + "\n".join(lines)


@dataclass
class GraceTracker:
    """
    Tracks grace window state with hysteresis.

    Prevents flickering by requiring N consecutive passing checks
    before entering grace, and N consecutive failures before exiting.
    """
    cfg: GraceConfig = field(default_factory=GraceConfig)
    _history: Deque[bool] = field(default_factory=lambda: deque(maxlen=5))
    _in_grace: bool = False

    def __post_init__(self):
        # Ensure history deque has correct maxlen
        self._history = deque(maxlen=self.cfg.window_size)

    def update(
        self,
        coherence: float,
        tension: float,
        tension_derivative: float,
        dignity: float,
        volatility: float,
    ) -> bool:
        """
        Update tracker with new readings and return current grace state.

        Uses hysteresis: must have window_size consecutive passes to enter grace,
        and window_size consecutive failures to exit grace.
        """
        # Clamp inputs to valid range
        coherence = clamp(coherence)
        tension = clamp(tension)
        dignity = clamp(dignity)
        volatility = clamp(volatility)

        # Check current state
        current_pass = is_grace_window(
            coherence, tension, tension_derivative, dignity, volatility,
            cfg=GraceConfig(
                c_hi=self.cfg.c_hi,
                t_lo=self.cfg.t_lo,
                d_floor=self.cfg.d_floor,
                v_max=self.cfg.v_max,
            )
        )

        self._history.append(current_pass)

        # Apply hysteresis
        if len(self._history) >= self.cfg.window_size:
            if self.cfg.require_unanimous:
                all_pass = all(self._history)
                all_fail = not any(self._history)
            else:
                # Majority rule
                pass_count = sum(self._history)
                threshold = (self.cfg.window_size // 2) + 1
                all_pass = pass_count >= threshold
                all_fail = (self.cfg.window_size - pass_count) >= threshold

            if all_pass and not self._in_grace:
                self._in_grace = True
            elif all_fail and self._in_grace:
                self._in_grace = False

        return self._in_grace

    @property
    def in_grace(self) -> bool:
        """Current grace state (with hysteresis applied)."""
        return self._in_grace

    @property
    def history(self) -> list:
        """Recent check history."""
        return list(self._history)


__all__ = [
    "clamp",
    "GraceConfig",
    "GraceStatus",
    "GraceTracker",
    "is_grace_window",
    "check_grace_status",
    "format_grace_status",
]
