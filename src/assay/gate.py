"""Evidence gate: deterministic CI enforcement for score regression.

``assay gate check`` computes the current Evidence Readiness Score and
enforces a minimum threshold and/or regression policy against a saved
baseline.

Exit codes follow the CLI convention:
  0  PASS
  1  FAIL (below threshold or regression detected)
  3  Bad input (invalid baseline file, missing directory)
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def evaluate_gate(
    *,
    current_score: Dict[str, Any],
    min_score: Optional[float] = None,
    fail_on_regression: bool = False,
    baseline_score: Optional[float] = None,
) -> Dict[str, Any]:
    """Evaluate gate policy against a computed score.

    Returns a gate report dict with result, reasons, and metadata.
    """
    score = current_score["score"]
    grade = current_score["grade"]
    reasons: List[str] = []
    regression_detected = False

    if min_score is not None and score < min_score:
        reasons.append(
            f"Score {score:.1f} below minimum threshold {min_score:.1f}"
        )

    if fail_on_regression and baseline_score is not None:
        if score < baseline_score:
            regression_detected = True
            reasons.append(
                f"Score regressed from {baseline_score:.1f} to {score:.1f}"
            )

    result = "FAIL" if reasons else "PASS"

    return {
        "command": "assay gate",
        "result": result,
        "current_score": score,
        "current_grade": grade,
        "baseline_score": baseline_score,
        "min_score": min_score,
        "regression_detected": regression_detected,
        "reasons": reasons,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def load_score_baseline(path: Path) -> Optional[float]:
    """Load a saved score baseline from a JSON file.

    Expected format: {"score": <float>, ...}
    Returns None if file is missing or invalid.
    """
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "score" in data:
            return normalize_score_value(data["score"])
    except (json.JSONDecodeError, OSError, TypeError, ValueError):
        pass
    return None


def normalize_score_value(value: Any) -> Optional[float]:
    """Normalize a score value to a finite float in [0, 100]."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score):
        return None
    if score < 0 or score > 100:
        return None
    return score


def save_score_baseline(score_data: Dict[str, Any], path: Path) -> Path:
    """Save current score as a gate baseline.

    Writes score, grade, and timestamp. Returns the path written.
    """
    baseline = {
        "score": score_data["score"],
        "grade": score_data["grade"],
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "score_version": score_data.get("score_version"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    return path


DEFAULT_BASELINE_PATH = Path(".assay") / "score-baseline.json"


# ---------------------------------------------------------------------------
# Posture-aware gate
# ---------------------------------------------------------------------------

# Ordered from most strict to most permissive.
DISPOSITION_RANK = {
    "blocked": 0,
    "incomplete": 1,
    "supported_but_capped": 2,
    "verified": 3,
}


def evaluate_posture_gate(
    *,
    disposition: str,
    min_disposition: str = "incomplete",
) -> Dict[str, Any]:
    """Evaluate a proof-posture disposition against a minimum threshold.

    Returns a gate-report dict with result and reasons.

    Disposition ranking (strictest → most permissive):
      blocked < incomplete < supported_but_capped < verified

    The default ``min_disposition="incomplete"`` fails only on ``blocked``.
    Use ``min_disposition="verified"`` to require full verification with no
    caps or blocking risks.
    """
    actual_rank = DISPOSITION_RANK.get(disposition)
    required_rank = DISPOSITION_RANK.get(min_disposition)

    reasons: List[str] = []

    if actual_rank is None:
        reasons.append(f"Unknown disposition '{disposition}'")
    elif required_rank is None:
        reasons.append(f"Unknown min_disposition '{min_disposition}'")
    elif actual_rank < required_rank:
        reasons.append(
            f"Posture disposition '{disposition}' does not meet "
            f"minimum '{min_disposition}'"
        )

    result = "FAIL" if reasons else "PASS"

    return {
        "posture_result": result,
        "disposition": disposition,
        "min_disposition": min_disposition,
        "reasons": reasons,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
