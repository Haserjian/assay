"""Match rules for parity field comparison.

Each rule takes two values and returns whether they match.
Rules are registered by name so contracts can reference them as strings.

Rules:
  exact          - Values must be identical (str, number, bool equality)
  content_hash   - SHA-256 of canonicalized content must match
  version_match  - Semantic version strings must be identical
  within_threshold - Numeric value within declared tolerance
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from assay.comparability.canonicalize import content_hash


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------

def _exact(a: Any, b: Any, **kwargs: Any) -> bool:
    """Values must be identical."""
    return a == b


def _content_hash_match(a: Any, b: Any, **kwargs: Any) -> bool:
    """SHA-256 of canonicalized content must match.

    Accepts raw content strings or pre-computed "sha256:<hex>" hashes.
    If both values look like hashes (start with "sha256:"), compare directly.
    Otherwise, canonicalize and hash both.
    """
    a_str = str(a)
    b_str = str(b)

    a_is_hash = a_str.startswith("sha256:")
    b_is_hash = b_str.startswith("sha256:")

    if a_is_hash and b_is_hash:
        return a_str == b_str

    # Compute hashes for non-hash values
    a_hash = a_str if a_is_hash else content_hash(a_str)
    b_hash = b_str if b_is_hash else content_hash(b_str)

    return a_hash == b_hash


def _version_match(a: Any, b: Any, **kwargs: Any) -> bool:
    """Semantic version strings must be identical.

    Simple string equality on normalized version strings.
    Does not do semver range matching — that would be too permissive
    for comparability governance.
    """
    return str(a).strip() == str(b).strip()


def _within_threshold(a: Any, b: Any, **kwargs: Any) -> bool:
    """Numeric value must be within declared tolerance.

    Requires 'threshold' in kwargs. Computes absolute difference.
    """
    threshold = kwargs.get("threshold")
    if threshold is None:
        # No threshold declared — fall back to exact match
        return a == b
    try:
        return abs(float(a) - float(b)) <= float(threshold)
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

MatchRuleFn = Callable[..., bool]

_RULES: Dict[str, MatchRuleFn] = {
    "exact": _exact,
    "content_hash": _content_hash_match,
    "version_match": _version_match,
    "within_threshold": _within_threshold,
}


def apply_rule(
    rule_name: str,
    baseline_value: Any,
    candidate_value: Any,
    **kwargs: Any,
) -> bool:
    """Apply a named match rule to two values.

    Raises KeyError if rule_name is not registered.
    """
    fn = _RULES.get(rule_name)
    if fn is None:
        raise KeyError(
            f"Unknown match rule: {rule_name!r}. "
            f"Available: {sorted(_RULES.keys())}"
        )
    return fn(baseline_value, candidate_value, **kwargs)


def available_rules() -> list[str]:
    """Return names of all registered match rules."""
    return sorted(_RULES.keys())
