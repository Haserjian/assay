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
    """Values must be identical (value AND type).

    Python's ``True == 1`` is True, but for parity comparison
    a boolean and an integer are semantically different field values.
    """
    if type(a) is not type(b):
        return False
    return a == b


def _content_hash_match(a: Any, b: Any, **kwargs: Any) -> bool:
    """SHA-256 of canonicalized content must match.

    Both sides must use the same representation:
      - Both raw content  → canonicalize and hash both, then compare.
      - Both pre-computed "sha256:<hex>" → compare digests directly.
      - Mixed (one raw, one pre-hash) → always returns False.

    Mixed-mode rejection prevents an attacker from substituting a
    pre-computed hash of baseline content into a candidate bundle,
    which would falsely satisfy the parity check without presenting
    the same underlying content.
    """
    a_str = str(a)
    b_str = str(b)

    a_is_hash = a_str.startswith("sha256:")
    b_is_hash = b_str.startswith("sha256:")

    if a_is_hash != b_is_hash:
        # Mixed representation: one raw, one pre-hash.
        # Reject — cannot safely compare across representation modes.
        return False

    if a_is_hash and b_is_hash:
        return a_str == b_str

    # Both raw: canonicalize and hash both sides
    return content_hash(a_str) == content_hash(b_str)


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
    Fallback (no threshold) uses type-aware exact match.
    """
    threshold = kwargs.get("threshold")
    if threshold is None:
        # No threshold declared — fall back to exact match (with type guard)
        return type(a) is type(b) and a == b
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
