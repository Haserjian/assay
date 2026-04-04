"""Shared receipt regression corpus parity checks.

These tests intentionally load the same regression fixture consumed by the
TypeScript verifier so corpus drift, missing fixtures, or path mistakes fail
in the Python runtime too.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay._receipts.canonicalize import (
    canonical_projection,
    prepare_receipt_for_hashing,
)

_REGRESSION_SPEC = (
    Path(__file__).resolve().parents[1]
    / "vectors"
    / "regression"
    / "homoglyph_field_bypass_spec.json"
)


def _load_regression_spec() -> dict:
    return json.loads(_REGRESSION_SPEC.read_text(encoding="utf-8"))


def test_shared_homoglyph_fixture_rejected_by_canonical_projection() -> None:
    spec = _load_regression_spec()

    assert spec["invariant"] == "INV-07"

    with pytest.raises(ValueError, match="ASCII-only"):
        canonical_projection(spec["receipt"])


def test_shared_homoglyph_fixture_rejected_by_prepare_receipt_for_hashing() -> None:
    spec = _load_regression_spec()

    with pytest.raises(ValueError, match="ASCII-only"):
        prepare_receipt_for_hashing(spec["receipt"])
