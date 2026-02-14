"""
Tests for schema version registry and parent_receipt_id emission.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List

import pytest

from assay.schema import (
    CORE_FIELDS,
    CURRENT_VERSION,
    KNOWN_VERSIONS,
    is_compatible,
    optional_fields,
    required_fields,
    validate_receipt_fields,
)
from assay.store import AssayStore, emit_receipt
import assay.store as store_mod


# ---------------------------------------------------------------------------
# Schema registry
# ---------------------------------------------------------------------------

class TestSchemaRegistry:
    """Version registry basics."""

    def test_current_version_is_3_0(self) -> None:
        assert CURRENT_VERSION == "3.0"

    def test_known_versions_includes_current(self) -> None:
        assert CURRENT_VERSION in KNOWN_VERSIONS

    def test_core_fields(self) -> None:
        assert CORE_FIELDS == frozenset({"receipt_id", "type", "timestamp"})

    def test_required_fields_3_0(self) -> None:
        assert required_fields("3.0") == CORE_FIELDS

    def test_optional_fields_3_0_includes_parent(self) -> None:
        opts = optional_fields("3.0")
        assert "parent_receipt_id" in opts
        assert "schema_version" in opts
        assert "seq" in opts

    def test_required_fields_unknown_version(self) -> None:
        """Unknown version falls back to core fields."""
        assert required_fields("99.9") == CORE_FIELDS

    def test_optional_fields_unknown_version(self) -> None:
        """Unknown version has no recognized optional fields."""
        assert optional_fields("99.9") == frozenset()


# ---------------------------------------------------------------------------
# Version compatibility
# ---------------------------------------------------------------------------

class TestVersionCompatibility:
    """is_compatible() checks."""

    def test_same_version(self) -> None:
        assert is_compatible("3.0", "3.0") is True

    def test_older_receipt_compatible(self) -> None:
        """Receipt 3.0 is compatible with expected 3.1."""
        assert is_compatible("3.0", "3.1") is True

    def test_newer_receipt_incompatible(self) -> None:
        """Receipt 3.1 is NOT compatible with expected 3.0."""
        assert is_compatible("3.1", "3.0") is False

    def test_major_bump_incompatible(self) -> None:
        """Different major version is never compatible."""
        assert is_compatible("4.0", "3.0") is False
        assert is_compatible("3.0", "4.0") is False

    def test_invalid_version_format(self) -> None:
        assert is_compatible("abc", "3.0") is False
        assert is_compatible("3.0", "xyz") is False
        assert is_compatible("3", "3.0") is False
        assert is_compatible("3.0.1", "3.0") is False


# ---------------------------------------------------------------------------
# Field validation
# ---------------------------------------------------------------------------

class TestFieldValidation:
    """validate_receipt_fields() checks."""

    def test_valid_receipt(self) -> None:
        receipt = {
            "receipt_id": "r_abc",
            "type": "model_call",
            "timestamp": "2026-01-01T00:00:00Z",
            "schema_version": "3.0",
        }
        assert validate_receipt_fields(receipt) == []

    def test_missing_receipt_id(self) -> None:
        receipt = {"type": "test", "timestamp": "2026-01-01T00:00:00Z"}
        errors = validate_receipt_fields(receipt)
        assert any("receipt_id" in e for e in errors)

    def test_missing_type(self) -> None:
        receipt = {"receipt_id": "r1", "timestamp": "2026-01-01T00:00:00Z"}
        errors = validate_receipt_fields(receipt)
        assert any("type" in e for e in errors)

    def test_missing_timestamp(self) -> None:
        receipt = {"receipt_id": "r1", "type": "test"}
        errors = validate_receipt_fields(receipt)
        assert any("timestamp" in e for e in errors)

    def test_explicit_version_override(self) -> None:
        """Explicit version parameter overrides receipt's schema_version."""
        receipt = {
            "receipt_id": "r1",
            "type": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "schema_version": "3.0",
        }
        # Should pass with any version since core fields are present
        assert validate_receipt_fields(receipt, version="99.9") == []

    def test_empty_receipt(self) -> None:
        errors = validate_receipt_fields({})
        assert len(errors) == 3  # All 3 core fields missing


# ---------------------------------------------------------------------------
# parent_receipt_id in emit_receipt
# ---------------------------------------------------------------------------

class TestParentReceiptId:
    """parent_receipt_id flows through emit_receipt correctly."""

    def test_parent_included_when_provided(self, tmp_path: Path, monkeypatch) -> None:
        """parent_receipt_id appears in emitted receipt."""
        monkeypatch.setattr(store_mod, "_default_store", AssayStore(base_dir=tmp_path))
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setattr(store_mod, "_seq_trace_id", None)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_parent_test")

        r = emit_receipt("model_call", {"model": "gpt-4"},
                         parent_receipt_id="r_parent_abc")
        assert r["parent_receipt_id"] == "r_parent_abc"

    def test_parent_absent_when_not_provided(self, tmp_path: Path, monkeypatch) -> None:
        """parent_receipt_id is NOT in receipt when not specified."""
        monkeypatch.setattr(store_mod, "_default_store", AssayStore(base_dir=tmp_path))
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setattr(store_mod, "_seq_trace_id", None)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_no_parent")

        r = emit_receipt("model_call", {"model": "gpt-4"})
        assert "parent_receipt_id" not in r

    def test_parent_persisted_to_jsonl(self, tmp_path: Path, monkeypatch) -> None:
        """parent_receipt_id round-trips through JSONL storage."""
        store = AssayStore(base_dir=tmp_path)
        monkeypatch.setattr(store_mod, "_default_store", store)
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setattr(store_mod, "_seq_trace_id", None)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_persist")

        emit_receipt("model_call", {"model": "gpt-4"},
                     parent_receipt_id="r_parent_xyz")

        entries = store.read_trace("trace_persist")
        assert len(entries) == 1
        assert entries[0]["parent_receipt_id"] == "r_parent_xyz"

    def test_causal_chain_two_receipts(self, tmp_path: Path, monkeypatch) -> None:
        """Two receipts linked by parent_receipt_id form a causal chain."""
        store = AssayStore(base_dir=tmp_path)
        monkeypatch.setattr(store_mod, "_default_store", store)
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setattr(store_mod, "_seq_trace_id", None)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_chain")

        r1 = emit_receipt("model_call", {"model": "gpt-4"})
        r2 = emit_receipt("guardian_verdict", {"verdict": "allow"},
                          parent_receipt_id=r1["receipt_id"])

        assert r2["parent_receipt_id"] == r1["receipt_id"]

        entries = store.read_trace("trace_chain")
        assert len(entries) == 2
        assert entries[1]["parent_receipt_id"] == entries[0]["receipt_id"]

    def test_causal_chain_three_deep(self, tmp_path: Path, monkeypatch) -> None:
        """Three-receipt chain: call -> verdict -> escalation."""
        store = AssayStore(base_dir=tmp_path)
        monkeypatch.setattr(store_mod, "_default_store", store)
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setattr(store_mod, "_seq_trace_id", None)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_deep")

        r1 = emit_receipt("model_call", {"model": "gpt-4"})
        r2 = emit_receipt("guardian_verdict", {"verdict": "deny"},
                          parent_receipt_id=r1["receipt_id"])
        r3 = emit_receipt("escalation", {"reason": "denied"},
                          parent_receipt_id=r2["receipt_id"])

        # Walk the chain backward
        entries = store.read_trace("trace_deep")
        chain: dict[str, str] = {}
        for e in entries:
            pid = e.get("parent_receipt_id")
            if pid:
                chain[e["receipt_id"]] = pid

        assert chain[r3["receipt_id"]] == r2["receipt_id"]
        assert chain[r2["receipt_id"]] == r1["receipt_id"]
        assert r1["receipt_id"] not in chain  # root has no parent

    def test_parent_does_not_overwrite_data(self, tmp_path: Path, monkeypatch) -> None:
        """parent_receipt_id in kwarg doesn't collide with data dict."""
        store = AssayStore(base_dir=tmp_path)
        monkeypatch.setattr(store_mod, "_default_store", store)
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setattr(store_mod, "_seq_trace_id", None)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_no_collide")

        r = emit_receipt("test", {"model": "gpt-4", "extra": "value"},
                         parent_receipt_id="r_parent")
        assert r["parent_receipt_id"] == "r_parent"
        assert r["model"] == "gpt-4"
        assert r["extra"] == "value"

    def test_backward_compat_no_parent(self, tmp_path: Path, monkeypatch) -> None:
        """Receipts without parent_receipt_id are still valid."""
        store = AssayStore(base_dir=tmp_path)
        monkeypatch.setattr(store_mod, "_default_store", store)
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setattr(store_mod, "_seq_trace_id", None)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_compat")

        r = emit_receipt("model_call", {"model": "gpt-4"})
        errors = validate_receipt_fields(r)
        assert errors == []
