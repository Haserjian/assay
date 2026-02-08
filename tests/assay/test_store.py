"""
Tests for Assay receipt storage.
"""
from __future__ import annotations

import json
from pathlib import Path


from assay.store import AssayStore, emit_receipt, generate_trace_id


class TestGenerateTraceId:
    """Tests for trace ID generation."""

    def test_format(self) -> None:
        """Trace ID has expected format."""
        trace_id = generate_trace_id()
        assert trace_id.startswith("trace_")
        # Format: trace_YYYYMMDDTHHMMSS_xxxxxxxx
        parts = trace_id.split("_")
        assert len(parts) == 3
        assert len(parts[1]) == 15  # YYYYMMDDTHHMMSS
        assert len(parts[2]) == 8   # 8 hex chars

    def test_uniqueness(self) -> None:
        """Trace IDs are unique."""
        ids = [generate_trace_id() for _ in range(100)]
        assert len(set(ids)) == 100


class TestAssayStore:
    """Tests for AssayStore."""

    def test_start_trace_creates_directory(self, tmp_path: Path) -> None:
        """Starting a trace creates the date directory."""
        store = AssayStore(base_dir=tmp_path)
        trace_id = store.start_trace()

        assert trace_id is not None
        assert store.trace_file is not None
        assert store.trace_file.parent.exists()

    def test_append_dict(self, tmp_path: Path) -> None:
        """append_dict writes to trace file."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace()

        store.append_dict({"type": "test", "value": 42})

        # Read back
        with open(store.trace_file) as f:
            line = f.readline()
            data = json.loads(line)

        assert data["type"] == "test"
        assert data["value"] == 42
        assert "_trace_id" in data
        assert "_stored_at" in data

    def test_append_receipt(self, tmp_path: Path) -> None:
        """append writes Pydantic model to trace file."""
        from assay._receipts.domains.blockages import create_incompleteness_receipt

        store = AssayStore(base_dir=tmp_path)
        store.start_trace()

        receipt = create_incompleteness_receipt(
            undecidable_claim="test claim",
            missing_evidence=["evidence1"],
        )
        receipt_id = store.append(receipt)

        # Read back
        with open(store.trace_file) as f:
            line = f.readline()
            data = json.loads(line)

        assert data["receipt_type"] == "IncompletenessReceipt"
        assert data["undecidable_claim"] == "test claim"
        assert receipt_id == receipt.receipt_id

    def test_read_trace(self, tmp_path: Path) -> None:
        """read_trace retrieves stored entries."""
        store = AssayStore(base_dir=tmp_path)
        trace_id = store.start_trace()

        store.append_dict({"type": "entry1"})
        store.append_dict({"type": "entry2"})

        entries = store.read_trace(trace_id)

        assert len(entries) == 2
        assert entries[0]["type"] == "entry1"
        assert entries[1]["type"] == "entry2"

    def test_read_nonexistent_trace(self, tmp_path: Path) -> None:
        """read_trace returns empty list for unknown trace."""
        store = AssayStore(base_dir=tmp_path)
        entries = store.read_trace("nonexistent_trace")
        assert entries == []

    def test_list_traces(self, tmp_path: Path) -> None:
        """list_traces returns recent traces."""
        store = AssayStore(base_dir=tmp_path)

        # Create a few traces
        trace1 = store.start_trace()
        store.append_dict({"test": 1})

        trace2 = store.start_trace()
        store.append_dict({"test": 2})

        traces = store.list_traces()

        assert len(traces) >= 2
        trace_ids = [t["trace_id"] for t in traces]
        assert trace1 in trace_ids
        assert trace2 in trace_ids

    def test_list_traces_empty(self, tmp_path: Path) -> None:
        """list_traces returns empty list when no traces exist."""
        store = AssayStore(base_dir=tmp_path)
        traces = store.list_traces()
        assert traces == []


class TestGraceTracker:
    """Tests for GraceTracker with hysteresis."""

    def test_hysteresis_prevents_flicker(self) -> None:
        """Tracker doesn't enter grace on single passing check."""
        from assay.health import GraceTracker, GraceConfig

        tracker = GraceTracker(cfg=GraceConfig(window_size=3))

        # Single passing check shouldn't trigger grace
        result = tracker.update(0.85, 0.15, -0.01, 0.25, 0.10)
        assert result is False  # Not in grace yet

    def test_enters_grace_after_window(self) -> None:
        """Tracker enters grace after window_size consecutive passes."""
        from assay.health import GraceTracker, GraceConfig

        tracker = GraceTracker(cfg=GraceConfig(window_size=3))

        # Three consecutive passes
        tracker.update(0.85, 0.15, -0.01, 0.25, 0.10)
        tracker.update(0.85, 0.15, -0.01, 0.25, 0.10)
        result = tracker.update(0.85, 0.15, -0.01, 0.25, 0.10)

        assert result is True
        assert tracker.in_grace is True

    def test_stays_in_grace_on_single_fail(self) -> None:
        """Tracker stays in grace after single failing check."""
        from assay.health import GraceTracker, GraceConfig

        tracker = GraceTracker(cfg=GraceConfig(window_size=3))

        # Enter grace
        for _ in range(3):
            tracker.update(0.85, 0.15, -0.01, 0.25, 0.10)
        assert tracker.in_grace is True

        # Single fail shouldn't exit grace
        result = tracker.update(0.50, 0.50, 0.05, 0.10, 0.50)
        assert result is True  # Still in grace due to hysteresis

    def test_exits_grace_after_window_fails(self) -> None:
        """Tracker exits grace after window_size consecutive fails."""
        from assay.health import GraceTracker, GraceConfig

        tracker = GraceTracker(cfg=GraceConfig(window_size=3))

        # Enter grace
        for _ in range(3):
            tracker.update(0.85, 0.15, -0.01, 0.25, 0.10)
        assert tracker.in_grace is True

        # Three consecutive fails
        for _ in range(3):
            tracker.update(0.50, 0.50, 0.05, 0.10, 0.50)

        assert tracker.in_grace is False


class TestEmitReceipt:
    """Tests for the emit_receipt convenience function."""

    def _reset(self, tmp_path, monkeypatch):
        """Reset global state for each test."""
        import assay.store as store_mod

        monkeypatch.setattr(store_mod, "_default_store", AssayStore(base_dir=tmp_path))
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.delenv("ASSAY_TRACE_ID", raising=False)

    def test_basic_emit(self, tmp_path, monkeypatch):
        """emit_receipt writes to the store and returns the receipt."""
        self._reset(tmp_path, monkeypatch)

        receipt = emit_receipt("model_call", {"model": "gpt-4", "tokens": 500})

        assert receipt["type"] == "model_call"
        assert receipt["model"] == "gpt-4"
        assert receipt["tokens"] == 500
        assert receipt["receipt_id"].startswith("r_")
        assert receipt["schema_version"] == "3.0"
        assert receipt["seq"] == 0
        assert "timestamp" in receipt

    def test_picks_up_env_trace_id(self, tmp_path, monkeypatch):
        """emit_receipt uses ASSAY_TRACE_ID from environment."""
        import assay.store as store_mod

        store = AssayStore(base_dir=tmp_path)
        monkeypatch.setattr(store_mod, "_default_store", store)
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_from_env")

        emit_receipt("guardian_verdict", {"verdict": "allow"})

        entries = store.read_trace("trace_from_env")
        assert len(entries) == 1
        assert entries[0]["type"] == "guardian_verdict"
        assert entries[0]["verdict"] == "allow"

    def test_multiple_receipts_same_trace(self, tmp_path, monkeypatch):
        """Multiple emit_receipt calls append with auto-incrementing seq."""
        import assay.store as store_mod

        store = AssayStore(base_dir=tmp_path)
        monkeypatch.setattr(store_mod, "_default_store", store)
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_multi")

        emit_receipt("model_call", {"model": "gpt-4"})
        emit_receipt("guardian_verdict", {"verdict": "block"})
        emit_receipt("model_call", {"model": "gpt-4"})

        entries = store.read_trace("trace_multi")
        assert len(entries) == 3
        types = [e["type"] for e in entries]
        assert types == ["model_call", "guardian_verdict", "model_call"]
        seqs = [e["seq"] for e in entries]
        assert seqs == [0, 1, 2]

    def test_custom_fields(self, tmp_path, monkeypatch):
        """emit_receipt respects custom receipt_id, timestamp, seq."""
        self._reset(tmp_path, monkeypatch)

        receipt = emit_receipt(
            "model_call",
            {"model": "gpt-4"},
            receipt_id="custom_001",
            timestamp="2026-01-01T00:00:00Z",
            seq=42,
        )

        assert receipt["receipt_id"] == "custom_001"
        assert receipt["timestamp"] == "2026-01-01T00:00:00Z"
        assert receipt["seq"] == 42

    def test_explicit_seq_does_not_reset_counter(self, tmp_path, monkeypatch):
        """Explicit seq=42 advances counter past 42, next auto is 43."""
        self._reset(tmp_path, monkeypatch)

        r1 = emit_receipt("model_call", {"model": "gpt-4"}, seq=42)
        r2 = emit_receipt("model_call", {"model": "gpt-4"})

        assert r1["seq"] == 42
        assert r2["seq"] == 43
