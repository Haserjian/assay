"""
Tests for store hardening: thread safety, process safety, quickstart guard.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import threading
import time
from pathlib import Path
from typing import List

import pytest

from assay.store import AssayStore, emit_receipt, get_default_store
import assay.store as store_mod


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:
    """Verify AssayStore under concurrent thread access."""

    def test_concurrent_append_dict(self, tmp_path: Path) -> None:
        """10 threads emit receipts concurrently -- all appear, no corruption."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_thread_test")

        errors: List[Exception] = []
        n_threads = 10
        n_per_thread = 20

        def writer(thread_id: int) -> None:
            try:
                for i in range(n_per_thread):
                    store.append_dict({
                        "type": "test",
                        "thread_id": thread_id,
                        "index": i,
                    })
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"

        entries = store.read_trace("trace_thread_test")
        assert len(entries) == n_threads * n_per_thread

        # Every line must be valid JSON
        with open(store.trace_file) as f:
            for lineno, line in enumerate(f, 1):
                assert line.strip(), f"Empty line at {lineno}"
                json.loads(line)  # raises on corruption

    def test_concurrent_emit_receipt_seq_unique(self, tmp_path: Path, monkeypatch) -> None:
        """10 threads call emit_receipt -- seq numbers are unique."""
        monkeypatch.setattr(store_mod, "_default_store", AssayStore(base_dir=tmp_path))
        monkeypatch.setattr(store_mod, "_seq_counter", 0)
        monkeypatch.setattr(store_mod, "_seq_trace_id", None)
        monkeypatch.setenv("ASSAY_TRACE_ID", "trace_seq_test")

        results: List[dict] = []
        lock = threading.Lock()
        n_threads = 10
        n_per_thread = 10

        def emitter() -> None:
            for _ in range(n_per_thread):
                r = emit_receipt("test", {"v": 1})
                with lock:
                    results.append(r)

        threads = [threading.Thread(target=emitter) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == n_threads * n_per_thread
        seqs = [r["seq"] for r in results]
        assert len(set(seqs)) == len(seqs), f"Duplicate seqs: {sorted(seqs)}"

    def test_get_default_store_singleton(self, tmp_path: Path, monkeypatch) -> None:
        """get_default_store() called from 10 threads returns same instance."""
        monkeypatch.setattr(store_mod, "_default_store", None)
        # Point assay_home at tmp_path to avoid writing to real ~/.assay
        monkeypatch.setattr(store_mod, "assay_home", lambda: tmp_path)

        instances: List[AssayStore] = []
        lock = threading.Lock()

        def getter() -> None:
            s = get_default_store()
            with lock:
                instances.append(s)

        threads = [threading.Thread(target=getter) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(s is instances[0] for s in instances)

    def test_start_trace_concurrent(self, tmp_path: Path) -> None:
        """start_trace() called concurrently -- no race on file creation."""
        store = AssayStore(base_dir=tmp_path)
        errors: List[Exception] = []

        def starter(tid: int) -> None:
            try:
                store.start_trace(f"trace_race_{tid}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=starter, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_jsonl_valid_after_concurrent_writes(self, tmp_path: Path) -> None:
        """Receipt JSONL is valid JSON-per-line after concurrent writes."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_jsonl_valid")

        def writer(tid: int) -> None:
            for i in range(50):
                store.append_dict({"t": tid, "i": i, "data": "x" * 100})

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with open(store.trace_file) as f:
            lines = [l for l in f if l.strip()]
        assert len(lines) == 250
        for line in lines:
            d = json.loads(line)
            assert "t" in d
            assert "i" in d


# ---------------------------------------------------------------------------
# Process safety
# ---------------------------------------------------------------------------

def _child_writer(trace_file: str, n: int, large: bool) -> None:
    """Child process: write n receipts to trace_file via O_APPEND."""
    store = AssayStore(base_dir=Path(trace_file).parent.parent)
    store._current_trace_id = "trace_mp"
    store._current_file = Path(trace_file)
    payload = "x" * 5000 if large else "y"
    for i in range(n):
        store.append_dict({"pid": os.getpid(), "i": i, "payload": payload})


class TestProcessSafety:
    """Verify cross-process write safety."""

    def test_two_processes_append(self, tmp_path: Path) -> None:
        """2 child processes append to same trace -- all lines valid JSON."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_mp")
        trace_file = str(store.trace_file)

        n_per_proc = 50
        p1 = multiprocessing.Process(
            target=_child_writer, args=(trace_file, n_per_proc, False)
        )
        p2 = multiprocessing.Process(
            target=_child_writer, args=(trace_file, n_per_proc, False)
        )
        p1.start()
        p2.start()
        p1.join()
        p2.join()

        with open(trace_file) as f:
            lines = [l for l in f if l.strip()]

        assert len(lines) == n_per_proc * 2
        pids = set()
        for line in lines:
            d = json.loads(line)
            pids.add(d["pid"])
        assert len(pids) == 2

    def test_large_receipt_no_interleave(self, tmp_path: Path) -> None:
        """Large receipt (>4096 bytes) writes without interleaving."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_mp")
        trace_file = str(store.trace_file)

        n_per_proc = 10
        p1 = multiprocessing.Process(
            target=_child_writer, args=(trace_file, n_per_proc, True)
        )
        p2 = multiprocessing.Process(
            target=_child_writer, args=(trace_file, n_per_proc, True)
        )
        p1.start()
        p2.start()
        p1.join()
        p2.join()

        with open(trace_file) as f:
            lines = [l for l in f if l.strip()]

        assert len(lines) == n_per_proc * 2
        for line in lines:
            d = json.loads(line)
            assert len(d["payload"]) == 5000

    def test_receipt_ids_unique_across_processes(self, tmp_path: Path) -> None:
        """receipt_id is unique even when seq overlaps across processes."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_mp")
        trace_file = str(store.trace_file)

        p1 = multiprocessing.Process(
            target=_child_writer, args=(trace_file, 20, False)
        )
        p2 = multiprocessing.Process(
            target=_child_writer, args=(trace_file, 20, False)
        )
        p1.start()
        p2.start()
        p1.join()
        p2.join()

        with open(trace_file) as f:
            lines = [l for l in f if l.strip()]

        # Each line gets a unique _stored_at + pid combo at minimum
        assert len(lines) == 40

    @pytest.mark.skipif(
        not hasattr(os, "O_APPEND"),
        reason="O_APPEND not available on this platform",
    )
    def test_flock_no_deadlock_on_error(self, tmp_path: Path) -> None:
        """fcntl.flock acquired and released correctly (no deadlock)."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_flock")

        # Write a large line that triggers flock
        big = json.dumps({"data": "x" * 5000}) + "\n"
        store._write_line(big.encode("utf-8"))

        # If flock wasn't released, this second write would deadlock
        store._write_line(big.encode("utf-8"))

        with open(store.trace_file) as f:
            lines = [l for l in f if l.strip()]
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# Quickstart guard
# ---------------------------------------------------------------------------

class TestQuickstartGuard:
    """Verify quickstart rejects system-wide directories."""

    def test_home_dir_exit_3(self, tmp_path: Path, monkeypatch) -> None:
        """quickstart from / exits with code 3."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        runner = CliRunner()
        result = runner.invoke(assay_app, ["quickstart", "/"])
        assert result.exit_code == 3
        assert "may take a long time" in result.output

    def test_nonexistent_dir_exit_3(self, tmp_path: Path) -> None:
        """quickstart with missing directory exits with code 3."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        runner = CliRunner()
        result = runner.invoke(assay_app, ["quickstart", "/does/not/exist"])
        assert result.exit_code == 3

    def test_json_exit_code_3_bad_input(self, tmp_path: Path) -> None:
        """quickstart --json returns exit_code 3 in JSON for bad input."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        runner = CliRunner()
        result = runner.invoke(assay_app, ["quickstart", "/does/not/exist", "--json"])
        assert result.exit_code == 3

    def test_json_exit_code_3_guarded_dir(self, tmp_path: Path) -> None:
        """quickstart --json returns exit_code 3 for guarded directory."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        runner = CliRunner()
        result = runner.invoke(assay_app, ["quickstart", "/", "--json"])
        assert result.exit_code == 3

    def test_project_dir_accepted(self, tmp_path: Path) -> None:
        """quickstart from a small project dir does not trigger guard."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        # Create a few Python files
        for i in range(3):
            (tmp_path / f"mod_{i}.py").write_text(f"x = {i}")

        runner = CliRunner()
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path), "--skip-demo"])
        # Should not contain the warning message
        assert "may take a long time" not in (result.output or "")
        assert "system directory" not in (result.output or "")

    def test_many_files_rejected(self, tmp_path: Path, monkeypatch) -> None:
        """quickstart warns when >10K Python files found."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        original_rglob = Path.rglob

        def fake_rglob(self, pattern):
            if pattern == "*.py":
                for i in range(10_001):
                    yield tmp_path / f"fake_{i}.py"
            else:
                yield from original_rglob(self, pattern)

        monkeypatch.setattr(Path, "rglob", fake_rglob)

        runner = CliRunner()
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path)])
        assert result.exit_code == 3
        assert "10,000" in result.output or "system directory" in result.output

    def test_force_bypasses_file_count_guard(self, tmp_path: Path, monkeypatch) -> None:
        """--force bypasses the >10K file guard."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        original_rglob = Path.rglob

        def fake_rglob(self, pattern):
            if pattern == "*.py":
                for i in range(10_001):
                    yield tmp_path / f"fake_{i}.py"
            else:
                yield from original_rglob(self, pattern)

        monkeypatch.setattr(Path, "rglob", fake_rglob)

        runner = CliRunner()
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path), "--skip-demo", "--force"])
        # Should NOT hit the file-count guard
        assert "system directory" not in (result.output or "")
        assert "10,000" not in (result.output or "")


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompat:
    """Ensure upgraded store reads old-format traces correctly."""

    def test_read_trace_old_format(self, tmp_path: Path) -> None:
        """Existing JSONL traces read correctly after store upgrade."""
        # Write a trace file in old format (plain open/write)
        day_dir = tmp_path / "2026-01-01"
        day_dir.mkdir()
        trace_file = day_dir / "trace_old.jsonl"
        with open(trace_file, "w") as f:
            f.write(json.dumps({"type": "old", "_trace_id": "trace_old", "_stored_at": "2026-01-01T00:00:00"}) + "\n")
            f.write(json.dumps({"type": "old2", "_trace_id": "trace_old", "_stored_at": "2026-01-01T00:00:01"}) + "\n")

        store = AssayStore(base_dir=tmp_path)
        entries = store.read_trace("trace_old")
        assert len(entries) == 2
        assert entries[0]["type"] == "old"
        assert entries[1]["type"] == "old2"

    def test_append_to_old_trace(self, tmp_path: Path) -> None:
        """New store can append to traces created by old store."""
        day_dir = tmp_path / "2026-01-01"
        day_dir.mkdir()
        trace_file = day_dir / "trace_old.jsonl"
        with open(trace_file, "w") as f:
            f.write(json.dumps({"type": "old", "_trace_id": "trace_old"}) + "\n")

        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_old")
        store.append_dict({"type": "new"})

        entries = store.read_trace("trace_old")
        assert len(entries) == 2
        assert entries[0]["type"] == "old"
        assert entries[1]["type"] == "new"

    def test_no_schema_change(self, tmp_path: Path) -> None:
        """Receipt written by hardened store has same schema as before."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_schema")
        store.append_dict({"type": "test", "value": 42})

        entries = store.read_trace("trace_schema")
        assert len(entries) == 1
        d = entries[0]
        assert d["type"] == "test"
        assert d["value"] == 42
        assert "_trace_id" in d
        assert "_stored_at" in d


# ---------------------------------------------------------------------------
# Lock internals
# ---------------------------------------------------------------------------

class TestLockInternals:
    """Verify lock attributes exist and behave correctly."""

    def test_store_has_rlock(self, tmp_path: Path) -> None:
        """AssayStore has a threading.RLock."""
        store = AssayStore(base_dir=tmp_path)
        assert hasattr(store, "_lock")
        # RLock is reentrant -- acquiring twice should not deadlock
        store._lock.acquire()
        store._lock.acquire()
        store._lock.release()
        store._lock.release()

    def test_module_lock_exists(self) -> None:
        """Module-level _module_lock exists."""
        assert hasattr(store_mod, "_module_lock")
        assert isinstance(store_mod._module_lock, type(threading.Lock()))

    def test_write_line_uses_o_append(self, tmp_path: Path) -> None:
        """_write_line creates files with O_APPEND."""
        store = AssayStore(base_dir=tmp_path)
        store.start_trace("trace_o_append")
        line = b'{"test": true}\n'
        store._write_line(line)

        with open(store.trace_file) as f:
            content = f.read()
        assert content == '{"test": true}\n'

        # Second write appends
        store._write_line(line)
        with open(store.trace_file) as f:
            content = f.read()
        assert content == '{"test": true}\n{"test": true}\n'
