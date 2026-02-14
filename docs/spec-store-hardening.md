# Store Hardening Spec

**Status**: Implementation spec
**Feature**: Thread-safe AND process-safe receipt writes, quickstart guard
**Prerequisite for**: MCP Receipt Layer, all concurrent workloads
**Priority**: FIRST -- blocks everything else

---

## Problem

The `AssayStore` has no thread or process safety:

1. `append_dict()` opens and writes without locks
2. Global `_seq_counter` is unprotected
3. Global `_default_store` is unprotected
4. `quickstart` scanning from `~` causes recursion/timeout on large dirs

MCP servers handle concurrent tool calls. Gunicorn/Uvicorn workers
fork processes. Multiple agents may write to the same trace file.
The store must not corrupt receipts under any concurrency model.

---

## Changes

### 1. Thread-safe store (in-process concurrency)

**File:** `src/assay/store.py`

```python
import threading

# Module-level lock for global state
_module_lock = threading.Lock()
_default_store: Optional["AssayStore"] = None
_seq_counter: int = 0
_seq_trace_id: Optional[str] = None


def get_default_store() -> "AssayStore":
    global _default_store
    with _module_lock:
        if _default_store is None:
            _default_store = AssayStore()
        return _default_store


class AssayStore:
    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            base_dir = assay_home()
        self.base_dir = Path(base_dir)
        self._current_trace_id: Optional[str] = None
        self._current_file: Optional[Path] = None
        self._lock = threading.RLock()  # Reentrant for nested calls

    def start_trace(self, trace_id: Optional[str] = None) -> str:
        with self._lock:
            # existing logic
            ...

    def append(self, receipt: BaseModel) -> str:
        with self._lock:
            # existing logic
            ...

    def append_dict(self, data: Dict[str, Any]) -> None:
        with self._lock:
            # existing logic -- delegates to _write_line()
            ...
```

**`emit_receipt()` protection:**

```python
def emit_receipt(...) -> Dict[str, Any]:
    global _seq_counter, _seq_trace_id
    store = get_default_store()

    with _module_lock:
        trace_id = os.environ.get("ASSAY_TRACE_ID")
        if store.trace_id is None:
            store.start_trace(trace_id)

        if seq is None:
            if trace_id != _seq_trace_id:
                _seq_counter = 0
                _seq_trace_id = trace_id
            seq = _seq_counter
            _seq_counter += 1

    # Build receipt dict (no lock needed -- local vars)
    receipt = {
        "receipt_id": receipt_id or f"r_{uuid.uuid4().hex[:12]}",
        "type": type,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "schema_version": schema_version,
        "seq": seq,
    }
    if data:
        receipt.update(data)

    # Write (store has its own lock)
    store.append_dict(receipt)
    return receipt
```

### 2. Process-safe append (cross-process concurrency)

`threading.Lock` does NOT protect Gunicorn/Uvicorn workers (separate
processes). Two layers of protection:

**Layer 1: Atomic POSIX write**

On POSIX systems, `write()` to a file opened with `O_APPEND` is atomic
for writes under `PIPE_BUF` (4096 bytes on Linux, 512 on older POSIX).
Each receipt JSON line is typically 200-800 bytes, well under this limit.

```python
def _write_line(self, line_bytes: bytes) -> None:
    """Write a single line atomically. Thread-lock must be held by caller."""
    fd = os.open(
        str(self._current_file),
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
        0o644,
    )
    try:
        os.write(fd, line_bytes)
    finally:
        os.close(fd)
```

**Layer 2: Advisory file lock for oversized writes**

If a receipt exceeds `PIPE_BUF` (e.g. with `store_prompts=True`), the
write is no longer guaranteed atomic. For these cases, use `fcntl.flock`:

```python
import fcntl
import sys

_PIPE_BUF = 4096 if sys.platform != "win32" else 512

def _write_line(self, line_bytes: bytes) -> None:
    """Write a single JSONL line. Atomic for lines < PIPE_BUF,
    flock-protected for larger lines."""
    fd = os.open(
        str(self._current_file),
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
        0o644,
    )
    try:
        if len(line_bytes) >= _PIPE_BUF:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.write(fd, line_bytes)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        else:
            # Under PIPE_BUF: O_APPEND guarantees atomicity
            os.write(fd, line_bytes)
    finally:
        os.close(fd)
```

**Windows fallback:** `fcntl` is POSIX-only. On Windows, always use
`msvcrt.locking` or fall back to thread-lock-only (Windows MCP servers
are rare enough that this is acceptable for v0).

```python
if sys.platform == "win32":
    def _write_line(self, line_bytes: bytes) -> None:
        # Windows: no O_APPEND atomicity guarantee, always lock
        with open(self._current_file, "ab") as f:
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, len(line_bytes))
            try:
                f.write(line_bytes)
            finally:
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, len(line_bytes))
```

**Seq counter in multi-process:** Each process gets its own `_seq_counter`.
Within a process, seq is monotonic. Across processes, seq values may
overlap. This is acceptable because `receipt_id` is the unique key,
not `seq`. The `seq` field is for ordering within a single writer --
proof pack build sorts by `(run_id, seq, receipt_id)` which handles
multi-writer correctly via the `receipt_id` tiebreaker.

**`append_dict()` final form:**

```python
def append_dict(self, data: Dict[str, Any]) -> None:
    with self._lock:
        if self._current_file is None:
            raise RuntimeError("No active trace -- call start_trace() first")

        data["_trace_id"] = self._current_trace_id
        data["_stored_at"] = datetime.now(timezone.utc).isoformat()
        line = json.dumps(data, separators=(",", ":")) + "\n"
        self._write_line(line.encode("utf-8"))
```

### 3. Quickstart scan guard

**Problem:** `assay quickstart` runs `assay scan <path>`. If `path` is
`~` or `/`, scanning traverses the entire filesystem.

**Fix in `commands.py` quickstart function:**

```python
QUICKSTART_MAX_FILES = 10_000
QUICKSTART_WARN_DIRS = {
    Path.home(),
    Path("/"),
    Path("/Users"),
    Path("/home"),
}

def quickstart_cmd(path: str = "."):
    scan_path = Path(path).resolve()

    # Guard: warn if scanning a huge/non-project directory
    if scan_path in QUICKSTART_WARN_DIRS:
        console.print(
            f"[yellow]Warning:[/] Scanning {scan_path} may take a long time.\n"
            f"Tip: run from your project directory instead:\n"
            f"  cd your-project && assay quickstart"
        )
        return

    # Guard: bail if too many files (counted with early-exit generator)
    file_count = 0
    for _ in scan_path.rglob("*.py"):
        file_count += 1
        if file_count > QUICKSTART_MAX_FILES:
            break
    if file_count > QUICKSTART_MAX_FILES:
        console.print(
            f"[yellow]Warning:[/] Found >{QUICKSTART_MAX_FILES:,} Python files. "
            f"This looks like a system directory, not a project.\n"
            f"Tip: cd into your project first."
        )
        return
```

### 4. Pack format version field

Add `pack_format_version` to manifests now, before format entropy grows:

```python
# In proof_pack.py, in the manifest builder
unsigned_manifest = {
    "pack_version": "1",
    "pack_format_version": "1.0",  # NEW: explicit format version
    "manifest_version": "3",
    ...
}
```

This field enables future schema migration: a verifier can check
`pack_format_version` and apply the right validation rules.

No migration logic yet -- just plant the field so every pack from now
on declares its format version.

---

## Test cases

### Thread safety

1. 10 threads emit receipts concurrently -- all receipts appear, no corruption
2. 10 threads emit to same trace -- seq numbers are unique and monotonic within each thread
3. `get_default_store()` called from 10 threads -- returns same instance
4. `start_trace()` called concurrently -- no race on file creation
5. Receipt JSONL file is valid JSON-per-line after concurrent writes

### Process safety

6. 2 child processes append to same trace file -- all lines valid JSON
7. Large receipt (>4096 bytes with `store_prompts=True`) writes without interleaving
8. Seq numbers may overlap across processes but `receipt_id` is unique
9. `fcntl.flock` acquired and released correctly (no deadlock on error path)

### Quickstart guard

10. `quickstart` from `~` prints warning and returns
11. `quickstart` from `/` prints warning and returns
12. `quickstart` from project dir with <100 files runs normally
13. `quickstart` from dir with >10K Python files warns (early exit, doesn't enumerate all)

### Pack format version

14. New packs include `pack_format_version: "1.0"`
15. Verification accepts packs with `pack_format_version`
16. Verification still accepts legacy packs without the field

### Backward compatibility

17. Existing JSONL traces read correctly after store upgrade
18. `read_trace()` handles both old-format and new-format lines
19. No change to receipt schema -- only store write mechanics change

---

## Exit criteria

- [ ] `AssayStore` uses `threading.RLock` on all write operations
- [ ] Global `_seq_counter` and `_default_store` protected by module lock
- [ ] `_write_line()` uses `O_APPEND` + `os.write()` for atomic small writes
- [ ] `_write_line()` uses `fcntl.flock` for writes >= PIPE_BUF
- [ ] Windows fallback uses `msvcrt.locking`
- [ ] Quickstart guard prevents scanning `~`, `/`, and dirs with >10K .py files
- [ ] `pack_format_version` present in all new manifests
- [ ] 19+ tests for thread/process safety, guards, and compat
- [ ] All existing 745 tests still pass
- [ ] No performance regression on single-threaded workloads (lock overhead < 1ms)
