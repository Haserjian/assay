"""
MCP Notary Proxy v0: transparent stdio proxy with receipt emission.

Sits between an MCP client and server, intercepts tools/call requests,
and emits one MCPToolCallReceipt per tool invocation. All other JSON-RPC
messages are forwarded unchanged.

Supports both MCP stdio framing styles:
  - NDJSON (newline-delimited JSON)
  - Content-Length framed (LSP-style headers)

v0 scope:
  - stdio transport only
  - tools/call interception only
  - audit profile only (no policy enforcement)
  - privacy-by-default: args/results hashed (SHA-256 of JCS)
  - auto-pack on clean session end
  - session trace on crash (no crash-pack yet)

Usage:
    proxy = MCPProxy(server_id="my-server")
    await proxy.run(["python", "my_server.py"])
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Receipt helpers
# ---------------------------------------------------------------------------

def _jcs_sha256(obj: Any) -> str:
    """SHA-256 of JSON Canonical form (sorted keys, no whitespace)."""
    canonical = json.dumps(obj, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    """UTC ISO-8601 timestamp with milliseconds."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Dual-format message reader (NDJSON + Content-Length)
# ---------------------------------------------------------------------------

async def read_message(reader: asyncio.StreamReader) -> Optional[Tuple[bytes, Dict[str, Any]]]:
    """Read one JSON-RPC message from a stream, auto-detecting framing.

    Supports:
      - Content-Length framing: "Content-Length: N\\r\\n...\\r\\n<N bytes>"
      - NDJSON: one JSON object per line, terminated by \\n

    Returns (raw_bytes, parsed_dict) or None on EOF/error.
    raw_bytes is the complete wire representation for transparent forwarding.
    """
    # Peek at the first byte to detect framing style
    try:
        peek = await reader.read(1)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None
    if not peek:
        return None

    if peek in (b"C", b"c"):
        # Likely Content-Length header -- read until we get the full header
        header_line = peek + await reader.readline()
        header_str = header_line.decode("utf-8", errors="replace").strip()

        # Parse Content-Length value
        if not header_str.lower().startswith("content-length:"):
            # Not a Content-Length header -- treat as NDJSON fragment
            rest = await reader.readline()
            full_line = header_line + rest
            return _try_parse_line(full_line)

        try:
            content_length = int(header_str.split(":", 1)[1].strip())
        except (ValueError, IndexError):
            return None

        # Read remaining headers until empty line (\r\n\r\n)
        all_headers = header_line
        while True:
            line = await reader.readline()
            if not line:
                return None
            all_headers += line
            if line in (b"\r\n", b"\n"):
                break

        # Read exactly content_length bytes
        try:
            body = await reader.readexactly(content_length)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return None

        # Build raw wire bytes for forwarding
        raw = all_headers + body
        try:
            parsed = json.loads(body)
            return (raw, parsed)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return (raw, None)
    else:
        # NDJSON: read the rest of the line
        rest = await reader.readline()
        full_line = peek + rest
        return _try_parse_line(full_line)


def _try_parse_line(line: bytes) -> Optional[Tuple[bytes, Optional[Dict[str, Any]]]]:
    """Parse a line as JSON. Returns (raw_bytes, parsed) or None on empty."""
    stripped = line.strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped)
        return (line, parsed)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Forward non-JSON lines transparently
        return (line, None)


def write_message_framed(data: bytes, writer: Any, framing: str) -> None:
    """Write a message using the specified framing style.

    For transparent proxying, we always forward raw bytes unchanged.
    This function is only used if we ever need to synthesize messages.
    """
    if framing == "content-length":
        header = f"Content-Length: {len(data)}\r\n\r\n".encode("utf-8")
        writer.write(header + data)
    else:
        writer.write(data)


# ---------------------------------------------------------------------------
# Compat: keep parse_jsonrpc_line for tests and internal use
# ---------------------------------------------------------------------------

def parse_jsonrpc_line(line: bytes) -> Optional[Dict[str, Any]]:
    """Try to parse a line as a JSON-RPC message. Returns None on failure."""
    stripped = line.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def is_tool_call_request(msg: Dict[str, Any]) -> bool:
    """Check if this is a tools/call JSON-RPC request."""
    return (
        msg.get("method") == "tools/call"
        and "id" in msg
        and "params" in msg
    )


def is_response(msg: Dict[str, Any]) -> bool:
    """Check if this is a JSON-RPC response (has result or error, has id, no method)."""
    return (
        "id" in msg
        and "method" not in msg
        and ("result" in msg or "error" in msg)
    )


# ---------------------------------------------------------------------------
# MCP Proxy
# ---------------------------------------------------------------------------

class MCPProxy:
    """Transparent MCP stdio proxy with receipt emission.

    Spawns an upstream MCP server as a subprocess. Bridges stdin/stdout
    between the client (our stdin/stdout) and the server process.
    Intercepts tools/call requests and their responses, emitting one
    MCPToolCallReceipt per round-trip.

    Handles both NDJSON and Content-Length framed messages transparently.
    """

    def __init__(
        self,
        *,
        audit_dir: str = ".assay/mcp",
        server_id: Optional[str] = None,
        store_args: bool = False,
        store_results: bool = False,
        auto_pack: bool = True,
        json_output: bool = False,
    ):
        self.audit_dir = Path(audit_dir)
        self.server_id = server_id or "unknown"
        self.store_args = store_args
        self.store_results = store_results
        self.auto_pack = auto_pack
        self.json_output = json_output

        self.session_id = f"mcp_{uuid.uuid4().hex[:16]}"
        self.trace_id = f"mcp_{self.session_id}_{int(time.time())}"
        self.pending: Dict[Any, Dict[str, Any]] = {}  # request_id -> pending info
        self.receipts: List[Dict[str, Any]] = []
        self.seq = 0
        self._shutting_down = False

    async def run(self, upstream_cmd: List[str]) -> int:
        """Run the proxy. Returns exit code."""
        if not upstream_cmd:
            return 3  # bad input

        # Set trace ID so emit_receipt picks it up
        os.environ["ASSAY_TRACE_ID"] = self.trace_id

        # Ensure audit dir exists
        self.audit_dir.mkdir(parents=True, exist_ok=True)

        proc = await asyncio.create_subprocess_exec(
            *upstream_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Set up signal handlers for graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda s=sig: self._handle_signal(s, proc))

        session_complete = True
        try:
            # Create tasks so we can cancel client_to_server when server exits
            c2s_task = asyncio.create_task(self._client_to_server(proc))
            s2c_task = asyncio.create_task(self._server_to_client(proc))
            stderr_task = asyncio.create_task(self._forward_stderr(proc))

            # Wait for server-to-client to finish (server closed stdout).
            # Then cancel client-to-server (stdin reader) to avoid hang.
            done, _ = await asyncio.wait(
                [s2c_task, c2s_task, stderr_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # If server-to-client finished, cancel client-to-server
            if s2c_task in done:
                c2s_task.cancel()
                stderr_task.cancel()
            elif c2s_task in done:
                # Client closed stdin -- wait briefly for server to finish
                try:
                    await asyncio.wait_for(s2c_task, timeout=5.0)
                except asyncio.TimeoutError:
                    s2c_task.cancel()
                stderr_task.cancel()

            # Suppress CancelledError from cancelled tasks
            for t in [c2s_task, s2c_task, stderr_task]:
                if not t.done():
                    t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass

        except Exception:
            session_complete = False
        finally:
            # Wait for process to finish
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

            # P0 fix: non-zero returncode = not a clean session
            if proc.returncode is not None and proc.returncode != 0:
                session_complete = False

        # Persist session trace
        self._write_session_trace(session_complete)

        # Auto-pack on clean end
        if session_complete and self.auto_pack and self.receipts:
            return self._build_pack()

        return 0 if session_complete else 2

    def _handle_signal(self, sig: signal.Signals, proc: asyncio.subprocess.Process) -> None:
        """Handle SIGINT/SIGTERM: signal upstream and start shutdown."""
        if self._shutting_down:
            return
        self._shutting_down = True
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass

    # -----------------------------------------------------------------------
    # Forwarding loops (dual-format: NDJSON + Content-Length)
    # -----------------------------------------------------------------------

    async def _client_to_server(self, proc: asyncio.subprocess.Process) -> None:
        """Read from our stdin, inspect tools/call, forward to server."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        while not self._shutting_down:
            result = await read_message(reader)
            if result is None:
                break

            raw, msg = result
            if msg and is_tool_call_request(msg):
                self._on_tool_call_request(msg)

            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.write(raw)
                await proc.stdin.drain()

        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.close()

    async def _server_to_client(self, proc: asyncio.subprocess.Process) -> None:
        """Read from server stdout, inspect responses, forward to client."""
        while not self._shutting_down:
            result = await read_message(proc.stdout)
            if result is None:
                break

            raw, msg = result
            if msg and is_response(msg):
                req_id = msg.get("id")
                if req_id in self.pending:
                    self._on_tool_call_response(req_id, msg)

            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()

    async def _forward_stderr(self, proc: asyncio.subprocess.Process) -> None:
        """Forward server stderr to our stderr."""
        while not self._shutting_down:
            line = await proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    # -----------------------------------------------------------------------
    # Tool call tracking + receipt emission
    # -----------------------------------------------------------------------

    def _on_tool_call_request(self, msg: Dict[str, Any]) -> None:
        """Record a pending tool call request."""
        req_id = msg["id"]
        params = msg.get("params", {})
        self.pending[req_id] = {
            "tool_name": params.get("name", "unknown"),
            "arguments": params.get("arguments", {}),
            "request_observed_at": _now_iso(),
            "mcp_request_id": req_id,
        }

    def _on_tool_call_response(self, req_id: Any, msg: Dict[str, Any]) -> None:
        """Match a response to a pending request and emit a receipt."""
        pending = self.pending.pop(req_id, None)
        if not pending:
            return

        response_observed_at = _now_iso()
        arguments = pending["arguments"]
        tool_name = pending["tool_name"]

        # Determine outcome
        is_error = False
        result_obj = None
        if "error" in msg:
            outcome = "error"
            is_error = True
            result_obj = msg["error"]
        else:
            result_obj = msg.get("result", {})
            # MCP result has isError flag in content
            if isinstance(result_obj, dict) and result_obj.get("isError"):
                outcome = "error"
                is_error = True
            else:
                outcome = "forwarded"

        # Compute duration
        req_time = pending["request_observed_at"]
        try:
            from datetime import datetime, timezone
            t0 = datetime.fromisoformat(req_time.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(response_observed_at.replace("Z", "+00:00"))
            duration_ms = round((t1 - t0).total_seconds() * 1000, 1)
        except Exception:
            duration_ms = 0

        receipt = self._mint_receipt(
            tool_name=tool_name,
            arguments=arguments,
            result_obj=result_obj,
            outcome=outcome,
            is_error=is_error,
            duration_ms=duration_ms,
            request_observed_at=pending["request_observed_at"],
            response_observed_at=response_observed_at,
            mcp_request_id=pending["mcp_request_id"],
        )

        self.receipts.append(receipt)

        # Emit to store
        self._emit_to_store(receipt)

    def _mint_receipt(
        self,
        *,
        tool_name: str,
        arguments: Dict[str, Any],
        result_obj: Any,
        outcome: str,
        is_error: bool,
        duration_ms: float,
        request_observed_at: str,
        response_observed_at: str,
        mcp_request_id: Any,
    ) -> Dict[str, Any]:
        """Create an MCPToolCallReceipt."""
        receipt_id = f"mtc_{uuid.uuid4().hex[:16]}"
        now = _now_iso()
        seq = self.seq
        self.seq += 1

        receipt: Dict[str, Any] = {
            "type": "mcp_tool_call",
            "receipt_id": receipt_id,
            "timestamp": now,
            "schema_version": "3.0",
            "seq": seq,

            # Correlation
            "invocation_id": f"inv_{uuid.uuid4().hex[:16]}",
            "session_id": self.session_id,
            "parent_receipt_id": None,

            # MCP context
            "server_id": self.server_id,
            "server_transport": "stdio",
            "tool_name": tool_name,
            "mcp_request_id": mcp_request_id,

            # Phase timing
            "request_observed_at": request_observed_at,
            "policy_decided_at": None,  # v0: no policy
            "response_observed_at": response_observed_at,

            # Arguments (privacy-by-default)
            "arguments_hash": _jcs_sha256(arguments),
            "arguments_content": arguments if self.store_args else None,

            # Result (privacy-by-default)
            "result_hash": _jcs_sha256(result_obj) if result_obj is not None else None,
            "result_content": result_obj if self.store_results else None,
            "result_is_error": is_error,

            # Outcome
            "outcome": outcome,
            "duration_ms": duration_ms,

            # Policy (v0: no policy)
            "policy_verdict": "no_policy",
            "policy_ref": None,
            "policy_hash": None,

            # Integration
            "proxy_version": self._get_version(),
            "integration_source": "assay.mcp_proxy",
        }
        return receipt

    # -----------------------------------------------------------------------
    # Store + pack integration
    # -----------------------------------------------------------------------

    def _emit_to_store(self, receipt: Dict[str, Any]) -> None:
        """Emit receipt to AssayStore (best-effort)."""
        try:
            from assay.store import emit_receipt
            emit_receipt(
                type=receipt["type"],
                data={k: v for k, v in receipt.items()
                      if k not in ("type", "receipt_id", "timestamp",
                                   "schema_version", "seq", "parent_receipt_id")},
                receipt_id=receipt["receipt_id"],
                timestamp=receipt["timestamp"],
                schema_version=receipt["schema_version"],
                seq=receipt["seq"],
                parent_receipt_id=receipt.get("parent_receipt_id"),
            )
        except Exception:
            pass  # store integration is optional

    def _write_session_trace(self, session_complete: bool) -> None:
        """Write session receipts to JSONL file."""
        receipts_dir = self.audit_dir / "receipts"
        receipts_dir.mkdir(parents=True, exist_ok=True)

        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        trace_file = receipts_dir / f"session_{ts}.jsonl"

        with open(trace_file, "w", encoding="utf-8") as f:
            # Write session metadata as first line
            meta = {
                "type": "session_metadata",
                "session_id": self.session_id,
                "trace_id": self.trace_id,
                "server_id": self.server_id,
                "session_complete": session_complete,
                "receipt_count": len(self.receipts),
                "started_at": self.receipts[0]["request_observed_at"] if self.receipts else _now_iso(),
                "ended_at": _now_iso(),
            }
            f.write(json.dumps(meta, separators=(",", ":"), sort_keys=True) + "\n")

            for r in self.receipts:
                f.write(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n")

        return trace_file

    def _build_pack(self) -> int:
        """Build a proof pack from the session trace. Returns exit code."""
        try:
            from assay.proof_pack import build_proof_pack

            packs_dir = self.audit_dir / "packs"
            packs_dir.mkdir(parents=True, exist_ok=True)

            ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            pack_dir = packs_dir / f"proof_pack_{ts}"

            result_dir = build_proof_pack(
                self.trace_id,
                output_dir=pack_dir,
                mode="shadow",
            )

            if not self.json_output:
                sys.stderr.write(f"[assay mcp-proxy] Pack built: {result_dir}\n")

            return 0
        except Exception as e:
            sys.stderr.write(f"[assay mcp-proxy] Pack build failed: {e}\n")
            return 2

    @staticmethod
    def _get_version() -> str:
        """Get Assay version (best-effort)."""
        try:
            from assay import __version__
            return __version__
        except Exception:
            return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_proxy(
    upstream_cmd: List[str],
    *,
    audit_dir: str = ".assay/mcp",
    server_id: Optional[str] = None,
    store_args: bool = False,
    store_results: bool = False,
    auto_pack: bool = True,
    json_output: bool = False,
) -> int:
    """Run the MCP proxy synchronously. Returns exit code."""
    proxy = MCPProxy(
        audit_dir=audit_dir,
        server_id=server_id,
        store_args=store_args,
        store_results=store_results,
        auto_pack=auto_pack,
        json_output=json_output,
    )
    return asyncio.run(proxy.run(upstream_cmd))


__all__ = [
    "MCPProxy",
    "run_proxy",
    "read_message",
    "parse_jsonrpc_line",
    "is_tool_call_request",
    "is_response",
]
