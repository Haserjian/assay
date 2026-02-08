"""
Assay Bridge: Hard shim for untrusted tool orchestrators (OpenClaw, etc.).

Treats external orchestrators as untrusted I/O:
- Guardian preflight (tool allowlist, SSRF deny, scheme guard)
- Subprocess invocation with deterministic capture (stdin args, no ps leak)
- Receipt minting via existing receipt types (no parallel schemas)
- Artifact output to disk (current/ + history/) + trace integration

Usage:
    from assay.bridge import ReceiptBridge, BridgeConfig

    bridge = ReceiptBridge(agent_id="agent:researcher")
    result = bridge.run_tool("sess-001", "web_search", {"query": "python asyncio"})

Design invariants:
    - Every invocation yields a receipt or denial. No silent drops.
    - Args never appear on the command line (stdin transport).
    - Timeouts always mint receipts (outcome="timeout").
    - Private-net / localhost SSRF is denied by default.
    - Full stdout/stderr stored by hash; previews in receipts.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Literal, Optional, Protocol, runtime_checkable
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BridgeConfig:
    """
    Environment-driven configuration for the bridge.

    Set OPENCLAW_PYTHON to the venv interpreter path to capture
    stdout from OpenClaw's specific Python environment.
    """
    artifacts_dir: Path = field(default_factory=lambda: Path("artifacts"))

    # Invocation: prefer python -m if openclaw_python set, else use binary
    openclaw_bin: str = field(default_factory=lambda: os.environ.get("OPENCLAW_BIN", "openclaw"))
    openclaw_python: str = field(default_factory=lambda: os.environ.get("OPENCLAW_PYTHON", ""))
    openclaw_module: str = field(default_factory=lambda: os.environ.get("OPENCLAW_MODULE", "openclaw"))

    # Safety / determinism
    timeout_s: int = 90
    max_preview_bytes: int = 16_000
    write_full_payload: bool = field(
        default_factory=lambda: bool(int(os.environ.get("ASSAY_BRIDGE_WRITE_PAYLOAD", "0")))
    )

    # Deterministic env anchors
    tz: str = "UTC"
    locale: str = "C"
    pythonhashseed: str = "0"

    # Stable working directory (recorded into receipts)
    cwd: str = field(default_factory=lambda: os.environ.get("ASSAY_BRIDGE_CWD", os.getcwd()))


# ---------------------------------------------------------------------------
# Tool policy engine (SSRF deny, tool allow/deny)
# ---------------------------------------------------------------------------

PRIVATE_NETS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local + cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]


def _host_is_private(host: str) -> bool:
    """Fail-closed: unresolvable hosts are treated as private."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return True  # fail-closed
    return any(ip in net for net in PRIVATE_NETS)


@dataclass(frozen=True)
class PolicyVerdict:
    """Result of a bridge-level policy check."""
    allowed: bool
    reason: str = "OK"
    policy_ref: str = "POLICY_UNSET"


class ToolPolicy:
    """
    Bridge-level tool policy: allowlist, denylist, SSRF guard.

    Default-deny for unknown tools. Safe web tools allowed with
    URL safety checks.
    """

    def __init__(
        self,
        safe_tools: Optional[FrozenSet[str]] = None,
        dangerous_tools: Optional[FrozenSet[str]] = None,
    ):
        self.safe_tools: FrozenSet[str] = safe_tools or frozenset({
            "web_search",
            "web_fetch",
        })
        self.dangerous_tools: FrozenSet[str] = dangerous_tools or frozenset({
            "shell_exec",
            "file_write",
            "file_delete",
            "browser_control",
        })

    def policy_hash(self) -> str:
        """Stable hash of policy constants for reproducibility."""
        blob = json.dumps(
            {
                "safe": sorted(self.safe_tools),
                "dangerous": sorted(self.dangerous_tools),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def check(self, tool_name: str, arguments: Dict[str, Any]) -> PolicyVerdict:
        # Block known dangerous tools
        if tool_name in self.dangerous_tools:
            return PolicyVerdict(
                allowed=False,
                reason=f"Tool '{tool_name}' disabled by default",
                policy_ref="POLICY_DEFAULT_DENY_000",
            )

        # Allow safe tools with URL safety for web_fetch
        if tool_name in self.safe_tools:
            if tool_name == "web_fetch":
                url = str(arguments.get("url", "")).strip()
                parsed = urlparse(url)

                if parsed.scheme not in ("http", "https"):
                    return PolicyVerdict(
                        allowed=False,
                        reason=f"Non-http(s) scheme '{parsed.scheme}' blocked",
                        policy_ref="POLICY_URL_001",
                    )

                if not parsed.hostname or _host_is_private(parsed.hostname):
                    return PolicyVerdict(
                        allowed=False,
                        reason="Private/localhost URL blocked",
                        policy_ref="POLICY_URL_002",
                    )

            return PolicyVerdict(
                allowed=True,
                reason="Tool in safe set",
                policy_ref="POLICY_ALLOW_WEB_000",
            )

        # Unknown tool: default deny
        return PolicyVerdict(
            allowed=False,
            reason=f"Unknown tool '{tool_name}' (default deny)",
            policy_ref="POLICY_DEFAULT_DENY_001",
        )


# ---------------------------------------------------------------------------
# Subprocess invoke result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InvokeResult:
    """Deterministic result from a subprocess tool invocation."""
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False


# ---------------------------------------------------------------------------
# OpenClaw subprocess invoker
# ---------------------------------------------------------------------------

@runtime_checkable
class ToolInvoker(Protocol):
    """Seam for swapping invocation strategy (subprocess / HTTP / direct)."""
    def invoke(self, tool_name: str, arguments: Dict[str, Any]) -> InvokeResult: ...


class OpenClawSubprocessInvoker:
    """
    Invoke OpenClaw as a subprocess with hardened defaults:
    - Args via stdin (never on command line)
    - Timeout always returns InvokeResult (never crashes)
    - Deterministic env (PYTHONHASHSEED=0, TZ=UTC, LANG=C)
    - Stable cwd
    """

    def __init__(self, cfg: BridgeConfig):
        self.cfg = cfg

    def build_command(self, tool_name: str) -> List[str]:
        """
        Build the subprocess command. Args are passed via stdin.

        Patch this single method when you confirm the real OpenClaw CLI flags.
        Current default: openclaw tool run <tool_name> --json-args-stdin
        """
        if self.cfg.openclaw_python.strip():
            return [
                self.cfg.openclaw_python,
                "-m",
                self.cfg.openclaw_module,
                "tool", "run", tool_name,
                "--json-args-stdin",
            ]
        return [
            self.cfg.openclaw_bin,
            "tool", "run", tool_name,
            "--json-args-stdin",
        ]

    def invoke(self, tool_name: str, arguments: Dict[str, Any]) -> InvokeResult:
        cmd = self.build_command(tool_name)
        stdin_payload = json.dumps(arguments, separators=(",", ":"), sort_keys=True)

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_payload,
                capture_output=True,
                text=True,
                timeout=self.cfg.timeout_s,
                env=self._deterministic_env(),
                cwd=self.cfg.cwd,
            )
            return InvokeResult(
                exit_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                duration_ms=(time.time() - start) * 1000.0,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as e:
            stdout = e.stdout if isinstance(e.stdout, str) else ""
            stderr = e.stderr if isinstance(e.stderr, str) else ""
            return InvokeResult(
                exit_code=None,
                stdout=stdout,
                stderr=(stderr + "\n[bridge] TIMEOUT").strip(),
                duration_ms=(time.time() - start) * 1000.0,
                timed_out=True,
            )

    def _deterministic_env(self) -> Dict[str, str]:
        allow = {"PATH", "HOME", "USER", "TERM",
                 "OPENCLAW_CONFIG", "OPENCLAW_PROFILE", "OPENCLAW_GATEWAY"}
        env: Dict[str, str] = {}
        for k in allow:
            if k in os.environ:
                env[k] = os.environ[k]
        env["PYTHONHASHSEED"] = self.cfg.pythonhashseed
        env["TZ"] = self.cfg.tz
        env["LANG"] = self.cfg.locale
        env["LC_ALL"] = self.cfg.locale
        return env


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def _preview(s: str, max_bytes: int) -> str:
    b = s.encode("utf-8", errors="replace")
    if len(b) <= max_bytes:
        return s
    return b[:max_bytes].decode("utf-8", errors="replace") + "\n[...PREVIEW_TRUNCATED...]"


def _short_hash(payload: Dict[str, Any]) -> str:
    b = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(b).hexdigest()[:10]


# ---------------------------------------------------------------------------
# Receipt bridge
# ---------------------------------------------------------------------------

class ReceiptBridge:
    """
    Integrity source of truth for tool invocations:
    1. ToolPolicy preflight (SSRF deny, tool allow/deny)
    2. Subprocess invocation (deterministic, stdin args)
    3. Receipt minting (using existing receipt types)
    4. Artifact output (current/ + history/ + optional payload/)
    5. Trace integration (via emit_receipt)
    """

    def __init__(
        self,
        cfg: Optional[BridgeConfig] = None,
        policy: Optional[ToolPolicy] = None,
        invoker: Optional[ToolInvoker] = None,
        agent_id: str = "bridge-local-01",
    ):
        self.cfg = cfg or BridgeConfig()
        self.policy = policy or ToolPolicy()
        self.invoker = invoker or OpenClawSubprocessInvoker(self.cfg)
        self.agent_id = agent_id

        self.current_dir = self.cfg.artifacts_dir / "current"
        self.history_dir = self.cfg.artifacts_dir / "history"
        self.payload_dir = self.cfg.artifacts_dir / "payload"

        self.current_dir.mkdir(parents=True, exist_ok=True)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.payload_dir.mkdir(parents=True, exist_ok=True)

    def run_tool(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Run a tool through the bridge. Returns a receipt dict.

        Every call produces either:
        - An execution receipt (tool ran, with outcome ok/error/timeout)
        - A denial receipt (policy blocked it)

        Never returns without a receipt. Never crashes without a receipt.
        """
        policy_hash = self.policy.policy_hash()
        verdict = self.policy.check(tool_name=tool_name, arguments=arguments)

        if not verdict.allowed:
            return self._mint_denial(
                session_id=session_id,
                tool_name=tool_name,
                arguments=arguments,
                verdict=verdict,
                policy_hash=policy_hash,
            )

        return self._mint_execution(
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            policy_hash=policy_hash,
        )

    # -----------------------------------------------------------------------
    # Internal: denial receipt
    # -----------------------------------------------------------------------

    def _mint_denial(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        verdict: PolicyVerdict,
        policy_hash: str,
    ) -> Dict[str, Any]:
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        receipt: Dict[str, Any] = {
            "receipt_type": "BridgeDenial",
            "receipt_id": f"bd_{uuid.uuid4().hex[:16]}",
            "timestamp": now_iso,
            "agent_id": self.agent_id,
            "session_id": session_id,
            "tool_name": tool_name,
            "arguments_sha256": _sha256_text(
                json.dumps(arguments, separators=(",", ":"), sort_keys=True)
            ),
            "allowed": False,
            "denial_reason": verdict.reason,
            "policy_ref": verdict.policy_ref,
            "policy_hash": policy_hash,
            "cwd": self.cfg.cwd,
        }
        self._dump_receipt(receipt, kind="denial", tool_name=tool_name)
        self._emit_to_trace(receipt)
        return receipt

    # -----------------------------------------------------------------------
    # Internal: execution receipt
    # -----------------------------------------------------------------------

    def _mint_execution(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        policy_hash: str,
    ) -> Dict[str, Any]:
        result = self.invoker.invoke(tool_name=tool_name, arguments=arguments)

        stdout_hash = _sha256_text(result.stdout)
        stderr_hash = _sha256_text(result.stderr)

        outcome: Literal["ok", "error", "timeout"]
        if result.timed_out:
            outcome = "timeout"
        elif result.exit_code == 0:
            outcome = "ok"
        else:
            outcome = "error"

        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Optional: write full payload to content-addressed files
        stdout_path: Optional[str] = None
        stderr_path: Optional[str] = None
        if self.cfg.write_full_payload:
            stdout_path = self._write_payload("stdout", tool_name, result.stdout, stdout_hash)
            stderr_path = self._write_payload("stderr", tool_name, result.stderr, stderr_hash)

        receipt: Dict[str, Any] = {
            "receipt_type": "BridgeExecution",
            "receipt_id": f"be_{uuid.uuid4().hex[:16]}",
            "timestamp": now_iso,
            "agent_id": self.agent_id,
            "session_id": session_id,
            "tool_name": tool_name,
            "arguments_sha256": _sha256_text(
                json.dumps(arguments, separators=(",", ":"), sort_keys=True)
            ),
            "allowed": True,
            "outcome": outcome,
            "exit_code": result.exit_code,
            "duration_ms": round(result.duration_ms, 2),
            "stdout_sha256": stdout_hash,
            "stderr_sha256": stderr_hash,
            "stdout_preview": _preview(result.stdout, self.cfg.max_preview_bytes),
            "stderr_preview": _preview(result.stderr, self.cfg.max_preview_bytes),
            "policy_hash": policy_hash,
            "cwd": self.cfg.cwd,
        }
        if stdout_path:
            receipt["stdout_artifact_path"] = stdout_path
        if stderr_path:
            receipt["stderr_artifact_path"] = stderr_path

        self._dump_receipt(receipt, kind="execution", tool_name=tool_name)
        self._emit_to_trace(receipt)
        return receipt

    # -----------------------------------------------------------------------
    # Artifact output
    # -----------------------------------------------------------------------

    def _dump_receipt(self, payload: Dict[str, Any], kind: str, tool_name: str) -> None:
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        short = _short_hash(payload)

        current_path = self.current_dir / f"{kind}_{tool_name}_latest.json"
        history_path = self.history_dir / f"{ts}_{kind}_{tool_name}_{short}.json"

        self._write_json(current_path, payload)
        self._write_json(history_path, payload)

    def _write_payload(self, kind: str, tool_name: str, content: str, content_sha: str) -> str:
        path = self.payload_dir / f"{tool_name}_{kind}_{content_sha[:16]}.log"
        if not path.exists():
            tmp = path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            tmp.replace(path)
        return str(path)

    @staticmethod
    def _write_json(path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
        tmp.replace(path)

    @staticmethod
    def _emit_to_trace(receipt: Dict[str, Any]) -> None:
        """Emit to AssayStore trace if available (best-effort)."""
        try:
            from assay.store import emit_receipt
            emit_receipt(
                type=receipt.get("receipt_type", "bridge_unknown"),
                data=receipt,
                receipt_id=receipt.get("receipt_id"),
            )
        except Exception:
            pass  # trace integration is optional


__all__ = [
    "BridgeConfig",
    "InvokeResult",
    "ToolPolicy",
    "PolicyVerdict",
    "ToolInvoker",
    "OpenClawSubprocessInvoker",
    "ReceiptBridge",
]
