"""Helpers for validating real exported OpenClaw session logs.

This module is intentionally narrower than the deterministic demo path.
It answers one question honestly:

How well does the current importer fit actual exported session logs available
on disk right now?

If no real logs are available, it returns a blocker instead of inventing
confidence.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal, Optional, Sequence

DEFAULT_OPENCLAW_HOME = Path("~/.openclaw").expanduser()
DEFAULT_SESSION_LOG_GLOBS: tuple[str, ...] = ("agents/*/sessions/*.jsonl",)
DEFAULT_ALLOWLIST: tuple[str, ...] = ("*",)


@dataclass(frozen=True)
class OpenClawValidatedLog:
    """Summary of importing one exported OpenClaw session log."""

    path: str
    agent_name: str
    agent_id: str
    session_id: str
    total_lines: int
    blank_lines: int
    imported_count: int
    skipped_count: int
    completeness: Literal["clean", "partial"]
    imported_tools: dict[str, int]
    recognized_entry_types: dict[str, int]
    message_roles: dict[str, int]
    skipped_reasons: dict[str, int]
    skipped_entries_preview: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "total_lines": self.total_lines,
            "blank_lines": self.blank_lines,
            "imported_count": self.imported_count,
            "skipped_count": self.skipped_count,
            "completeness": self.completeness,
            "imported_tools": self.imported_tools,
            "recognized_entry_types": self.recognized_entry_types,
            "message_roles": self.message_roles,
            "skipped_reasons": self.skipped_reasons,
            "skipped_entries_preview": self.skipped_entries_preview,
        }


@dataclass(frozen=True)
class _RecognizedSessionLogRow:
    """One exported session-log row recognized by the live-validation parser."""

    line_number: int
    entry_type: str
    message_role: Optional[str] = None
    tool_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class OpenClawLiveValidationResult:
    """Machine-readable result for real OpenClaw exported-log validation."""

    status: Literal["ok", "blocked"]
    reason: Optional[Literal["openclaw_home_missing", "no_session_logs"]]
    openclaw_home: str
    openclaw_home_exists: bool
    searched_globs: list[str]
    top_level_entries: list[str]
    validated_logs: list[OpenClawValidatedLog]
    allowlist: list[str]

    @property
    def log_count(self) -> int:
        return len(self.validated_logs)

    @property
    def imported_count(self) -> int:
        return sum(log.imported_count for log in self.validated_logs)

    @property
    def skipped_count(self) -> int:
        return sum(log.skipped_count for log in self.validated_logs)

    @property
    def partial_log_count(self) -> int:
        return sum(1 for log in self.validated_logs if log.completeness == "partial")

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "openclaw_home": self.openclaw_home,
            "openclaw_home_exists": self.openclaw_home_exists,
            "searched_globs": self.searched_globs,
            "top_level_entries": self.top_level_entries,
            "allowlist": self.allowlist,
            "log_count": self.log_count,
            "imported_count": self.imported_count,
            "skipped_count": self.skipped_count,
            "partial_log_count": self.partial_log_count,
            "validated_logs": [log.to_dict() for log in self.validated_logs],
        }


def discover_openclaw_session_logs(
    openclaw_home: Path,
    *,
    session_log_globs: Sequence[str] = DEFAULT_SESSION_LOG_GLOBS,
) -> list[Path]:
    """Return exported session logs from the standard OpenClaw runtime home."""

    home = Path(openclaw_home).expanduser().resolve()
    discovered: list[Path] = []
    seen: set[Path] = set()
    for pattern in session_log_globs:
        for candidate in home.glob(pattern):
            resolved = candidate.resolve()
            if resolved in seen or not resolved.is_file():
                continue
            seen.add(resolved)
            discovered.append(resolved)
    return sorted(discovered)


def validate_openclaw_session_logs(
    *,
    openclaw_home: Path = DEFAULT_OPENCLAW_HOME,
    session_log_paths: Optional[Iterable[Path]] = None,
    allowlist: Sequence[str] = DEFAULT_ALLOWLIST,
    session_log_globs: Sequence[str] = DEFAULT_SESSION_LOG_GLOBS,
    skipped_preview_limit: int = 5,
) -> OpenClawLiveValidationResult:
    """Import available OpenClaw session logs or return an explicit blocker."""

    resolved_home = Path(openclaw_home).expanduser().resolve()
    resolved_allowlist = [pattern for pattern in allowlist] or ["*"]
    searched_globs = [str(resolved_home / pattern) for pattern in session_log_globs]
    top_level_entries = _list_top_level_entries(resolved_home)

    if session_log_paths is None and not resolved_home.exists():
        return OpenClawLiveValidationResult(
            status="blocked",
            reason="openclaw_home_missing",
            openclaw_home=str(resolved_home),
            openclaw_home_exists=False,
            searched_globs=searched_globs,
            top_level_entries=[],
            validated_logs=[],
            allowlist=resolved_allowlist,
        )

    logs = (
        [Path(path).expanduser().resolve() for path in session_log_paths]
        if session_log_paths is not None
        else discover_openclaw_session_logs(
            resolved_home,
            session_log_globs=session_log_globs,
        )
    )

    if not logs:
        return OpenClawLiveValidationResult(
            status="blocked",
            reason="no_session_logs",
            openclaw_home=str(resolved_home),
            openclaw_home_exists=resolved_home.exists(),
            searched_globs=searched_globs,
            top_level_entries=top_level_entries,
            validated_logs=[],
            allowlist=resolved_allowlist,
        )

    validated_logs = [
        _validate_session_log(
            log_path,
            openclaw_home=resolved_home,
            allowlist=resolved_allowlist,
            skipped_preview_limit=skipped_preview_limit,
        )
        for log_path in logs
    ]

    return OpenClawLiveValidationResult(
        status="ok",
        reason=None,
        openclaw_home=str(resolved_home),
        openclaw_home_exists=resolved_home.exists(),
        searched_globs=searched_globs,
        top_level_entries=top_level_entries,
        validated_logs=validated_logs,
        allowlist=resolved_allowlist,
    )


def render_openclaw_live_validation(result: OpenClawLiveValidationResult) -> str:
    """Render a concise human-readable validation report."""

    lines = [
        "=== OpenClaw Live Validation ===",
        f"Status: {result.status.upper()}",
        f"OpenClaw home: {result.openclaw_home}",
        f"Home exists: {'yes' if result.openclaw_home_exists else 'no'}",
        f"Allowlist: {', '.join(result.allowlist)}",
    ]

    if result.reason is not None:
        lines.append(f"Reason: {result.reason}")
    if result.top_level_entries:
        lines.append(f"Home entries: {', '.join(result.top_level_entries)}")

    if result.status == "blocked":
        lines.append("Searched:")
        lines.extend(f"  - {glob}" for glob in result.searched_globs)
        if result.reason == "openclaw_home_missing":
            lines.append(
                "No OpenClaw runtime home exists at the default path, so there are no real exported sessions to validate."
            )
        elif result.reason == "no_session_logs":
            lines.append(
                "OpenClaw runtime state exists or is configured, but no exported session logs were found under the standard session path."
            )
        return "\n".join(lines)

    lines.append(
        "Summary: "
        f"{result.log_count} log(s), {result.imported_count} imported row(s), "
        f"{result.skipped_count} skipped row(s), {result.partial_log_count} partial log(s)"
    )
    for log in result.validated_logs:
        lines.extend(
            [
                "",
                f"Log: {log.path}",
                f"  Agent: {log.agent_name}",
                f"  Session: {log.session_id}",
                f"  Import: {log.completeness}",
                f"  Imported: {log.imported_count}",
                f"  Skipped: {log.skipped_count}",
                f"  Lines: {log.total_lines} total, {log.blank_lines} blank",
            ]
        )
        if log.recognized_entry_types:
            lines.append(
                "  Recognized entry types: "
                + ", ".join(
                    f"{entry_type}={count}"
                    for entry_type, count in sorted(log.recognized_entry_types.items())
                )
            )
        if log.message_roles:
            lines.append(
                "  Message roles: "
                + ", ".join(
                    f"{role}={count}"
                    for role, count in sorted(log.message_roles.items())
                )
            )
        if log.imported_tools:
            lines.append(
                "  Observed tools: "
                + ", ".join(
                    f"{tool}={count}"
                    for tool, count in sorted(log.imported_tools.items())
                )
            )
        if log.skipped_reasons:
            lines.append(
                "  Skipped reasons: "
                + ", ".join(
                    f"{reason}={count}"
                    for reason, count in sorted(log.skipped_reasons.items())
                )
            )
    return "\n".join(lines)


def _validate_session_log(
    log_path: Path,
    *,
    openclaw_home: Path,
    allowlist: Sequence[str],
    skipped_preview_limit: int,
) -> OpenClawValidatedLog:
    agent_name = infer_openclaw_agent_name(log_path, openclaw_home=openclaw_home)
    agent_id = f"agent:{agent_name}"
    total_lines = 0
    blank_lines = 0
    recognized_rows: list[_RecognizedSessionLogRow] = []
    skipped_entries: list[dict[str, object]] = []

    del allowlist

    with log_path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            total_lines += 1
            line = raw_line.strip()
            if not line:
                blank_lines += 1
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                skipped_entries.append(
                    _build_skipped_entry(
                        line_number=line_number,
                        reason="invalid_json",
                        message=str(exc),
                        raw_line=raw_line,
                    )
                )
                continue

            recognized_row = _recognize_session_log_row(
                entry=entry,
                line_number=line_number,
                raw_line=raw_line,
            )
            if isinstance(recognized_row, dict):
                skipped_entries.append(recognized_row)
                continue

            recognized_rows.append(recognized_row)

    imported_tools = Counter(
        tool_name for row in recognized_rows for tool_name in row.tool_names
    )
    recognized_entry_types = Counter(row.entry_type for row in recognized_rows)
    message_roles = Counter(
        row.message_role for row in recognized_rows if row.message_role is not None
    )
    skipped_reasons = Counter(
        str(entry.get("reason")) for entry in skipped_entries if entry.get("reason")
    )
    skipped_entries_preview = skipped_entries[:skipped_preview_limit]
    completeness: Literal["clean", "partial"] = (
        "clean" if not skipped_entries else "partial"
    )

    return OpenClawValidatedLog(
        path=str(log_path),
        agent_name=agent_name,
        agent_id=agent_id,
        session_id=log_path.stem,
        total_lines=total_lines,
        blank_lines=blank_lines,
        imported_count=len(recognized_rows),
        skipped_count=len(skipped_entries),
        completeness=completeness,
        imported_tools=dict(imported_tools),
        recognized_entry_types=dict(recognized_entry_types),
        message_roles=dict(message_roles),
        skipped_reasons=dict(skipped_reasons),
        skipped_entries_preview=skipped_entries_preview,
    )


def _recognize_session_log_row(
    *,
    entry: Any,
    line_number: int,
    raw_line: str,
) -> _RecognizedSessionLogRow | dict[str, object]:
    if not isinstance(entry, dict):
        return _build_skipped_entry(
            line_number=line_number,
            reason="invalid_entry",
            message="Session-log row must be a JSON object",
            raw_line=raw_line,
        )

    legacy_tool = entry.get("tool")
    if legacy_tool is not None:
        return _recognize_legacy_tool_row(
            entry=entry,
            line_number=line_number,
            raw_line=raw_line,
        )

    entry_type = entry.get("type")
    if not isinstance(entry_type, str) or not entry_type.strip():
        return _build_skipped_entry(
            line_number=line_number,
            reason="invalid_entry",
            message="Session-log row must include a non-empty type or tool field",
            raw_line=raw_line,
        )

    normalized_entry_type = entry_type.strip()
    if normalized_entry_type in {"session", "model_change", "thinking_level_change"}:
        return _RecognizedSessionLogRow(
            line_number=line_number,
            entry_type=normalized_entry_type,
        )

    if normalized_entry_type == "custom":
        custom_type = entry.get("customType")
        if not isinstance(custom_type, str) or not custom_type.strip():
            return _build_skipped_entry(
                line_number=line_number,
                reason="invalid_entry",
                message="Custom session-log row must include a non-empty customType",
                raw_line=raw_line,
            )
        return _RecognizedSessionLogRow(
            line_number=line_number,
            entry_type="custom",
        )

    if normalized_entry_type == "message":
        return _recognize_message_row(
            entry=entry,
            line_number=line_number,
            raw_line=raw_line,
        )

    return _build_skipped_entry(
        line_number=line_number,
        reason="unsupported_entry_type",
        message=f"Unsupported session-log entry type: {normalized_entry_type}",
        raw_line=raw_line,
    )


def _recognize_legacy_tool_row(
    *,
    entry: dict[str, Any],
    line_number: int,
    raw_line: str,
) -> _RecognizedSessionLogRow | dict[str, object]:
    tool = entry.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        return _build_skipped_entry(
            line_number=line_number,
            reason="unsupported_tool",
            message="Unsupported or missing tool field",
            raw_line=raw_line,
        )

    normalized_tool = tool.strip()
    if normalized_tool not in {"web_search", "web_fetch", "browser"}:
        return _build_skipped_entry(
            line_number=line_number,
            reason="unsupported_tool",
            message="Unsupported or missing tool field",
            tool=normalized_tool,
            raw_line=raw_line,
        )

    if (
        normalized_tool == "browser"
        and entry.get("sensitive_action_attempted")
        and entry.get("sensitive_action_approved") is None
    ):
        return _build_skipped_entry(
            line_number=line_number,
            reason="invalid_entry",
            message="Sensitive action attempted requires explicit approval status.",
            tool=normalized_tool,
            raw_line=raw_line,
        )

    return _RecognizedSessionLogRow(
        line_number=line_number,
        entry_type="legacy_tool",
        tool_names=(normalized_tool,),
    )


def _recognize_message_row(
    *,
    entry: dict[str, Any],
    line_number: int,
    raw_line: str,
) -> _RecognizedSessionLogRow | dict[str, object]:
    message = entry.get("message")
    if not isinstance(message, dict):
        return _build_skipped_entry(
            line_number=line_number,
            reason="invalid_entry",
            message="Message session-log row must include a message object",
            raw_line=raw_line,
        )

    role = message.get("role")
    if not isinstance(role, str) or not role.strip():
        return _build_skipped_entry(
            line_number=line_number,
            reason="invalid_entry",
            message="Message session-log row must include a non-empty message role",
            raw_line=raw_line,
        )

    tool_names: list[str] = []
    if role == "assistant":
        content = message.get("content")
        if not isinstance(content, list):
            return _build_skipped_entry(
                line_number=line_number,
                reason="invalid_entry",
                message="Assistant message rows must include a content list",
                raw_line=raw_line,
            )
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "toolCall":
                continue
            tool_name = item.get("name")
            if isinstance(tool_name, str) and tool_name.strip():
                tool_names.append(tool_name.strip())

    return _RecognizedSessionLogRow(
        line_number=line_number,
        entry_type="message",
        message_role=role.strip(),
        tool_names=tuple(tool_names),
    )


def _build_skipped_entry(
    *,
    line_number: int,
    reason: str,
    message: str,
    raw_line: str,
    tool: Optional[str] = None,
) -> dict[str, object]:
    return {
        "line_number": line_number,
        "reason": reason,
        "message": message,
        "tool": tool,
        "raw_preview": _preview_line(raw_line),
    }


def _preview_line(raw_line: str, max_chars: int = 160) -> str:
    preview = raw_line.strip().replace("\n", "\\n")
    if len(preview) <= max_chars:
        return preview
    return preview[:max_chars] + "...[truncated]"


def infer_openclaw_agent_name(log_path: Path, *, openclaw_home: Path) -> str:
    """Infer the agent name from a standard OpenClaw session-log path."""

    resolved_path = Path(log_path).expanduser().resolve()
    resolved_home = Path(openclaw_home).expanduser().resolve()
    try:
        relative = resolved_path.relative_to(resolved_home)
    except ValueError:
        return "external"

    parts = relative.parts
    if len(parts) >= 4 and parts[0] == "agents" and parts[2] == "sessions":
        return parts[1]
    return "unknown"


def _list_top_level_entries(openclaw_home: Path) -> list[str]:
    if not openclaw_home.exists() or not openclaw_home.is_dir():
        return []
    entries: list[str] = []
    for child in sorted(openclaw_home.iterdir(), key=lambda path: path.name):
        entries.append(f"{child.name}/" if child.is_dir() else child.name)
    return entries


__all__ = [
    "DEFAULT_ALLOWLIST",
    "DEFAULT_OPENCLAW_HOME",
    "DEFAULT_SESSION_LOG_GLOBS",
    "OpenClawLiveValidationResult",
    "OpenClawValidatedLog",
    "discover_openclaw_session_logs",
    "infer_openclaw_agent_name",
    "render_openclaw_live_validation",
    "validate_openclaw_session_logs",
]
