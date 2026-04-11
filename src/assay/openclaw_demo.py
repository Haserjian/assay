"""Deterministic OpenClaw demo with proof-pack projection.

This module wires the currently supported OpenClaw posture into one surviving
demo path:

- enforcement membrane via ReceiptBridge
- receipt adapter via OpenClawBridge and session-log parsing
- proof-pack projection into proof-pack-admissible namespaced tokens
- offline verification of the resulting proof pack
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence

import assay.store as store_mod
from assay.bridge import BridgeConfig, InvokeResult, ReceiptBridge, ToolInvoker
from assay.keystore import AssayKeyStore
from assay.openclaw_bridge import (
    OpenClawBridge,
    SessionLogImportReport,
    import_openclaw_session_log,
)
from assay.proof_pack import ProofPack, verify_proof_pack

DEMO_TRACE_ID = "openclaw_demo_v1"
DEMO_SESSION_ID = "sess_openclaw_demo_v1"
DEMO_TIMESTAMP = "2026-04-08T00:00:00+00:00"
DEMO_PACK_ID = "pack_openclaw_demo_v1"
DEMO_SIGNER_ID = "openclaw-demo-signer"
DEMO_AGENT_ID = "agent:openclaw-demo"


@dataclass(frozen=True)
class OpenClawDemoResult:
    """Structured result for the deterministic OpenClaw demo."""

    output_dir: Path
    pack_dir: Path
    session_log_path: Path
    summary_path: Path
    projected_entries: List[Dict[str, Any]]
    import_report: SessionLogImportReport
    verification_passed: bool
    verification_errors: List[Dict[str, Any]]


class DeterministicOpenClawInvoker(ToolInvoker):
    """Static invoker used by the demo to avoid a real OpenClaw dependency."""

    def invoke(self, tool_name: str, arguments: Dict[str, Any]) -> InvokeResult:
        if tool_name != "web_fetch":
            raise ValueError(f"Unsupported demo tool: {tool_name}")

        url = str(arguments.get("url") or "")
        payload = {
            "url": url,
            "status": 200,
            "title": "Async I/O in Python",
            "provider": "openclaw-demo",
        }
        return InvokeResult(
            exit_code=0,
            stdout=json.dumps(payload, separators=(",", ":"), sort_keys=True),
            stderr="",
            duration_ms=42.0,
            timed_out=False,
        )


@contextmanager
def isolated_demo_store(base_dir: Path, trace_id: str) -> Iterator[None]:
    """Route bridge trace writes into a temporary store for the demo lifetime."""

    previous_store = store_mod._default_store
    previous_seq_counter = store_mod._seq_counter
    previous_seq_trace_id = store_mod._seq_trace_id
    previous_trace_id = os.environ.get("ASSAY_TRACE_ID")

    store_mod._default_store = store_mod.AssayStore(base_dir=base_dir)
    store_mod._seq_counter = 0
    store_mod._seq_trace_id = None
    os.environ["ASSAY_TRACE_ID"] = trace_id
    try:
        yield
    finally:
        if previous_trace_id is None:
            os.environ.pop("ASSAY_TRACE_ID", None)
        else:
            os.environ["ASSAY_TRACE_ID"] = previous_trace_id
        store_mod._default_store = previous_store
        store_mod._seq_counter = previous_seq_counter
        store_mod._seq_trace_id = previous_seq_trace_id


def _json_ready_receipt(receipt: Any) -> Dict[str, Any]:
    if hasattr(receipt, "model_dump"):
        return receipt.model_dump(mode="json", exclude_none=True)
    return dict(receipt)


def project_bridge_receipt_for_proof_pack(
    receipt: Dict[str, Any],
    *,
    run_id: str,
    seq: int,
    evidence_source: str = "membrane_execution",
) -> Dict[str, Any]:
    """Project an internal bridge receipt into a proof-pack-admissible token."""

    source_type = str(receipt.get("receipt_type") or receipt.get("type") or "")
    projected_type = {
        "BridgeExecution": "openclaw.bridge_execution/v1",
        "BridgeDenial": "openclaw.bridge_denial/v1",
    }.get(source_type)
    if projected_type is None:
        raise ValueError(f"Unsupported bridge receipt type: {source_type}")

    allowed = bool(receipt.get("allowed", False))
    outcome = str(receipt.get("outcome") or ("blocked" if not allowed else "ok"))

    projected: Dict[str, Any] = {
        "receipt_id": str(receipt["receipt_id"]),
        "type": projected_type,
        "timestamp": str(receipt.get("timestamp") or DEMO_TIMESTAMP),
        "schema_version": str(receipt.get("schema_version") or "3.0"),
        "seq": seq,
        "run_id": run_id,
        "provider": "openclaw",
        "integration_source": "assay.bridge",
        "source_receipt_type": source_type,
        "source_receipt_id": str(receipt["receipt_id"]),
        "evidence_source": evidence_source,
        "agent_id": str(receipt.get("agent_id") or DEMO_AGENT_ID),
        "session_id": str(receipt.get("session_id") or DEMO_SESSION_ID),
        "tool_name": str(receipt.get("tool_name") or "unknown"),
        "allowed": allowed,
        "outcome": outcome,
        "policy_hash": receipt.get("policy_hash"),
        "policy_ref": receipt.get("policy_ref"),
        "arguments_sha256": receipt.get("arguments_sha256"),
    }

    optional_fields = (
        "cwd",
        "denial_reason",
        "duration_ms",
        "exit_code",
        "stderr_preview",
        "stderr_sha256",
        "stdout_preview",
        "stdout_sha256",
    )
    for field in optional_fields:
        value = receipt.get(field)
        if value is not None:
            projected[field] = value
    return projected


def project_web_tool_receipt_for_proof_pack(
    receipt: Any,
    *,
    run_id: str,
    seq: int,
    evidence_source: str = "live_receipt_adapter",
    source_line_number: int | None = None,
) -> Dict[str, Any]:
    """Project an OpenClaw web-tool receipt into a proof-pack-admissible token."""

    payload = _json_ready_receipt(receipt)
    tool = str(payload.get("tool") or "unknown")
    projected_type = {
        "web_search": "openclaw.web_search/v1",
        "web_fetch": "openclaw.web_fetch/v1",
        "browser": "openclaw.browser/v1",
    }.get(tool)
    if projected_type is None:
        raise ValueError(f"Unsupported web tool type: {tool}")

    timestamp = payload.get("ts") or payload.get("timestamp") or DEMO_TIMESTAMP
    projected: Dict[str, Any] = {
        "receipt_id": str(payload["receipt_id"]),
        "type": projected_type,
        "timestamp": str(timestamp),
        "schema_version": str(payload.get("schema_version") or "3.0"),
        "seq": seq,
        "run_id": run_id,
        "provider": str(payload.get("provider") or "openclaw"),
        "integration_source": "assay.openclaw_bridge",
        "source_receipt_type": str(payload.get("receipt_type") or "WebToolReceipt"),
        "source_receipt_id": str(payload["receipt_id"]),
        "evidence_source": evidence_source,
        "agent_id": str(payload.get("agent_id") or DEMO_AGENT_ID),
        "session_id": payload.get("session_id"),
        "tool": tool,
        "allowed": bool(payload.get("allowed", False)),
        "outcome": str(payload.get("outcome") or "blocked"),
        "policy_rule": payload.get("policy_rule"),
        "target_domain": payload.get("target_domain"),
    }

    optional_fields = (
        "cached",
        "content_hash",
        "content_type",
        "crossed_domain_boundary",
        "domain_allowlist_match",
        "latency_ms",
        "outcome_details",
        "query",
        "redirect_chain",
        "result_items",
        "result_size_chars",
        "sensitive_action_approved",
        "sensitive_action_attempted",
        "sensitive_action_type",
        "url",
    )
    for field in optional_fields:
        value = payload.get(field)
        if value is not None:
            projected[field] = value
    if source_line_number is not None:
        projected["source_line_number"] = source_line_number
    return projected


def _write_demo_session_log(
    path: Path,
    *,
    entries: Sequence[Dict[str, Any] | str] | None = None,
) -> None:
    """Write a deterministic exported OpenClaw session log for the demo."""

    log_entries = (
        list(entries)
        if entries is not None
        else [
            {
                "tool": "browser",
                "url": "https://github.com/anthropics/claude-code",
                "content_length": 1024,
            }
        ]
    )
    rendered_lines: List[str] = []
    for entry in log_entries:
        if isinstance(entry, str):
            rendered_lines.append(entry.rstrip("\n"))
        elif isinstance(entry, dict):
            rendered_lines.append(
                json.dumps(entry, separators=(",", ":"), sort_keys=True)
            )
        else:
            raise TypeError(f"Unsupported demo session-log entry: {type(entry)!r}")

    body = "\n".join(rendered_lines)
    if rendered_lines:
        body += "\n"
    path.write_text(body, encoding="utf-8")


def _reset_demo_outputs(output_dir: Path) -> None:
    for path in (
        output_dir / "artifacts",
        output_dir / "proof_pack",
    ):
        if path.exists():
            shutil.rmtree(path)
    for path in (
        output_dir / "DEMO_SUMMARY.json",
        output_dir / "openclaw_session.jsonl",
    ):
        if path.exists():
            path.unlink()


def run_openclaw_demo(
    output_dir: Path,
    *,
    keystore: AssayKeyStore | None = None,
    session_log_lines: Sequence[Dict[str, Any] | str] | None = None,
) -> OpenClawDemoResult:
    """Run the deterministic OpenClaw demo and build a verifiable proof pack."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _reset_demo_outputs(output_dir)

    artifacts_dir = output_dir / "artifacts"
    session_log_path = output_dir / "openclaw_session.jsonl"
    summary_path = output_dir / "DEMO_SUMMARY.json"
    pack_dir = output_dir / "proof_pack"

    with tempfile.TemporaryDirectory(prefix="assay_openclaw_demo_") as tmpdir:
        temp_root = Path(tmpdir)
        demo_store_dir = temp_root / "assay_store"
        demo_keystore = keystore or AssayKeyStore(keys_dir=temp_root / "keys")
        demo_keystore.generate_key(DEMO_SIGNER_ID)

        with isolated_demo_store(demo_store_dir, DEMO_TRACE_ID):
            membrane = ReceiptBridge(
                cfg=BridgeConfig(artifacts_dir=artifacts_dir, cwd=str(output_dir)),
                invoker=DeterministicOpenClawInvoker(),
                agent_id=DEMO_AGENT_ID,
            )
            allowed_bridge = membrane.run_tool(
                DEMO_SESSION_ID,
                "web_fetch",
                {"url": "https://docs.python.org/3/library/asyncio.html"},
            )
            denied_bridge = membrane.run_tool(
                DEMO_SESSION_ID,
                "web_fetch",
                {"url": "http://127.0.0.1:8080/admin"},
            )

        _write_demo_session_log(session_log_path, entries=session_log_lines)
        import_report = import_openclaw_session_log(
            session_log_path,
            agent_id=DEMO_AGENT_ID,
            allowlist=["*.github.com"],
        )
        imported_receipts = import_report.receipts

        adapter = OpenClawBridge(
            allowlist=["*.github.com"],
            agent_id=DEMO_AGENT_ID,
            session_id=DEMO_SESSION_ID,
        )
        blocked_sensitive = adapter.record_browser(
            url="https://github.com/login",
            sensitive_action_attempted=True,
            sensitive_action_type="credential_entry",
            sensitive_action_approved=False,
        )

        projected_entries: List[Dict[str, Any]] = []
        seq = 0
        for receipt in (allowed_bridge, denied_bridge):
            projected_entries.append(
                project_bridge_receipt_for_proof_pack(
                    receipt,
                    run_id=DEMO_TRACE_ID,
                    seq=seq,
                    evidence_source="membrane_execution",
                )
            )
            seq += 1
        for imported in import_report.imported_entries:
            projected_entries.append(
                project_web_tool_receipt_for_proof_pack(
                    imported.receipt,
                    run_id=DEMO_TRACE_ID,
                    seq=seq,
                    evidence_source="imported_session_log",
                    source_line_number=imported.line_number,
                )
            )
            seq += 1
        projected_entries.append(
            project_web_tool_receipt_for_proof_pack(
                blocked_sensitive,
                run_id=DEMO_TRACE_ID,
                seq=seq,
                evidence_source="live_receipt_adapter",
            )
        )

        pack = ProofPack(
            run_id=DEMO_TRACE_ID,
            entries=projected_entries,
            signer_id=DEMO_SIGNER_ID,
            suite_id="openclaw_demo",
            claim_set_id="openclaw_demo_contract_v1",
            mode="shadow",
        )
        pack.build(
            pack_dir,
            keystore=demo_keystore,
            pack_id=DEMO_PACK_ID,
            deterministic_ts=DEMO_TIMESTAMP,
        )

        manifest = json.loads(
            (pack_dir / "pack_manifest.json").read_text(encoding="utf-8")
        )
        verify_result = verify_proof_pack(manifest, pack_dir, demo_keystore)

    summary = {
        "demo": "openclaw",
        "trace_id": DEMO_TRACE_ID,
        "pack_id": DEMO_PACK_ID,
        "verification": "PASS" if verify_result.passed else "FAIL",
        "projected_receipt_count": len(projected_entries),
        "projected_receipt_types": [entry["type"] for entry in projected_entries],
        "projected_evidence_sources": dict(
            Counter(entry["evidence_source"] for entry in projected_entries)
        ),
        "cases": {
            "membrane_allowed": {
                "tool": allowed_bridge["tool_name"],
                "url": "https://docs.python.org/3/library/asyncio.html",
                "outcome": allowed_bridge["outcome"],
            },
            "membrane_denied": {
                "tool": denied_bridge["tool_name"],
                "url": "http://127.0.0.1:8080/admin",
                "policy_ref": denied_bridge["policy_ref"],
                "reason": denied_bridge["denial_reason"],
            },
            "session_log_import": {
                "path": str(session_log_path),
                "status": import_report.completeness,
                "receipt_count": len(imported_receipts),
                "imported_count": import_report.imported_count,
                "total_lines": import_report.total_lines,
                "blank_lines": import_report.blank_lines,
                "skipped_count": import_report.skipped_count,
            },
            "sensitive_action_blocked": {
                "url": blocked_sensitive.url,
                "outcome": blocked_sensitive.outcome,
                "approved": blocked_sensitive.sensitive_action_approved,
            },
        },
        "import_report": {
            "status": import_report.completeness,
            "total_lines": import_report.total_lines,
            "blank_lines": import_report.blank_lines,
            "imported_count": import_report.imported_count,
            "skipped_count": import_report.skipped_count,
            "skipped_entries": [
                {
                    "line_number": skipped.line_number,
                    "reason": skipped.reason,
                    "message": skipped.message,
                    "tool": skipped.tool,
                    "raw_preview": skipped.raw_preview,
                }
                for skipped in import_report.skipped_entries
            ],
        },
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return OpenClawDemoResult(
        output_dir=output_dir,
        pack_dir=pack_dir,
        session_log_path=session_log_path,
        summary_path=summary_path,
        projected_entries=projected_entries,
        import_report=import_report,
        verification_passed=verify_result.passed,
        verification_errors=[error.to_dict() for error in verify_result.errors],
    )


__all__ = [
    "DEMO_AGENT_ID",
    "DEMO_PACK_ID",
    "DEMO_SESSION_ID",
    "DEMO_TIMESTAMP",
    "DEMO_TRACE_ID",
    "OpenClawDemoResult",
    "DeterministicOpenClawInvoker",
    "project_bridge_receipt_for_proof_pack",
    "project_web_tool_receipt_for_proof_pack",
    "run_openclaw_demo",
]
