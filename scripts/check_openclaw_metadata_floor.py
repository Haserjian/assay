#!/usr/bin/env python3
"""Validate the OpenClaw v1 metadata floor against emitted demo artifacts."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

ALLOWED_EVIDENCE_SOURCES = frozenset(
    {
        "membrane_execution",
        "imported_session_log",
        "live_receipt_adapter",
    }
)


@dataclass(frozen=True)
class MetadataIssue:
    """One metadata-floor validation failure."""

    location: str
    field: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "location": self.location,
            "field": self.field,
            "message": self.message,
        }


@dataclass(frozen=True)
class OpenClawMetadataFloorResult:
    """Result of checking one emitted OpenClaw artifact set."""

    pack_dir: str
    summary_path: str
    entry_count: int
    import_status: Optional[str]
    issues: list[MetadataIssue]

    @property
    def passed(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, object]:
        return {
            "pack_dir": self.pack_dir,
            "summary_path": self.summary_path,
            "entry_count": self.entry_count,
            "import_status": self.import_status,
            "issue_count": len(self.issues),
            "issues": [issue.to_dict() for issue in self.issues],
            "passed": self.passed,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the OpenClaw v1 metadata floor for a generated proof pack "
            "and demo summary."
        )
    )
    parser.add_argument(
        "--openclaw-json",
        type=Path,
        help=(
            "Path to the JSON emitted by 'assay try-openclaw --json'. "
            "When provided, summary and pack-dir paths are resolved from it."
        ),
    )
    parser.add_argument(
        "--pack-dir",
        type=Path,
        help="Path to the generated proof-pack directory.",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help="Path to DEMO_SUMMARY.json for the emitted artifact set.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable report.",
    )
    args = parser.parse_args()
    if args.openclaw_json is None and (args.pack_dir is None or args.summary is None):
        parser.error("Provide --openclaw-json or both --pack-dir and --summary.")
    return args


def main() -> int:
    args = parse_args()
    if args.openclaw_json is not None:
        result = check_openclaw_metadata_floor_from_openclaw_json(args.openclaw_json)
    else:
        assert args.pack_dir is not None and args.summary is not None
        result = check_openclaw_metadata_floor(
            pack_dir=args.pack_dir,
            summary_path=args.summary,
        )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0 if result.passed else 1

    print("=== OpenClaw Metadata Floor ===")
    print(f"Pack dir:    {result.pack_dir}")
    print(f"Summary:     {result.summary_path}")
    print(f"Entry count: {result.entry_count}")
    if result.import_status is not None:
        print(f"Import:      {result.import_status}")
    print(f"Result:      {'PASS' if result.passed else 'HOLD'}")
    if result.issues:
        print()
        for issue in result.issues:
            print(f"- {issue.location} :: {issue.field} :: {issue.message}")
    return 0 if result.passed else 1


def check_openclaw_metadata_floor_from_openclaw_json(
    openclaw_json_path: Path,
) -> OpenClawMetadataFloorResult:
    pack_dir, summary_path = resolve_openclaw_artifact_paths(openclaw_json_path)
    return check_openclaw_metadata_floor(pack_dir=pack_dir, summary_path=summary_path)


def resolve_openclaw_artifact_paths(openclaw_json_path: Path) -> tuple[Path, Path]:
    payload = _load_json(Path(openclaw_json_path))
    base_dir = Path(openclaw_json_path).resolve().parent
    pack_dir = _resolve_path(base_dir, payload.get("pack_dir"), "pack_dir")
    summary_path = _resolve_path(base_dir, payload.get("summary"), "summary")
    return pack_dir, summary_path


def check_openclaw_metadata_floor(
    *,
    pack_dir: Path,
    summary_path: Path,
) -> OpenClawMetadataFloorResult:
    issues: list[MetadataIssue] = []
    pack_dir = Path(pack_dir).resolve()
    summary_path = Path(summary_path).resolve()

    summary = _safe_load_json(summary_path, f"summary:{summary_path.name}", issues)
    entries = _load_receipt_pack_entries(pack_dir, issues)

    entry_types: list[str] = []
    evidence_counts: Counter[str] = Counter()
    imported_count = 0

    for index, entry in enumerate(entries):
        location = f"receipt_pack[{index}]"
        _validate_common_entry_fields(entry, location, issues)
        entry_type = _value_as_non_empty_string(entry, "type", location, issues)
        if entry_type is not None:
            entry_types.append(entry_type)

        evidence_source = _value_as_non_empty_string(
            entry,
            "evidence_source",
            location,
            issues,
        )
        if evidence_source is None:
            continue
        if evidence_source not in ALLOWED_EVIDENCE_SOURCES:
            issues.append(
                MetadataIssue(
                    location=location,
                    field="evidence_source",
                    message=(
                        "Unexpected evidence_source; expected one of "
                        f"{sorted(ALLOWED_EVIDENCE_SOURCES)}"
                    ),
                )
            )
            continue

        evidence_counts[evidence_source] += 1
        if evidence_source == "membrane_execution":
            _validate_membrane_entry(entry, location, issues)
        elif evidence_source == "imported_session_log":
            imported_count += 1
            _validate_imported_session_log_entry(entry, location, issues)
        elif evidence_source == "live_receipt_adapter":
            _validate_live_receipt_entry(entry, location, issues)

    import_status = None
    if summary is not None:
        import_status = _validate_summary(
            summary,
            entry_count=len(entries),
            entry_types=entry_types,
            evidence_counts=evidence_counts,
            imported_entry_count=imported_count,
            issues=issues,
        )

    return OpenClawMetadataFloorResult(
        pack_dir=str(pack_dir),
        summary_path=str(summary_path),
        entry_count=len(entries),
        import_status=import_status,
        issues=issues,
    )


def _validate_common_entry_fields(
    entry: dict[str, Any],
    location: str,
    issues: list[MetadataIssue],
) -> None:
    for field in (
        "receipt_id",
        "type",
        "timestamp",
        "schema_version",
        "run_id",
        "provider",
        "integration_source",
        "source_receipt_type",
        "source_receipt_id",
        "evidence_source",
        "agent_id",
        "outcome",
    ):
        _value_as_non_empty_string(entry, field, location, issues)

    _value_as_int(entry, "seq", location, issues)
    _value_as_bool(entry, "allowed", location, issues)


def _validate_membrane_entry(
    entry: dict[str, Any],
    location: str,
    issues: list[MetadataIssue],
) -> None:
    _value_as_non_empty_string(entry, "tool_name", location, issues)
    _value_as_non_empty_string(entry, "arguments_sha256", location, issues)

    policy_ref = _optional_non_empty_string(entry, "policy_ref")
    policy_hash = _optional_non_empty_string(entry, "policy_hash")
    if policy_ref is None and policy_hash is None:
        issues.append(
            MetadataIssue(
                location=location,
                field="policy_ref|policy_hash",
                message="At least one policy link must remain present for membrane_execution.",
            )
        )

    outcome = entry.get("outcome")
    if outcome == "blocked":
        _value_as_non_empty_string(entry, "denial_reason", location, issues)


def _validate_imported_session_log_entry(
    entry: dict[str, Any],
    location: str,
    issues: list[MetadataIssue],
) -> None:
    _value_as_int(entry, "source_line_number", location, issues)
    _value_as_bool(entry, "allowed", location, issues)
    _value_as_non_empty_string(entry, "outcome", location, issues)

    tool = _optional_non_empty_string(entry, "tool")
    entry_type = _optional_non_empty_string(entry, "type")
    if tool is None and entry_type not in {
        "openclaw.web_search/v1",
        "openclaw.web_fetch/v1",
        "openclaw.browser/v1",
    }:
        issues.append(
            MetadataIssue(
                location=location,
                field="tool|type",
                message="Imported session-log entry must preserve tool identity.",
            )
        )
        return

    if tool == "browser" or entry_type == "openclaw.browser/v1":
        _value_as_non_empty_string(entry, "policy_rule", location, issues)
        _value_as_non_empty_string(entry, "target_domain", location, issues)


def _validate_live_receipt_entry(
    entry: dict[str, Any],
    location: str,
    issues: list[MetadataIssue],
) -> None:
    _value_as_non_empty_string(entry, "tool", location, issues)
    _value_as_non_empty_string(entry, "policy_rule", location, issues)
    _value_as_bool(entry, "allowed", location, issues)
    _value_as_non_empty_string(entry, "outcome", location, issues)

    sensitive_attempted = entry.get("sensitive_action_attempted")
    sensitive_type = entry.get("sensitive_action_type")
    if sensitive_attempted or sensitive_type is not None:
        _value_as_bool(entry, "sensitive_action_attempted", location, issues)
        _value_as_non_empty_string(entry, "sensitive_action_type", location, issues)
        _value_as_bool(entry, "sensitive_action_approved", location, issues)


def _validate_summary(
    summary: dict[str, Any],
    *,
    entry_count: int,
    entry_types: list[str],
    evidence_counts: Counter[str],
    imported_entry_count: int,
    issues: list[MetadataIssue],
) -> Optional[str]:
    location = "summary"

    verification = _value_as_non_empty_string(summary, "verification", location, issues)
    if verification is not None and verification != "PASS":
        issues.append(
            MetadataIssue(
                location=location,
                field="verification",
                message="Release-candidate summary must report verification PASS.",
            )
        )

    projected_receipt_count = _value_as_int(
        summary,
        "projected_receipt_count",
        location,
        issues,
    )
    if projected_receipt_count is not None and projected_receipt_count != entry_count:
        issues.append(
            MetadataIssue(
                location=location,
                field="projected_receipt_count",
                message=(
                    f"Summary count {projected_receipt_count} does not match receipt pack count {entry_count}."
                ),
            )
        )

    projected_receipt_types = _value_as_list(
        summary,
        "projected_receipt_types",
        location,
        issues,
    )
    if projected_receipt_types is not None:
        normalized_types = [str(value) for value in projected_receipt_types]
        if normalized_types != entry_types:
            issues.append(
                MetadataIssue(
                    location=location,
                    field="projected_receipt_types",
                    message="Summary receipt types no longer match the emitted receipt pack order.",
                )
            )

    summary_evidence_sources = _value_as_dict(
        summary,
        "projected_evidence_sources",
        location,
        issues,
    )
    if summary_evidence_sources is not None:
        normalized_counts = {
            str(key): int(value) for key, value in summary_evidence_sources.items()
        }
        if normalized_counts != dict(evidence_counts):
            issues.append(
                MetadataIssue(
                    location=location,
                    field="projected_evidence_sources",
                    message="Summary evidence-source counts do not match emitted receipt entries.",
                )
            )

    cases = _value_as_dict(summary, "cases", location, issues)
    if cases is not None:
        _value_as_dict(cases, "membrane_allowed", "summary.cases", issues)
        _value_as_dict(cases, "membrane_denied", "summary.cases", issues)
        session_log_import = _value_as_dict(
            cases,
            "session_log_import",
            "summary.cases",
            issues,
        )
        _value_as_dict(cases, "sensitive_action_blocked", "summary.cases", issues)
        if session_log_import is not None:
            _value_as_non_empty_string(
                session_log_import,
                "path",
                "summary.cases.session_log_import",
                issues,
            )
            case_status = _value_as_non_empty_string(
                session_log_import,
                "status",
                "summary.cases.session_log_import",
                issues,
            )
            if case_status is not None and case_status not in {"clean", "partial"}:
                issues.append(
                    MetadataIssue(
                        location="summary.cases.session_log_import",
                        field="status",
                        message="Session-log import status must stay explicit as 'clean' or 'partial'.",
                    )
                )
            case_receipt_count = _value_as_int(
                session_log_import,
                "receipt_count",
                "summary.cases.session_log_import",
                issues,
            )
            case_imported_count = _value_as_int(
                session_log_import,
                "imported_count",
                "summary.cases.session_log_import",
                issues,
            )
            for field in ("total_lines", "blank_lines", "skipped_count"):
                _value_as_int(
                    session_log_import,
                    field,
                    "summary.cases.session_log_import",
                    issues,
                )
            if (
                case_receipt_count is not None
                and case_receipt_count != imported_entry_count
            ):
                issues.append(
                    MetadataIssue(
                        location="summary.cases.session_log_import",
                        field="receipt_count",
                        message="Session-log receipt_count no longer matches imported_session_log entries.",
                    )
                )
            if (
                case_imported_count is not None
                and case_imported_count != imported_entry_count
            ):
                issues.append(
                    MetadataIssue(
                        location="summary.cases.session_log_import",
                        field="imported_count",
                        message="Session-log imported_count no longer matches imported_session_log entries.",
                    )
                )

    import_report = _value_as_dict(summary, "import_report", location, issues)
    if import_report is None:
        return None

    import_status = _value_as_non_empty_string(
        import_report,
        "status",
        "summary.import_report",
        issues,
    )
    if import_status is not None and import_status not in {"clean", "partial"}:
        issues.append(
            MetadataIssue(
                location="summary.import_report",
                field="status",
                message="Import report status must stay explicit as 'clean' or 'partial'.",
            )
        )

    imported_count = _value_as_int(
        import_report,
        "imported_count",
        "summary.import_report",
        issues,
    )
    if imported_count is not None and imported_count != imported_entry_count:
        issues.append(
            MetadataIssue(
                location="summary.import_report",
                field="imported_count",
                message="Import report imported_count no longer matches imported_session_log entries.",
            )
        )

    for field in ("total_lines", "blank_lines", "skipped_count"):
        _value_as_int(import_report, field, "summary.import_report", issues)

    if import_status == "partial":
        skipped_entries = _value_as_list(
            import_report,
            "skipped_entries",
            "summary.import_report",
            issues,
        )
        if skipped_entries is None:
            return import_status
        if not skipped_entries:
            issues.append(
                MetadataIssue(
                    location="summary.import_report",
                    field="skipped_entries",
                    message="Partial import status requires explicit skipped-row entries.",
                )
            )
            return import_status
        for index, skipped in enumerate(skipped_entries):
            if not isinstance(skipped, dict):
                issues.append(
                    MetadataIssue(
                        location=f"summary.import_report.skipped_entries[{index}]",
                        field="entry",
                        message="Skipped-entry details must remain structured objects.",
                    )
                )
                continue
            entry_location = f"summary.import_report.skipped_entries[{index}]"
            _value_as_int(skipped, "line_number", entry_location, issues)
            _value_as_non_empty_string(skipped, "reason", entry_location, issues)
            _value_as_non_empty_string(skipped, "message", entry_location, issues)

    return import_status


def _load_receipt_pack_entries(
    pack_dir: Path,
    issues: list[MetadataIssue],
) -> list[dict[str, Any]]:
    receipt_pack_path = pack_dir / "receipt_pack.jsonl"
    if not pack_dir.exists():
        issues.append(
            MetadataIssue(
                location="pack_dir",
                field="path",
                message=f"Pack directory does not exist: {pack_dir}",
            )
        )
        return []
    if not receipt_pack_path.exists():
        issues.append(
            MetadataIssue(
                location="pack_dir",
                field="receipt_pack.jsonl",
                message=f"Missing receipt_pack.jsonl in {pack_dir}",
            )
        )
        return []

    entries: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        receipt_pack_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not raw_line.strip():
            continue
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            issues.append(
                MetadataIssue(
                    location=f"receipt_pack.jsonl:{line_number}",
                    field="json",
                    message=f"Invalid JSON: {exc.msg}",
                )
            )
            continue
        if not isinstance(entry, dict):
            issues.append(
                MetadataIssue(
                    location=f"receipt_pack.jsonl:{line_number}",
                    field="entry",
                    message="Receipt-pack rows must remain JSON objects.",
                )
            )
            continue
        entries.append(entry)
    return entries


def _safe_load_json(
    path: Path,
    location: str,
    issues: list[MetadataIssue],
) -> Optional[dict[str, Any]]:
    if not path.exists():
        issues.append(
            MetadataIssue(
                location=location,
                field="path",
                message=f"Missing JSON file: {path}",
            )
        )
        return None
    try:
        payload = _load_json(path)
    except json.JSONDecodeError as exc:
        issues.append(
            MetadataIssue(
                location=location,
                field="json",
                message=f"Invalid JSON: {exc.msg}",
            )
        )
        return None
    if not isinstance(payload, dict):
        issues.append(
            MetadataIssue(
                location=location,
                field="root",
                message="Expected a JSON object.",
            )
        )
        return None
    return payload


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _resolve_path(base_dir: Path, raw_path: Any, field: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError(f"OpenClaw JSON is missing a usable {field} path.")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = (base_dir / candidate).resolve()
    return candidate.resolve()


def _optional_non_empty_string(mapping: dict[str, Any], field: str) -> Optional[str]:
    if field not in mapping:
        return None
    value = mapping[field]
    if value is None or not isinstance(value, str) or not value.strip():
        return None
    return value


def _value_as_non_empty_string(
    mapping: dict[str, Any],
    field: str,
    location: str,
    issues: list[MetadataIssue],
) -> Optional[str]:
    if field not in mapping:
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Missing required field.",
            )
        )
        return None
    value = mapping[field]
    if not isinstance(value, str) or not value.strip():
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Field must be present as a non-empty string.",
            )
        )
        return None
    return value


def _value_as_int(
    mapping: dict[str, Any],
    field: str,
    location: str,
    issues: list[MetadataIssue],
) -> Optional[int]:
    if field not in mapping:
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Missing required field.",
            )
        )
        return None
    value = mapping[field]
    if not isinstance(value, int) or isinstance(value, bool):
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Field must be present as an integer.",
            )
        )
        return None
    return value


def _value_as_bool(
    mapping: dict[str, Any],
    field: str,
    location: str,
    issues: list[MetadataIssue],
) -> Optional[bool]:
    if field not in mapping:
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Missing required field.",
            )
        )
        return None
    value = mapping[field]
    if not isinstance(value, bool):
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Field must be present as a boolean.",
            )
        )
        return None
    return value


def _value_as_list(
    mapping: dict[str, Any],
    field: str,
    location: str,
    issues: list[MetadataIssue],
) -> Optional[list[Any]]:
    if field not in mapping:
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Missing required field.",
            )
        )
        return None
    value = mapping[field]
    if not isinstance(value, list):
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Field must remain a list.",
            )
        )
        return None
    return value


def _value_as_dict(
    mapping: dict[str, Any],
    field: str,
    location: str,
    issues: list[MetadataIssue],
) -> Optional[dict[str, Any]]:
    if field not in mapping:
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Missing required field.",
            )
        )
        return None
    value = mapping[field]
    if not isinstance(value, dict):
        issues.append(
            MetadataIssue(
                location=location,
                field=field,
                message="Field must remain an object.",
            )
        )
        return None
    return value


if __name__ == "__main__":
    raise SystemExit(main())
