"""Compliance report generation for Assay evidence packs.

Maps evidence pack contents to specific regulatory framework controls.
Each control gets a verdict: PASS, FAIL, or UNKNOWN.

Supported frameworks:
- eu-ai-act: EU AI Act Articles 12 & 19
- soc2: SOC 2 Trust Services Criteria CC7.2
- iso42001: ISO/IEC 42001:2023
- nist-ai-rmf: NIST AI Risk Management Framework
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

COMPLIANCE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ControlSpec:
    """A single compliance control to evaluate."""

    control_id: str
    framework: str
    requirement: str
    check: str  # key into CHECKS registry
    citation: str
    severity: str  # "required" | "recommended"


@dataclass
class ControlResult:
    """Result of evaluating one control against a pack."""

    control_id: str
    verdict: str  # "PASS" | "FAIL" | "UNKNOWN"
    requirement: str
    evidence: str
    citation: str
    severity: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComplianceReport:
    """Full compliance report for one framework against one pack."""

    framework: str
    framework_label: str
    pack_id: str
    timestamp: str
    controls: List[ControlResult]
    summary: Dict[str, int]
    disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compliance_version": COMPLIANCE_VERSION,
            "framework": self.framework,
            "framework_label": self.framework_label,
            "pack_id": self.pack_id,
            "timestamp": self.timestamp,
            "controls": [c.to_dict() for c in self.controls],
            "summary": self.summary,
            "disclaimer": self.disclaimer,
        }


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

CheckFn = Callable[[Dict[str, Any], List[Dict[str, Any]]], Tuple[str, str]]


def check_receipts_present(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    n = pack_info.get("n_receipts", 0)
    if n > 0:
        return "PASS", f"{n} receipts recorded during execution."
    return "FAIL", "No receipts found in evidence pack."


def check_integrity_pass(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    if pack_info.get("integrity_pass"):
        return "PASS", "Ed25519 signature valid. SHA-256 file hashes match."
    errors = pack_info.get("errors", [])
    if errors:
        msgs = []
        for e in errors[:3]:
            msgs.append(e.get("message", str(e)) if isinstance(e, dict) else str(e))
        return "FAIL", f"Integrity check failed: {'; '.join(msgs)}"
    return "FAIL", "Integrity check did not pass."


def check_receipt_fields(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    required = {"receipt_id", "type", "timestamp"}
    missing_count = 0
    for r in receipts:
        missing = required - set(r.keys())
        if missing:
            missing_count += 1
    if not receipts:
        return "FAIL", "No receipts to check."
    if missing_count == 0:
        return "PASS", f"All {len(receipts)} receipts have receipt_id, type, and timestamp."
    return "FAIL", f"{missing_count}/{len(receipts)} receipts missing required identification fields."


def check_monitoring_fields(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    model_calls = [r for r in receipts if r.get("type") == "model_call"]
    if not model_calls:
        return "FAIL", "No model_call receipts found for monitoring data."
    monitored = {"model_id", "provider"}
    complete = 0
    for r in model_calls:
        if monitored.issubset(set(r.keys())):
            complete += 1
    if complete == len(model_calls):
        return "PASS", f"All {len(model_calls)} model_call receipts include model_id and provider."
    return "FAIL", f"{complete}/{len(model_calls)} model_call receipts have complete monitoring fields."


def check_portable_pack(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    # If we got here, the pack was loaded from portable files.
    return "PASS", "Evidence pack exists as portable, self-contained files."


def check_retention(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    return (
        "UNKNOWN",
        "Assay produces retainable evidence packs but does not enforce "
        "retention policy. Verify organizational retention procedures separately.",
    )


def check_claims_evaluated(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    if pack_info.get("claims_present"):
        n = len(pack_info.get("claim_results", []))
        status = pack_info.get("claims_status", "NONE")
        return "PASS", f"Governance claims evaluated ({n} claims, result: {status})."
    return "FAIL", "No governance claims were defined or evaluated for this pack."


def check_manifest_present(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    pack_id = pack_info.get("pack_id", "unknown")
    if pack_id != "unknown":
        return "PASS", f"Pack manifest present with attestation (pack_id: {pack_id})."
    return "FAIL", "Pack manifest missing or incomplete."


def check_signer_present(
    pack_info: Dict[str, Any], receipts: List[Dict[str, Any]]
) -> Tuple[str, str]:
    signer = pack_info.get("signer_id", "unknown")
    if signer != "unknown":
        return "PASS", f"Pack signed by '{signer}' with Ed25519 key."
    return "FAIL", "No signer identity found in pack manifest."


CHECKS: Dict[str, CheckFn] = {
    "check_receipts_present": check_receipts_present,
    "check_integrity_pass": check_integrity_pass,
    "check_receipt_fields": check_receipt_fields,
    "check_monitoring_fields": check_monitoring_fields,
    "check_portable_pack": check_portable_pack,
    "check_retention": check_retention,
    "check_claims_evaluated": check_claims_evaluated,
    "check_manifest_present": check_manifest_present,
    "check_signer_present": check_signer_present,
}

# ---------------------------------------------------------------------------
# Framework definitions
# ---------------------------------------------------------------------------

FRAMEWORK_LABELS: Dict[str, str] = {
    "eu-ai-act": "EU AI Act (Articles 12 & 19)",
    "soc2": "SOC 2 Trust Services Criteria (CC7.2)",
    "iso42001": "ISO/IEC 42001:2023",
    "nist-ai-rmf": "NIST AI Risk Management Framework",
}

FRAMEWORKS: Dict[str, List[ControlSpec]] = {
    "eu-ai-act": [
        ControlSpec(
            "EU-12.1", "eu-ai-act",
            "Automatic event logging",
            "check_receipts_present",
            "EU AI Act Article 12: automatic recording of events (logs)",
            "required",
        ),
        ControlSpec(
            "EU-12.2", "eu-ai-act",
            "Tamper-detectable logging",
            "check_integrity_pass",
            "EU AI Act Article 12: tamper-detectable checkpoint evidence",
            "required",
        ),
        ControlSpec(
            "EU-12.3", "eu-ai-act",
            "Event identification fields",
            "check_receipt_fields",
            "EU AI Act Article 12: events identifiable by type and timestamp",
            "required",
        ),
        ControlSpec(
            "EU-12.4", "eu-ai-act",
            "Operational monitoring data",
            "check_monitoring_fields",
            "EU AI Act Article 12: operational monitoring of system components",
            "required",
        ),
        ControlSpec(
            "EU-19.1", "eu-ai-act",
            "Log retention capability",
            "check_portable_pack",
            "EU AI Act Article 19: logs retained for >= 6 months",
            "required",
        ),
        ControlSpec(
            "EU-19.2", "eu-ai-act",
            "Retention period enforcement",
            "check_retention",
            "EU AI Act Article 19: organizational retention policy",
            "recommended",
        ),
    ],
    "soc2": [
        ControlSpec(
            "SOC2-CC7.2.1", "soc2",
            "System component monitoring",
            "check_monitoring_fields",
            "AICPA TSP CC7.2: monitor system components for anomalies",
            "required",
        ),
        ControlSpec(
            "SOC2-CC7.2.2", "soc2",
            "Anomaly detection capability",
            "check_claims_evaluated",
            "AICPA TSP CC7.2: anomalies analyzed as security events",
            "required",
        ),
        ControlSpec(
            "SOC2-CC7.2.3", "soc2",
            "Security event analysis",
            "check_integrity_pass",
            "AICPA TSP CC7.2: integrity of monitoring evidence",
            "required",
        ),
        ControlSpec(
            "SOC2-CC7.2.4", "soc2",
            "Evidence of ongoing monitoring",
            "check_receipts_present",
            "AICPA TSP CC7.2: continuous monitoring of operations",
            "required",
        ),
    ],
    "iso42001": [
        ControlSpec(
            "ISO-DOC.1", "iso42001",
            "AI system documentation",
            "check_manifest_present",
            "ISO/IEC 42001:2023: AI management system documentation",
            "required",
        ),
        ControlSpec(
            "ISO-DOC.2", "iso42001",
            "Governance process evidence",
            "check_claims_evaluated",
            "ISO/IEC 42001:2023: evidence of governance processes",
            "required",
        ),
        ControlSpec(
            "ISO-DOC.3", "iso42001",
            "Cryptographic authenticity",
            "check_integrity_pass",
            "ISO/IEC 42001:2023: documented evidence integrity",
            "required",
        ),
        ControlSpec(
            "ISO-DOC.4", "iso42001",
            "Continuous evaluation evidence",
            "check_receipts_present",
            "ISO/IEC 42001:2023: evidence of ongoing evaluation",
            "required",
        ),
    ],
    "nist-ai-rmf": [
        ControlSpec(
            "NIST-GOV.1", "nist-ai-rmf",
            "Governance accountability",
            "check_signer_present",
            "NIST AI RMF GOVERN: accountability for AI system governance",
            "required",
        ),
        ControlSpec(
            "NIST-MAP.1", "nist-ai-rmf",
            "AI system mapping",
            "check_monitoring_fields",
            "NIST AI RMF MAP: document AI system components and behavior",
            "required",
        ),
        ControlSpec(
            "NIST-MEASURE.1", "nist-ai-rmf",
            "Measurement and metrics",
            "check_monitoring_fields",
            "NIST AI RMF MEASURE: metrics for AI system performance",
            "required",
        ),
        ControlSpec(
            "NIST-MANAGE.1", "nist-ai-rmf",
            "Risk management evidence",
            "check_claims_evaluated",
            "NIST AI RMF MANAGE: evidence of risk management activities",
            "required",
        ),
    ],
}

ALL_FRAMEWORK_IDS = list(FRAMEWORKS.keys())

# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------


def _load_pack_data(pack_dir: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Load pack info and receipts from a pack directory."""
    from assay.explain import explain_pack

    pack_info = explain_pack(pack_dir)

    # Load raw receipts for field-level checks
    receipt_path = pack_dir / "receipt_pack.jsonl"
    receipts: List[Dict[str, Any]] = []
    if receipt_path.exists():
        text = receipt_path.read_text().strip()
        if text:
            for line in text.split("\n"):
                line = line.strip()
                if line:
                    receipts.append(json.loads(line))

    return pack_info, receipts


def evaluate_compliance(
    pack_dir: Path,
    framework_id: str,
) -> ComplianceReport:
    """Evaluate a pack against a compliance framework.

    Args:
        pack_dir: Path to proof pack directory.
        framework_id: One of: eu-ai-act, soc2, iso42001, nist-ai-rmf.

    Returns:
        ComplianceReport with per-control verdicts.

    Raises:
        ValueError: If framework_id is not recognized.
    """
    if framework_id not in FRAMEWORKS:
        raise ValueError(
            f"Unknown framework: {framework_id}. "
            f"Supported: {', '.join(ALL_FRAMEWORK_IDS)}"
        )

    pack_info, receipts = _load_pack_data(pack_dir)
    controls = FRAMEWORKS[framework_id]
    results: List[ControlResult] = []

    for spec in controls:
        check_fn = CHECKS[spec.check]
        verdict, evidence = check_fn(pack_info, receipts)
        results.append(
            ControlResult(
                control_id=spec.control_id,
                verdict=verdict,
                requirement=spec.requirement,
                evidence=evidence,
                citation=spec.citation,
                severity=spec.severity,
            )
        )

    passed = sum(1 for r in results if r.verdict == "PASS")
    failed = sum(1 for r in results if r.verdict == "FAIL")
    unknown = sum(1 for r in results if r.verdict == "UNKNOWN")

    return ComplianceReport(
        framework=framework_id,
        framework_label=FRAMEWORK_LABELS[framework_id],
        pack_id=pack_info.get("pack_id", "unknown"),
        timestamp=datetime.now(timezone.utc).isoformat(),
        controls=results,
        summary={"total": len(results), "passed": passed, "failed": failed, "unknown": unknown},
        disclaimer=(
            "This report maps evidence pack contents to framework controls. "
            "It does not constitute full compliance with any framework on its own. "
            "Consult your compliance team or legal counsel for framework-specific requirements."
        ),
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

_VERDICT_SYMBOLS = {"PASS": "PASS", "FAIL": "FAIL", "UNKNOWN": "----"}


def render_compliance_text(report: ComplianceReport) -> str:
    """Render compliance report as plain text for console output."""
    lines: List[str] = []

    lines.append(f"COMPLIANCE REPORT: {report.framework_label}")
    lines.append(f"Pack: {report.pack_id}")
    lines.append("")

    # Summary line
    s = report.summary
    lines.append(
        f"Controls: {s['total']} total, "
        f"{s['passed']} PASS, {s['failed']} FAIL, {s['unknown']} UNKNOWN"
    )
    lines.append("")

    # Per-control results
    for c in report.controls:
        symbol = _VERDICT_SYMBOLS.get(c.verdict, c.verdict)
        lines.append(f"  [{symbol}] {c.control_id}: {c.requirement}")
        lines.append(f"          {c.evidence}")
        lines.append(f"          Citation: {c.citation}")
        lines.append("")

    # Disclaimer
    lines.append(f"Disclaimer: {report.disclaimer}")
    lines.append("")

    return "\n".join(lines)


def render_compliance_md(report: ComplianceReport) -> str:
    """Render compliance report as markdown."""
    lines: List[str] = []

    lines.append(f"# Compliance Report: {report.framework_label}")
    lines.append("")
    lines.append(f"**Pack ID:** `{report.pack_id}`")
    lines.append(f"**Generated:** {report.timestamp}")
    lines.append("")

    # Summary
    s = report.summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Total | PASS | FAIL | UNKNOWN |")
    lines.append(f"|-------|------|------|---------|")
    lines.append(f"| {s['total']} | {s['passed']} | {s['failed']} | {s['unknown']} |")
    lines.append("")

    # Controls table
    lines.append("## Controls")
    lines.append("")
    lines.append("| Control | Requirement | Verdict | Evidence |")
    lines.append("|---------|-------------|---------|----------|")
    for c in report.controls:
        lines.append(f"| `{c.control_id}` | {c.requirement} | **{c.verdict}** | {c.evidence} |")
    lines.append("")

    # Citations
    lines.append("## Citations")
    lines.append("")
    for c in report.controls:
        lines.append(f"- **{c.control_id}**: {c.citation}")
    lines.append("")

    # Disclaimer
    lines.append("---")
    lines.append("")
    lines.append(f"*{report.disclaimer}*")
    lines.append("")

    return "\n".join(lines)


__all__ = [
    "COMPLIANCE_VERSION",
    "ALL_FRAMEWORK_IDS",
    "FRAMEWORKS",
    "FRAMEWORK_LABELS",
    "ControlSpec",
    "ControlResult",
    "ComplianceReport",
    "evaluate_compliance",
    "render_compliance_text",
    "render_compliance_md",
]
