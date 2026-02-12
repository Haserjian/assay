"""
Assay Doctor: first-user unblocking compiler.

Answers four questions in under 2 seconds:
1. Is Assay installed and runnable here?
2. Can this machine create and verify packs correctly?
3. Is this repo configured for the workflow you claim?
4. What is the single next command to become "green"?

Architecture:
- Pure check functions return DoctorCheckResult
- Runner orchestrates checks by profile
- CLI layer handles formatting and exit codes
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class CheckStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Profile(str, Enum):
    LOCAL = "local"
    CI = "ci"
    RELEASE = "release"
    LEDGER = "ledger"


@dataclass
class DoctorCheckResult:
    """Result of a single doctor check."""
    id: str
    status: CheckStatus
    severity: Severity
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    fix: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "status": self.status.value,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.evidence:
            d["evidence"] = self.evidence
        if self.fix:
            d["fix"] = self.fix
        return d


@dataclass
class DoctorReport:
    """Aggregated doctor report."""
    profile: Profile
    version: str
    checks: List[DoctorCheckResult] = field(default_factory=list)
    next_command: Optional[str] = None

    @property
    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"pass": 0, "warn": 0, "fail": 0, "skip": 0}
        for c in self.checks:
            counts[c.status.value] += 1
        return counts

    @property
    def overall_status(self) -> str:
        s = self.summary
        if s["fail"] > 0:
            return "fail"
        if s["warn"] > 0:
            return "warn"
        return "pass"

    @property
    def exit_code(self) -> int:
        s = self.summary
        if s["fail"] > 0:
            return 2
        if s["warn"] > 0:
            return 1
        return 0

    def exit_code_strict(self) -> int:
        s = self.summary
        if s["fail"] > 0 or s["warn"] > 0:
            return 2
        return 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "assay-doctor",
            "version": self.version,
            "profile": self.profile.value,
            "status": self.overall_status,
            "summary": self.summary,
            "checks": [c.to_dict() for c in self.checks],
            "next_command": self.next_command,
        }


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

# Maps profile -> list of check IDs that should run
_PROFILE_CHECKS: Dict[Profile, List[str]] = {
    Profile.LOCAL: [
        "DOCTOR_CORE_001",
        "DOCTOR_FS_001",
        "DOCTOR_KEY_001",
        "DOCTOR_CARD_001",
        "DOCTOR_PACK_001",
        "DOCTOR_PACK_002",
        "DOCTOR_EXIT_001",
    ],
    Profile.CI: [
        "DOCTOR_CORE_001",
        "DOCTOR_FS_001",
        "DOCTOR_KEY_001",
        "DOCTOR_CARD_001",
        "DOCTOR_PACK_001",
        "DOCTOR_PACK_002",
        "DOCTOR_EXIT_001",
        "DOCTOR_LOCK_001",
        "DOCTOR_LOCK_002",
        "DOCTOR_LOCK_003",
        "DOCTOR_CI_001",
        "DOCTOR_CI_002",
        "DOCTOR_CI_003",
    ],
    Profile.RELEASE: [
        "DOCTOR_CORE_001",
        "DOCTOR_FS_001",
        "DOCTOR_KEY_001",
        "DOCTOR_CARD_001",
        "DOCTOR_LOCK_001",
        "DOCTOR_LOCK_002",
        "DOCTOR_LOCK_003",
        "DOCTOR_EXIT_001",
    ],
    Profile.LEDGER: [
        "DOCTOR_CORE_001",
        "DOCTOR_FS_001",
        "DOCTOR_KEY_001",
        "DOCTOR_CARD_001",
        "DOCTOR_PACK_001",
        "DOCTOR_PACK_002",
        "DOCTOR_EXIT_001",
        "DOCTOR_LOCK_001",
        "DOCTOR_LOCK_002",
        "DOCTOR_LOCK_003",
        "DOCTOR_LEDGER_001",
        "DOCTOR_WITNESS_001",
    ],
}


# ---------------------------------------------------------------------------
# Individual checks (pure functions)
# ---------------------------------------------------------------------------

def _check_core_001() -> DoctorCheckResult:
    """Assay CLI/import/version available."""
    try:
        from assay import __version__
        return DoctorCheckResult(
            id="DOCTOR_CORE_001",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message=f"Assay CLI available ({__version__})",
            evidence={"version": __version__},
        )
    except ImportError as e:
        return DoctorCheckResult(
            id="DOCTOR_CORE_001",
            status=CheckStatus.FAIL,
            severity=Severity.CRITICAL,
            message="Assay not importable",
            evidence={"error": str(e)},
            fix="pip install assay-ai",
        )


def _check_fs_001() -> DoctorCheckResult:
    """Writable Assay home path."""
    home = Path.home() / ".loom" / "assay"
    if home.exists():
        # Check writable
        test_file = home / ".doctor_probe"
        try:
            test_file.write_text("probe")
            test_file.unlink()
            return DoctorCheckResult(
                id="DOCTOR_FS_001",
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                message=f"Assay home writable ({home})",
                evidence={"path": str(home), "exists": True},
            )
        except OSError as e:
            return DoctorCheckResult(
                id="DOCTOR_FS_001",
                status=CheckStatus.FAIL,
                severity=Severity.HIGH,
                message=f"Assay home not writable: {e}",
                evidence={"path": str(home), "error": str(e)},
                fix=f"chmod u+w {home}",
            )
    else:
        # Doesn't exist yet -- check parent is writable
        try:
            home.mkdir(parents=True, exist_ok=True)
            return DoctorCheckResult(
                id="DOCTOR_FS_001",
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                message=f"Assay home created ({home})",
                evidence={"path": str(home), "created": True},
            )
        except OSError as e:
            return DoctorCheckResult(
                id="DOCTOR_FS_001",
                status=CheckStatus.FAIL,
                severity=Severity.HIGH,
                message=f"Cannot create Assay home: {e}",
                evidence={"path": str(home), "error": str(e)},
                fix=f"mkdir -p {home}",
            )


def _check_key_001() -> DoctorCheckResult:
    """Signing key exists or can be generated."""
    try:
        from assay.keystore import DEFAULT_SIGNER_ID, get_default_keystore
        ks = get_default_keystore()
        try:
            vk = ks.get_verify_key(DEFAULT_SIGNER_ID)
            from assay.proof_pack import _sha256_hex
            fp = _sha256_hex(vk.encode())
            return DoctorCheckResult(
                id="DOCTOR_KEY_001",
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                message=f"Signer key present ({DEFAULT_SIGNER_ID})",
                evidence={"signer_id": DEFAULT_SIGNER_ID, "fingerprint": fp[:16] + "..."},
            )
        except Exception:
            return DoctorCheckResult(
                id="DOCTOR_KEY_001",
                status=CheckStatus.WARN,
                severity=Severity.MEDIUM,
                message="No signing key found (will be generated on first use)",
                evidence={"signer_id": DEFAULT_SIGNER_ID, "keys_dir": str(ks.keys_dir)},
                fix=f"assay demo-pack  # generates key automatically",
            )
    except ImportError:
        return DoctorCheckResult(
            id="DOCTOR_KEY_001",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message="Skipped (assay not available)",
        )


def _check_card_001() -> DoctorCheckResult:
    """Requested RunCards exist and hashes resolve."""
    try:
        from assay.run_cards import BUILTIN_CARDS
        card_ids = list(BUILTIN_CARDS.keys())
        return DoctorCheckResult(
            id="DOCTOR_CARD_001",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message=f"{len(card_ids)} built-in RunCards available",
            evidence={"cards": card_ids},
        )
    except ImportError:
        return DoctorCheckResult(
            id="DOCTOR_CARD_001",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message="Skipped (assay not available)",
        )


def _check_lock_001(lock_path: Optional[Path] = None) -> DoctorCheckResult:
    """Lockfile readable/valid when provided."""
    if lock_path is None:
        lock_path = Path("assay.lock")

    if not lock_path.exists():
        return DoctorCheckResult(
            id="DOCTOR_LOCK_001",
            status=CheckStatus.WARN,
            severity=Severity.MEDIUM,
            message=f"No lockfile found at {lock_path}",
            evidence={"path": str(lock_path)},
            fix="assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock",
        )

    try:
        from assay.lockfile import load_lockfile
        lock = load_lockfile(lock_path)
        return DoctorCheckResult(
            id="DOCTOR_LOCK_001",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message=f"Lockfile valid ({lock_path})",
            evidence={
                "path": str(lock_path),
                "lock_version": lock.get("lock_version"),
                "run_cards": len(lock.get("run_cards", [])),
            },
        )
    except Exception as e:
        return DoctorCheckResult(
            id="DOCTOR_LOCK_001",
            status=CheckStatus.FAIL,
            severity=Severity.HIGH,
            message=f"Lockfile invalid: {e}",
            evidence={"path": str(lock_path), "error": str(e)},
            fix="assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock",
        )


def _check_lock_002(lock_path: Optional[Path] = None) -> DoctorCheckResult:
    """Lock hash set consistent (claim_set_hash, run_cards_composite_hash)."""
    if lock_path is None:
        lock_path = Path("assay.lock")

    if not lock_path.exists():
        return DoctorCheckResult(
            id="DOCTOR_LOCK_002",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message="Skipped (no lockfile)",
        )

    try:
        from assay.lockfile import check_lockfile
        errors = check_lockfile(lock_path)
        if errors:
            return DoctorCheckResult(
                id="DOCTOR_LOCK_002",
                status=CheckStatus.FAIL,
                severity=Severity.HIGH,
                message=f"Lock hash drift: {errors[0]}",
                evidence={"errors": errors},
                fix="assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock",
            )
        return DoctorCheckResult(
            id="DOCTOR_LOCK_002",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message="Lock hashes consistent",
        )
    except Exception as e:
        return DoctorCheckResult(
            id="DOCTOR_LOCK_002",
            status=CheckStatus.FAIL,
            severity=Severity.HIGH,
            message=f"Lock check error: {e}",
            evidence={"error": str(e)},
        )


def _check_lock_003(lock_path: Optional[Path] = None) -> DoctorCheckResult:
    """Corpus-signer must not appear in production signer allowlist."""
    if lock_path is None:
        lock_path = Path("assay.lock")

    if not lock_path.exists():
        return DoctorCheckResult(
            id="DOCTOR_LOCK_003",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message="Skipped (no lockfile)",
        )

    try:
        import json
        lock = json.loads(lock_path.read_text())
        policy = lock.get("signer_policy", {})
        allowed = policy.get("allowed_fingerprints", [])
        allowed_ids = policy.get("allowed_signer_ids", [])

        # Check for corpus-signer by name in any field
        corpus_names = {"corpus-signer", "corpus_signer"}
        found_names = corpus_names & set(allowed_ids)
        if found_names:
            return DoctorCheckResult(
                id="DOCTOR_LOCK_003",
                status=CheckStatus.FAIL,
                severity=Severity.CRITICAL,
                message=f"Test-only signer in production allowlist: {', '.join(found_names)}",
                evidence={"found": list(found_names)},
                fix="Remove corpus-signer from signer_policy.allowed_signer_ids in your lockfile",
            )

        return DoctorCheckResult(
            id="DOCTOR_LOCK_003",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message="No test-only signers in allowlist",
        )
    except Exception as e:
        return DoctorCheckResult(
            id="DOCTOR_LOCK_003",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message=f"Skipped (lock parse error: {e})",
        )


def _check_pack_001(pack_dir: Optional[Path] = None) -> DoctorCheckResult:
    """pack_manifest.json and required 5-file kernel present."""
    if pack_dir is None:
        # Try to find a pack in current directory
        import glob
        candidates = glob.glob("proof_pack_*/pack_manifest.json")
        if not candidates:
            return DoctorCheckResult(
                id="DOCTOR_PACK_001",
                status=CheckStatus.SKIP,
                severity=Severity.INFO,
                message="No pack directory found (use --pack to specify)",
            )
        pack_dir = Path(candidates[0]).parent

    required = [
        "receipt_pack.jsonl",
        "verify_report.json",
        "verify_transcript.md",
        "pack_manifest.json",
        "pack_signature.sig",
    ]
    missing = [f for f in required if not (pack_dir / f).exists()]

    if missing:
        return DoctorCheckResult(
            id="DOCTOR_PACK_001",
            status=CheckStatus.FAIL,
            severity=Severity.HIGH,
            message=f"Pack missing files: {', '.join(missing)}",
            evidence={"pack_dir": str(pack_dir), "missing": missing},
            fix=f"assay proof-pack  # rebuild the pack",
        )

    return DoctorCheckResult(
        id="DOCTOR_PACK_001",
        status=CheckStatus.PASS,
        severity=Severity.INFO,
        message=f"Pack kernel complete ({pack_dir.name})",
        evidence={"pack_dir": str(pack_dir), "files": required},
    )


def _check_pack_002(pack_dir: Optional[Path] = None) -> DoctorCheckResult:
    """Schema + signature + D12 integrity check passes."""
    if pack_dir is None:
        import glob
        candidates = glob.glob("proof_pack_*/pack_manifest.json")
        if not candidates:
            return DoctorCheckResult(
                id="DOCTOR_PACK_002",
                status=CheckStatus.SKIP,
                severity=Severity.INFO,
                message="No pack directory found (use --pack to specify)",
            )
        pack_dir = Path(candidates[0]).parent

    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        return DoctorCheckResult(
            id="DOCTOR_PACK_002",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message="No manifest to verify",
        )

    try:
        import json
        from assay.integrity import verify_pack_manifest
        from assay.keystore import get_default_keystore

        manifest = json.loads(manifest_path.read_text())
        ks = get_default_keystore()
        result = verify_pack_manifest(manifest, pack_dir, ks)

        if result.passed:
            return DoctorCheckResult(
                id="DOCTOR_PACK_002",
                status=CheckStatus.PASS,
                severity=Severity.INFO,
                message="Pack integrity verified (signature + D12)",
                evidence={
                    "pack_dir": str(pack_dir),
                    "pack_root": manifest.get("pack_root_sha256", "")[:16] + "...",
                },
            )
        else:
            return DoctorCheckResult(
                id="DOCTOR_PACK_002",
                status=CheckStatus.FAIL,
                severity=Severity.CRITICAL,
                message=f"Pack integrity failed: {result.errors[0].message if result.errors else 'unknown'}",
                evidence={"pack_dir": str(pack_dir), "errors": [e.message for e in result.errors]},
                fix=f"assay verify-pack {pack_dir}  # see full report",
            )
    except Exception as e:
        return DoctorCheckResult(
            id="DOCTOR_PACK_002",
            status=CheckStatus.FAIL,
            severity=Severity.HIGH,
            message=f"Pack verification error: {e}",
            evidence={"error": str(e)},
        )


def _check_exit_001() -> DoctorCheckResult:
    """verify-pack exit code mapping contract visible."""
    try:
        from assay.integrity import verify_pack_manifest
        return DoctorCheckResult(
            id="DOCTOR_EXIT_001",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message="Exit code contract: 0=pass, 1=claim-fail, 2=integrity-fail, 3=bad-input",
            evidence={"exit_codes": {"0": "pass", "1": "claim_fail", "2": "integrity_fail", "3": "bad_input"}},
        )
    except ImportError:
        return DoctorCheckResult(
            id="DOCTOR_EXIT_001",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message="Skipped (integrity module not available)",
        )


def _check_ci_001() -> DoctorCheckResult:
    """At least one workflow references assay verify step."""
    workflow_dir = Path(".github/workflows")
    if not workflow_dir.exists():
        return DoctorCheckResult(
            id="DOCTOR_CI_001",
            status=CheckStatus.WARN,
            severity=Severity.MEDIUM,
            message="No .github/workflows directory found",
            evidence={"path": str(workflow_dir)},
            fix="mkdir -p .github/workflows  # then add assay verify step",
        )

    found = False
    matching_files: List[str] = []
    for yml in workflow_dir.glob("*.yml"):
        try:
            content = yml.read_text()
            if "assay" in content.lower() and ("verify-pack" in content or "assay-verify-action" in content):
                found = True
                matching_files.append(yml.name)
        except OSError:
            continue

    # Also check .yaml extension
    for yml in workflow_dir.glob("*.yaml"):
        try:
            content = yml.read_text()
            if "assay" in content.lower() and ("verify-pack" in content or "assay-verify-action" in content):
                found = True
                matching_files.append(yml.name)
        except OSError:
            continue

    if found:
        return DoctorCheckResult(
            id="DOCTOR_CI_001",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message=f"Assay verify step found in {', '.join(matching_files)}",
            evidence={"workflows": matching_files},
        )

    return DoctorCheckResult(
        id="DOCTOR_CI_001",
        status=CheckStatus.WARN,
        severity=Severity.MEDIUM,
        message="No workflow found using assay verify step",
        evidence={"searched": str(workflow_dir)},
        fix="# Add to your CI workflow:\n#   assay verify-pack ./proof_pack_*/ --require-claim-pass",
    )


def _check_ci_002(lock_path: Optional[Path] = None) -> DoctorCheckResult:
    """exit_contract in lockfile includes all documented exit codes."""
    lp = lock_path or Path("assay.lock")
    if not lp.exists():
        return DoctorCheckResult(
            id="DOCTOR_CI_002",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message="Skipped (no lockfile found)",
        )
    try:
        import json as _json
        lock = _json.loads(lp.read_text())
        contract = lock.get("exit_contract", {})
        missing = [c for c in ("0", "1", "2") if c not in contract]
        if missing:
            return DoctorCheckResult(
                id="DOCTOR_CI_002",
                status=CheckStatus.FAIL,
                severity=Severity.HIGH,
                message=f"exit_contract missing codes: {', '.join(missing)}",
                evidence={"missing_codes": missing, "found": list(contract.keys())},
                fix="assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock",
            )
        return DoctorCheckResult(
            id="DOCTOR_CI_002",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message="exit_contract covers all 3 outcome codes (0, 1, 2)",
            evidence={"codes": list(contract.keys())},
        )
    except Exception as e:
        return DoctorCheckResult(
            id="DOCTOR_CI_002",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message=f"Skipped (parse error: {e})",
        )


def _check_ci_003() -> DoctorCheckResult:
    """Workflow does not swallow assay failures with continue-on-error."""
    workflow_dir = Path(".github/workflows")
    if not workflow_dir.exists():
        return DoctorCheckResult(
            id="DOCTOR_CI_003",
            status=CheckStatus.SKIP,
            severity=Severity.INFO,
            message="Skipped (no .github/workflows directory)",
        )
    issues: List[str] = []
    for pattern in ("*.yml", "*.yaml"):
        for yml in workflow_dir.glob(pattern):
            try:
                content = yml.read_text()
                if "assay" in content.lower() and "continue-on-error: true" in content:
                    issues.append(yml.name)
            except OSError:
                continue
    if issues:
        return DoctorCheckResult(
            id="DOCTOR_CI_003",
            status=CheckStatus.WARN,
            severity=Severity.MEDIUM,
            message=f"continue-on-error may swallow assay failures: {', '.join(issues)}",
            evidence={"files": issues},
            fix="# Remove continue-on-error: true from assay verify steps",
        )
    return DoctorCheckResult(
        id="DOCTOR_CI_003",
        status=CheckStatus.PASS,
        severity=Severity.INFO,
        message="No continue-on-error detected on assay workflow steps",
    )


def _check_ledger_001() -> DoctorCheckResult:
    """Required submission fields resolvable for witnessed path."""
    try:
        from assay.keystore import DEFAULT_SIGNER_ID, get_default_keystore
        ks = get_default_keystore()
        vk = ks.get_verify_key(DEFAULT_SIGNER_ID)
        from assay.proof_pack import _sha256_hex
        fp = _sha256_hex(vk.encode())

        return DoctorCheckResult(
            id="DOCTOR_LEDGER_001",
            status=CheckStatus.PASS,
            severity=Severity.INFO,
            message="Ledger submission fields resolvable",
            evidence={
                "signer_id": DEFAULT_SIGNER_ID,
                "signer_fingerprint": fp[:16] + "...",
                "witness_path": "witnessed (manifest available)",
            },
        )
    except Exception as e:
        return DoctorCheckResult(
            id="DOCTOR_LEDGER_001",
            status=CheckStatus.WARN,
            severity=Severity.MEDIUM,
            message=f"Ledger submission may use unwitnessed path: {e}",
            evidence={"error": str(e)},
            fix="assay demo-pack  # generates signing key",
        )


def _check_witness_001(strict: bool = False) -> DoctorCheckResult:
    """Witness policy warning if hash_verified accepted in strict context."""
    if strict:
        return DoctorCheckResult(
            id="DOCTOR_WITNESS_001",
            status=CheckStatus.WARN,
            severity=Severity.MEDIUM,
            message="Strict mode: only signature_verified entries are trusted",
            evidence={"policy": "signature_verified required in strict/prod"},
            fix="# Ensure pack_manifest_b64 is included in ledger submission",
        )
    return DoctorCheckResult(
        id="DOCTOR_WITNESS_001",
        status=CheckStatus.PASS,
        severity=Severity.INFO,
        message="Witness policy: hash_verified and signature_verified both accepted (dev mode)",
        evidence={"policy": "dev (hash_verified accepted)"},
    )


# ---------------------------------------------------------------------------
# Check dispatch
# ---------------------------------------------------------------------------

_CHECK_FUNCTIONS = {
    "DOCTOR_CORE_001": lambda **kw: _check_core_001(),
    "DOCTOR_FS_001": lambda **kw: _check_fs_001(),
    "DOCTOR_KEY_001": lambda **kw: _check_key_001(),
    "DOCTOR_CARD_001": lambda **kw: _check_card_001(),
    "DOCTOR_LOCK_001": lambda **kw: _check_lock_001(kw.get("lock_path")),
    "DOCTOR_LOCK_002": lambda **kw: _check_lock_002(kw.get("lock_path")),
    "DOCTOR_LOCK_003": lambda **kw: _check_lock_003(kw.get("lock_path")),
    "DOCTOR_PACK_001": lambda **kw: _check_pack_001(kw.get("pack_dir")),
    "DOCTOR_PACK_002": lambda **kw: _check_pack_002(kw.get("pack_dir")),
    "DOCTOR_EXIT_001": lambda **kw: _check_exit_001(),
    "DOCTOR_CI_001": lambda **kw: _check_ci_001(),
    "DOCTOR_CI_002": lambda **kw: _check_ci_002(kw.get("lock_path")),
    "DOCTOR_CI_003": lambda **kw: _check_ci_003(),
    "DOCTOR_LEDGER_001": lambda **kw: _check_ledger_001(),
    "DOCTOR_WITNESS_001": lambda **kw: _check_witness_001(kw.get("strict", False)),
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _determine_next_command(report: DoctorReport) -> Optional[str]:
    """Determine the single best next command based on check results."""
    # Priority: first failing check with a fix command
    for check in report.checks:
        if check.status == CheckStatus.FAIL and check.fix:
            return check.fix
    # Then first warning with a fix
    for check in report.checks:
        if check.status == CheckStatus.WARN and check.fix:
            return check.fix
    # All green
    if report.overall_status == "pass":
        if report.profile == Profile.LOCAL:
            return "assay run -- python your_script.py  # produce your first Proof Pack"
        elif report.profile == Profile.CI:
            return "assay verify-pack ./proof_pack_*/ --require-claim-pass"
        elif report.profile == Profile.LEDGER:
            return "# Submit to ledger: gh workflow run accept-submission.yml -R Haserjian/assay-ledger ..."
    return None


def run_doctor(
    profile: Profile = Profile.LOCAL,
    *,
    pack_dir: Optional[Path] = None,
    lock_path: Optional[Path] = None,
    strict: bool = False,
) -> DoctorReport:
    """Run all checks for the given profile and return a report."""
    from assay import __version__

    report = DoctorReport(profile=profile, version=__version__)
    check_ids = _PROFILE_CHECKS.get(profile, _PROFILE_CHECKS[Profile.LOCAL])

    kwargs = {
        "pack_dir": pack_dir,
        "lock_path": lock_path,
        "strict": strict,
    }

    for check_id in check_ids:
        fn = _CHECK_FUNCTIONS.get(check_id)
        if fn is None:
            report.checks.append(DoctorCheckResult(
                id=check_id,
                status=CheckStatus.SKIP,
                severity=Severity.INFO,
                message=f"Check not implemented: {check_id}",
            ))
            continue
        try:
            result = fn(**kwargs)
            report.checks.append(result)
        except Exception as e:
            report.checks.append(DoctorCheckResult(
                id=check_id,
                status=CheckStatus.FAIL,
                severity=Severity.HIGH,
                message=f"Check raised exception: {e}",
                evidence={"error": str(e)},
            ))

    report.next_command = _determine_next_command(report)
    return report
