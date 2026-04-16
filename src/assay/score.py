"""Evidence readiness scoring for Assay repositories.

`assay score` composes existing scanner, lockfile, CI, receipt, and key
signals into a single readiness score (0-100) with an A-F grade.

Important:
- This is an evidence-readiness score, not a security guarantee.
- Anti-gaming caps are applied (e.g., no receipts => max grade D).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from packaging.version import Version

from assay import __version__ as ASSAY_VERSION
from assay.keystore import get_default_keystore
from assay.lockfile import check_lockfile
from assay.scanner import scan_directory

SCORE_VERSION = "2.0.0"

# Weighted repo-scoped components (must sum to 100).
# key_setup was removed in v2: it read the operator's ~/.assay/keys/
# instead of the scanned repo, making scores non-reproducible (#78).
WEIGHTS: Dict[str, int] = {
    "coverage": 39,
    "lockfile": 17,
    "ci_gate": 22,
    "receipts": 22,
}

# Grade tier descriptions shown to users.
GRADE_TIERS: Dict[str, Tuple[str, str]] = {
    # grade -> (range_label, description)
    "A": ("90-100", "Full evidence pipeline with signed packs and ledger."),
    "B": ("80-89", "Strong pipeline with baseline tracking."),
    "C": ("70-79", "Active receipts and CI gate in place."),
    "D": ("60-69", "Basic lockfile and some instrumentation."),
    "F": ("<60", "No evidence pipeline -- most repos start here."),
}


def gather_score_facts(repo_path: Path) -> Dict[str, Any]:
    """Collect readiness facts for a repository path."""
    repo_path = repo_path.resolve()

    # Scanner facts
    scan_result = scan_directory(repo_path)
    scan_summary = scan_result.summary

    # Lockfile facts
    lock_path = repo_path / "assay.lock"
    lock_present = lock_path.exists()
    lock_issues: List[str] = []
    lock_valid = False
    lock_stale = False
    lock_meta: Dict[str, Any] = {}
    if lock_present:
        lock_issues = check_lockfile(lock_path)
        lock_valid = len(lock_issues) == 0
        # "Stale" here means present but failing current lock checks.
        lock_stale = not lock_valid
        try:
            lock_data = json.loads(lock_path.read_text(encoding="utf-8"))
            lock_meta = {
                "lock_version": lock_data.get("lock_version"),
                "assay_version_min": lock_data.get("assay_version_min"),
                "locked_by_assay_version": lock_data.get("locked_by_assay_version"),
            }
            # If lockfile was produced by a newer assay than current, mark stale.
            lb = lock_data.get("locked_by_assay_version")
            if lb:
                try:
                    if Version(lb) > Version(ASSAY_VERSION):
                        lock_stale = True
                        lock_issues = lock_issues + [f"lockfile created by newer assay ({lb})"]
                        lock_valid = False
                except Exception:
                    pass
        except Exception:
            pass

    # CI workflow facts
    ci = _analyze_ci_workflows(repo_path)

    # Receipt facts (repo-local only)
    receipts = _analyze_receipts(repo_path)

    # Key facts (global Assay keystore)
    keys = _analyze_keys()

    return {
        "repo_path": str(repo_path),
        "scan": scan_summary,
        "lockfile": {
            "present": lock_present,
            "valid": lock_valid,
            "stale": lock_stale,
            "issues": lock_issues,
            **lock_meta,
        },
        "ci": ci,
        "receipts": receipts,
        "keys": keys,
    }


def compute_evidence_readiness_score(facts: Dict[str, Any]) -> Dict[str, Any]:
    """Compute weighted score + grade + anti-gaming caps from gathered facts."""
    breakdown: Dict[str, Dict[str, Any]] = {}

    # 1) Coverage
    scan = facts.get("scan", {})
    sites_total = int(scan.get("sites_total", 0) or 0)
    instrumented = int(scan.get("instrumented", 0) or 0)
    uninstrumented = int(scan.get("uninstrumented", 0) or 0)

    if sites_total <= 0:
        coverage_points = round(WEIGHTS["coverage"] * 0.5, 1)
        coverage_status = "unknown"
        coverage_note = "No call sites detected by scanner; partial credit only."
    else:
        ratio = max(0.0, min(1.0, instrumented / sites_total))
        coverage_points = round(WEIGHTS["coverage"] * ratio, 1)
        coverage_status = "pass" if uninstrumented == 0 else "partial"
        coverage_note = f"{instrumented}/{sites_total} instrumented"

    breakdown["coverage"] = {
        "weight": WEIGHTS["coverage"],
        "points": coverage_points,
        "status": coverage_status,
        "note": coverage_note,
        "evidence": {
            "sites_total": sites_total,
            "instrumented": instrumented,
            "uninstrumented": uninstrumented,
        },
    }

    # 2) Lockfile policy
    lock = facts.get("lockfile", {})
    if lock.get("present") and lock.get("valid") and not lock.get("stale"):
        lock_points = float(WEIGHTS["lockfile"])
        lock_status = "pass"
        lock_note = "Lockfile present and valid."
    elif lock.get("present"):
        lock_points = round(WEIGHTS["lockfile"] * 0.45, 1)
        lock_status = "partial"
        lock_note = "Lockfile present but stale/invalid; partial credit."
    else:
        lock_points = 0.0
        lock_status = "fail"
        lock_note = "No lockfile."

    breakdown["lockfile"] = {
        "weight": WEIGHTS["lockfile"],
        "points": lock_points,
        "status": lock_status,
        "note": lock_note,
        "evidence": {
            "present": bool(lock.get("present")),
            "valid": bool(lock.get("valid")),
            "stale": bool(lock.get("stale")),
            "issues": lock.get("issues", []),
        },
    }

    # 3) CI gate quality
    ci = facts.get("ci", {})
    has_run = bool(ci.get("has_run"))
    has_verify = bool(ci.get("has_verify"))
    has_lock = bool(ci.get("has_lock"))
    has_assay_ref = bool(ci.get("has_assay_ref"))

    if has_run and has_verify and has_lock:
        ci_points = float(WEIGHTS["ci_gate"])
        ci_status = "pass"
        ci_note = "Run + verify + lock detected."
    elif has_run and has_verify:
        ci_points = round(WEIGHTS["ci_gate"] * 0.7, 1)
        ci_status = "partial"
        ci_note = "Run + verify detected; lock not enforced."
    elif has_verify and has_assay_ref:
        ci_points = round(WEIGHTS["ci_gate"] * 0.5, 1)
        ci_status = "partial"
        ci_note = "Verify detected; generation step unclear."
    elif has_assay_ref:
        ci_points = round(WEIGHTS["ci_gate"] * 0.25, 1)
        ci_status = "partial"
        ci_note = "Assay referenced in CI, but gate semantics incomplete."
    else:
        ci_points = 0.0
        ci_status = "fail"
        ci_note = "No evidence CI gate detected."

    breakdown["ci_gate"] = {
        "weight": WEIGHTS["ci_gate"],
        "points": ci_points,
        "status": ci_status,
        "note": ci_note,
        "evidence": {
            "workflow_count": int(ci.get("workflow_count", 0) or 0),
            "files": ci.get("files", []),
            "has_assay_ref": has_assay_ref,
            "has_run": has_run,
            "has_verify": has_verify,
            "has_lock": has_lock,
        },
    }

    # 4) Receipts present (repo-local anti-gaming anchor)
    rec = facts.get("receipts", {})
    repo_receipt_files = int(rec.get("repo_receipt_files", 0) or 0)
    if repo_receipt_files > 0:
        rec_points = float(WEIGHTS["receipts"])
        rec_status = "pass"
        rec_note = "Repository contains evidence receipts/packs."
    else:
        rec_points = 0.0
        rec_status = "fail"
        rec_note = "No repository-local receipts found."

    breakdown["receipts"] = {
        "weight": WEIGHTS["receipts"],
        "points": rec_points,
        "status": rec_status,
        "note": rec_note,
        "evidence": {
            "proof_pack_receipt_files": int(rec.get("proof_pack_receipt_files", 0) or 0),
            "mcp_session_files": int(rec.get("mcp_session_files", 0) or 0),
            "repo_receipt_files": repo_receipt_files,
        },
    }

    # 5) Key setup — environment-scoped, NOT included in composite (#78).
    # Reported for operator awareness but does not affect repo score.
    keys = facts.get("keys", {})
    signer_count = int(keys.get("signer_count", 0) or 0)
    if signer_count > 0:
        key_status = "pass"
        key_note = f"{signer_count} signer(s) configured (operator environment)."
    else:
        key_status = "info"
        key_note = "No signing key configured (operator environment — does not affect score)."

    breakdown["key_setup"] = {
        "scope": "environment",
        "weight": 0,
        "points": 0.0,
        "status": key_status,
        "note": key_note,
        "evidence": {
            "has_signer": signer_count > 0,
            "signer_count": signer_count,
        },
    }

    raw_score = round(sum(c["points"] for c in breakdown.values()), 1)
    raw_grade = _grade_for_score(raw_score)

    score = raw_score
    grade = raw_grade
    caps_applied: List[Dict[str, Any]] = []

    # Anti-gaming cap: no receipts => max grade D
    if repo_receipt_files == 0:
        capped_score, capped_grade = _apply_grade_cap(score, grade, "D")
        if capped_score != score or capped_grade != grade:
            caps_applied.append(
                {
                    "id": "CAP_NO_RECEIPTS_MAX_D",
                    "reason": "No repository-local receipts detected.",
                    "max_grade": "D",
                    "before": {"score": score, "grade": grade},
                    "after": {"score": capped_score, "grade": capped_grade},
                }
            )
        score, grade = capped_score, capped_grade

    actions_detail = _build_next_actions(facts, breakdown)
    # Backward-compatible plain-string list.
    next_actions = [
        f"{a['action']}: {a['command']}" if a["command"] else a["action"]
        for a in actions_detail
    ]
    fastest_path = _compute_fastest_path(score, grade, actions_detail)
    tier_range, tier_desc = GRADE_TIERS.get(grade, ("", ""))

    return {
        "score_version": SCORE_VERSION,
        "score": score,
        "grade": grade,
        "grade_description": tier_desc,
        "raw_score": raw_score,
        "raw_grade": raw_grade,
        "caps_applied": caps_applied,
        "breakdown": breakdown,
        "next_actions": next_actions,
        "next_actions_detail": actions_detail,
        "fastest_path": fastest_path,
        "disclaimer": (
            "Evidence Readiness Score is a readiness signal, not a security guarantee."
        ),
    }


def _analyze_ci_workflows(repo_path: Path) -> Dict[str, Any]:
    workflow_dir = repo_path / ".github" / "workflows"
    files: List[str] = []
    has_assay_ref = False
    has_run = False
    has_verify = False
    has_lock = False

    if workflow_dir.exists():
        candidates = sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))
        for wf in candidates:
            try:
                text = wf.read_text(encoding="utf-8").lower()
            except Exception:
                continue
            files.append(str(wf.relative_to(repo_path)))
            if "assay" in text or "assay-verify-action" in text:
                has_assay_ref = True
            if "assay run" in text:
                has_run = True
            if "assay verify-pack" in text or "assay-verify-action" in text:
                has_verify = True
            if "--lock " in text or "lock-file" in text:
                has_lock = True

    return {
        "workflow_count": len(files),
        "files": files,
        "has_assay_ref": has_assay_ref,
        "has_run": has_run,
        "has_verify": has_verify,
        "has_lock": has_lock,
    }


def _analyze_receipts(repo_path: Path) -> Dict[str, int]:
    proof_pack_receipt_files = len(list(repo_path.glob("proof_pack_*/receipt_pack.jsonl")))
    mcp_session_files = len(list((repo_path / ".assay" / "mcp" / "receipts").glob("session_*.jsonl")))
    repo_receipt_files = proof_pack_receipt_files + mcp_session_files
    return {
        "proof_pack_receipt_files": proof_pack_receipt_files,
        "mcp_session_files": mcp_session_files,
        "repo_receipt_files": repo_receipt_files,
    }


def _analyze_keys() -> Dict[str, Any]:
    try:
        ks = get_default_keystore()
        signers = ks.list_signers()
        return {
            "signer_count": len(signers),
            "active_signer": ks.get_active_signer() if signers else None,
        }
    except Exception:
        return {"signer_count": 0, "active_signer": None}


def _grade_for_score(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _apply_grade_cap(score: float, grade: str, max_grade: str) -> Tuple[float, str]:
    order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
    # Worse grade has lower order value.
    if order.get(grade, 1) <= order.get(max_grade, 1):
        return score, grade

    # Clamp score to top of capped band for deterministic rendering.
    max_score_by_grade = {"A": 100.0, "B": 89.9, "C": 79.9, "D": 69.9, "F": 59.9}
    return min(score, max_score_by_grade[max_grade]), max_grade


def _build_next_actions(
    facts: Dict[str, Any], breakdown: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Build prioritised next-actions with estimated point gains.

    Each action is ``{"action": str, "command": str, "component": str,
    "points_est": float}`` where *points_est* is the gap between the
    component's current points and its weight (i.e. max possible gain).
    """
    actions: List[Dict[str, Any]] = []
    scan = facts.get("scan", {})
    lock = facts.get("lockfile", {})
    ci = facts.get("ci", {})
    rec = facts.get("receipts", {})
    keys = facts.get("keys", {})

    def _gap(component: str) -> float:
        comp = breakdown.get(component, {})
        return round(comp.get("weight", 0) - comp.get("points", 0), 1)

    if int(scan.get("uninstrumented", 0) or 0) > 0:
        actions.append({
            "action": "Instrument gaps",
            "command": "assay patch .",
            "component": "coverage",
            "points_est": _gap("coverage"),
        })
    if int(rec.get("repo_receipt_files", 0) or 0) == 0:
        actions.append({
            "action": "Generate first evidence pack",
            "command": 'assay run -c receipt_completeness -- python your_app.py',
            "component": "receipts",
            "points_est": _gap("receipts"),
        })
    if not lock.get("present"):
        actions.append({
            "action": "Create lockfile",
            "command": "assay lock init",
            "component": "lockfile",
            "points_est": _gap("lockfile"),
        })
    elif not lock.get("valid"):
        actions.append({
            "action": "Repair stale lockfile",
            "command": "assay lock check && assay lock write --cards receipt_completeness -o assay.lock",
            "component": "lockfile",
            "points_est": _gap("lockfile"),
        })
    if not (ci.get("has_run") and ci.get("has_verify") and ci.get("has_lock")):
        actions.append({
            "action": "Harden CI gate",
            "command": 'assay ci init github --run-command "python your_app.py"',
            "component": "ci_gate",
            "points_est": _gap("ci_gate"),
        })
    if int(keys.get("signer_count", 0) or 0) == 0:
        actions.append({
            "action": "Initialize signer key (operator environment — does not affect score)",
            "command": 'assay run --allow-empty -- python -c "pass"',
            "component": "key_setup",
            "points_est": 0.0,
        })

    if not actions:
        actions.append({
            "action": "Ready",
            "command": "assay diff --gate-*",
            "component": "",
            "points_est": 0.0,
        })

    # Sort by largest gain first.
    actions.sort(key=lambda a: a["points_est"], reverse=True)
    return actions


def _compute_fastest_path(
    score: float, grade: str, next_actions: List[Dict[str, Any]]
) -> Dict[str, Any] | None:
    """Find the single action that gets closest to the next grade threshold."""
    if grade == "A" or not next_actions:
        return None

    thresholds = {"F": ("D", 60), "D": ("C", 70), "C": ("B", 80), "B": ("A", 90)}
    target_grade, target_score = thresholds.get(grade, ("A", 90))

    # Pick the action with the highest estimated gain.
    best = max(next_actions, key=lambda a: a["points_est"])
    if best["points_est"] <= 0:
        return None

    projected = round(score + best["points_est"], 1)
    return {
        "target_grade": target_grade,
        "target_score": target_score,
        "command": best["command"],
        "points_est": best["points_est"],
        "projected_score": projected,
    }


__all__ = [
    "GRADE_TIERS",
    "SCORE_VERSION",
    "WEIGHTS",
    "gather_score_facts",
    "compute_evidence_readiness_score",
]
