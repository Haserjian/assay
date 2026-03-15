#!/usr/bin/env python3
"""Generate the seeded passport referee gallery.

Produces a self-contained worked example with pre-built artifacts:
  passport_v1.json   — signed passport (DemoApp)
  passport_v1.html   — rendered HTML
  xray_v1.html       — X-Ray diagnostic report
  challenge receipt   — signed challenge (coverage gap)
  passport_v2.json   — signed passport with coverage claim added
  supersession receipt — signed supersession (v1 → v2)
  trust_diff.html    — diff report showing v1 → v2 changes

Usage:
    python3 docs/passport/generate_gallery.py [--output-dir docs/passport/gallery]

All artifacts are deterministic given the same key seed.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from assay.keystore import AssayKeyStore
from assay.lifecycle_receipt import (
    create_signed_challenge_receipt,
    create_signed_supersession_receipt,
    derive_governance_dimensions,
    write_lifecycle_receipt,
)
from assay.passport_diff import diff_passports
from assay.passport_mint import mint_passport_draft
from assay.passport_render import render_passport_html
from assay.passport_sign import sign_passport, verify_passport_signature
from assay.reporting.passport_diff_report import render_passport_diff_html
from assay.xray import xray_passport


def generate(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # Ephemeral keystore
    tmp_keys = Path(tempfile.mkdtemp(prefix="assay_gallery_keys_"))
    ks = AssayKeyStore(keys_dir=tmp_keys)
    ks.generate_key("gallery-signer")

    try:
        _build(output_dir, ks)
    finally:
        shutil.rmtree(tmp_keys, ignore_errors=True)


def _build(out: Path, ks: AssayKeyStore) -> None:
    # ── 1. Mint v1 ──
    passport_v1 = mint_passport_draft(
        subject_name="AcmeSaaS",
        subject_system_id="acme.saas.v1",
        subject_owner="Acme Corp.",
        valid_days=30,
    )
    p1 = out / "passport_v1.json"
    p1.write_text(json.dumps(passport_v1, indent=2) + "\n", encoding="utf-8")

    # ── 2. Sign v1 ──
    sign_passport(p1, keystore=ks, signer_id="gallery-signer")

    # ── 3. Render v1 HTML ──
    vr = verify_passport_signature(p1, keystore=ks)
    html = render_passport_html(p1, verification_result=vr)
    (out / "passport_v1.html").write_text(html, encoding="utf-8")

    # ── 4. X-Ray v1 ──
    xr = xray_passport(p1, keystore=ks, verify=True)
    from assay.reporting.xray_report import render_xray_html
    xray_html = render_xray_html(xr)
    (out / "xray_v1.html").write_text(xray_html, encoding="utf-8")

    # ── 5. Challenge v1 (signed) ──
    data1 = json.loads(p1.read_text(encoding="utf-8"))
    challenge = create_signed_challenge_receipt(
        target_passport_id=data1["passport_id"],
        reason_code="coverage_gap",
        reason_summary="Missing admin override coverage",
        keystore=ks,
        signer_id="gallery-signer",
    )
    ch_path = write_lifecycle_receipt(challenge, out)

    # ── 6. Verify governance after challenge ──
    gov = derive_governance_dimensions(
        out, passport=data1, target_passport_id=data1["passport_id"],
    )
    assert gov["governance_status"] == "challenged", f"Expected challenged, got {gov['governance_status']}"

    # ── 7. Mint v2 (address the challenge) ──
    passport_v2 = mint_passport_draft(
        subject_name="AcmeSaaS",
        subject_system_id="acme.saas.v1",
        subject_owner="Acme Corp.",
        valid_days=30,
    )
    # v2 adds the coverage claim that was missing
    passport_v2["claims"].append({
        "claim_id": "C-DEMO-001",
        "topic": "Admin override coverage",
        "claim_type": "coverage",
        "applies_to": "admin_override_path",
        "assertion": "Admin override code path is instrumented and verified.",
        "result": "pass",
        "evidence_type": "machine_verified",
        "proof_tier": "core",
        "evidence_refs": ["demo/admin_override_coverage"],
        "qualification": None,
        "boundary": None,
    })
    passport_v2["evidence_summary"]["total_claims"] = len(passport_v2["claims"])
    passport_v2["evidence_summary"]["machine_verified"] = len(passport_v2["claims"])
    passport_v2["evidence_summary"]["core_claims_passed"] = (
        f"{len(passport_v2['claims'])}/{len(passport_v2['claims'])}"
    )
    p2 = out / "passport_v2.json"
    p2.write_text(json.dumps(passport_v2, indent=2) + "\n", encoding="utf-8")

    # ── 8. Sign v2 ──
    sign_passport(p2, keystore=ks, signer_id="gallery-signer")

    # ── 9. Supersede v1 → v2 (signed) ──
    data1 = json.loads(p1.read_text(encoding="utf-8"))
    data2 = json.loads(p2.read_text(encoding="utf-8"))
    sup = create_signed_supersession_receipt(
        target_passport_id=data1["passport_id"],
        new_passport_id=data2["passport_id"],
        reason_code="remediation",
        reason_summary="Addressed coverage gap",
        keystore=ks,
        signer_id="gallery-signer",
    )
    sup_path = write_lifecycle_receipt(sup, out)

    # ── 10. Trust Diff ──
    diff_result = diff_passports(p1, p2)
    diff_html = render_passport_diff_html(diff_result)
    (out / "trust_diff.html").write_text(diff_html, encoding="utf-8")

    # Summary
    artifacts = sorted(out.iterdir())
    print(f"Gallery generated in {out}/ ({len(artifacts)} artifacts):")
    for a in artifacts:
        size = a.stat().st_size
        print(f"  {a.name:40s} {size:>8,} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate passport referee gallery")
    parser.add_argument(
        "--output-dir",
        default="docs/passport/gallery",
        help="Output directory (default: docs/passport/gallery)",
    )
    args = parser.parse_args()
    generate(Path(args.output_dir))
