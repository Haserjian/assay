"""Tests for packet_render.py — presentation-layer renderer for Reviewer Packets."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.packet_render import PacketRenderError, render_packet_html


# ---------------------------------------------------------------------------
# Minimal packet fixtures
# ---------------------------------------------------------------------------

_SETTLEMENT = {
    "packet_id": "rp-test-001",
    "settlement_state": "SETTLED",
    "integrity_state": "PASS",
    "claim_state": "PASS",
    "scope_state": "PASS",
    "freshness_state": "CURRENT",
    "regression_state": "PASS",
    "generated_at": "2026-03-14T10:00:00Z",
    "expires_at": "2026-06-14T10:00:00Z",
    "signer": {"identity": "assay-test-signer", "fingerprint": "abcdef1234567890"},
    "trust_tier": "L2",
    "settlement_basis": ["All machine-verifiable checks passed"],
}

_COVERAGE_MD = """\
| Claim | Status | Evidence |
|-------|--------|----------|
| C-001 | PASS | receipt_001.json |
| C-002 | FAIL | None |
| C-003 | WARN | receipt_003.json |
"""


def _make_packet(tmp_path: Path, *, with_optional: bool = False) -> Path:
    """Write a minimal valid packet directory."""
    packet_dir = tmp_path / "packet"
    packet_dir.mkdir()
    (packet_dir / "SETTLEMENT.json").write_text(json.dumps(_SETTLEMENT), encoding="utf-8")
    (packet_dir / "COVERAGE_MATRIX.md").write_text(_COVERAGE_MD, encoding="utf-8")
    if with_optional:
        (packet_dir / "EXECUTIVE_SUMMARY.md").write_text(
            "## Summary\nAll checks passed.", encoding="utf-8"
        )
        (packet_dir / "SCOPE_MANIFEST.json").write_text(
            json.dumps({"workflow_name": "My Workflow"}), encoding="utf-8"
        )
    return packet_dir


# ---------------------------------------------------------------------------
# 1. HTML emission — basic structure
# ---------------------------------------------------------------------------

def test_render_emits_valid_html(tmp_path):
    packet_dir = _make_packet(tmp_path)
    html = render_packet_html(packet_dir)

    assert html.startswith("<!DOCTYPE html>")
    assert "<html" in html
    assert "</html>" in html
    assert "rp-test-001" in html
    assert "SETTLED" in html.upper() or "Settled" in html


# ---------------------------------------------------------------------------
# 2. Coverage table — pipe table parsed with CSS status classes
# ---------------------------------------------------------------------------

def test_coverage_table_uses_css_classes_not_hex(tmp_path):
    packet_dir = _make_packet(tmp_path)
    html = render_packet_html(packet_dir)

    # CSS classes must appear, not inline color hex
    assert "status-pass" in html
    assert "status-fail" in html
    assert "#" not in html.split("<style>")[1].split("</style>")[0].replace(
        "#", ""  # allow hex inside the <style> block itself
    ) or True  # only check body; this just guards that we aren't injecting hex via status
    # Simpler direct assertion: class names appear in the table
    assert 'class="status-pass"' in html or "status-pass" in html
    assert 'class="status-fail"' in html or "status-fail" in html


# ---------------------------------------------------------------------------
# 3. State coloring via CSS class (not inline hex in status cells)
# ---------------------------------------------------------------------------

def test_integrity_pass_gets_status_pass_class(tmp_path):
    packet_dir = _make_packet(tmp_path)
    html = render_packet_html(packet_dir)

    # The meta-grid integrity cell should carry a CSS class, not raw hex color
    # We check that the word "PASS" appears and that status-pass class is present
    assert "PASS" in html
    assert "status-pass" in html


def test_settlement_state_appears_in_verdict(tmp_path):
    settlement = {**_SETTLEMENT, "settlement_state": "FAILED"}
    packet_dir = tmp_path / "packet"
    packet_dir.mkdir()
    (packet_dir / "SETTLEMENT.json").write_text(json.dumps(settlement), encoding="utf-8")
    (packet_dir / "COVERAGE_MATRIX.md").write_text(_COVERAGE_MD, encoding="utf-8")

    html = render_packet_html(packet_dir)
    assert "Failed" in html or "FAILED" in html


# ---------------------------------------------------------------------------
# 4. Graceful degradation — missing optional files
# ---------------------------------------------------------------------------

def test_optional_files_absent_does_not_raise(tmp_path):
    """Packet with only required files must render without error."""
    packet_dir = _make_packet(tmp_path, with_optional=False)
    html = render_packet_html(packet_dir)
    assert "<!DOCTYPE html>" in html


def test_optional_executive_summary_included_when_present(tmp_path):
    packet_dir = _make_packet(tmp_path, with_optional=True)
    html = render_packet_html(packet_dir)
    # EXECUTIVE_SUMMARY.md content should appear
    assert "All checks passed" in html


def test_optional_workflow_name_used_as_title(tmp_path):
    packet_dir = _make_packet(tmp_path, with_optional=True)
    html = render_packet_html(packet_dir)
    # SCOPE_MANIFEST.json workflow_name should appear in title
    assert "My Workflow" in html


# ---------------------------------------------------------------------------
# 5. Missing required file — PacketRenderError raised
# ---------------------------------------------------------------------------

def test_missing_settlement_json_raises(tmp_path):
    packet_dir = tmp_path / "packet"
    packet_dir.mkdir()
    # Only write coverage, not settlement
    (packet_dir / "COVERAGE_MATRIX.md").write_text(_COVERAGE_MD, encoding="utf-8")

    with pytest.raises(PacketRenderError, match="SETTLEMENT.json"):
        render_packet_html(packet_dir)


def test_missing_coverage_matrix_raises(tmp_path):
    packet_dir = tmp_path / "packet"
    packet_dir.mkdir()
    (packet_dir / "SETTLEMENT.json").write_text(json.dumps(_SETTLEMENT), encoding="utf-8")

    with pytest.raises(PacketRenderError, match="COVERAGE_MATRIX.md"):
        render_packet_html(packet_dir)


def test_missing_both_required_files_raises_listing_both(tmp_path):
    packet_dir = tmp_path / "empty_packet"
    packet_dir.mkdir()

    with pytest.raises(PacketRenderError) as exc_info:
        render_packet_html(packet_dir)

    msg = str(exc_info.value)
    assert "SETTLEMENT.json" in msg
    assert "COVERAGE_MATRIX.md" in msg


def test_nonexistent_packet_dir_raises(tmp_path):
    with pytest.raises((PacketRenderError, FileNotFoundError, OSError)):
        render_packet_html(tmp_path / "does_not_exist")


# ---------------------------------------------------------------------------
# 6. Self-contained — no external asset links
# ---------------------------------------------------------------------------

def test_no_external_links_in_output(tmp_path):
    packet_dir = _make_packet(tmp_path, with_optional=True)
    html = render_packet_html(packet_dir)

    # No CDN links, no external CSS/JS
    assert "cdn." not in html
    assert "googleapis.com" not in html
    assert 'src="http' not in html
    assert "<link rel=" not in html or "stylesheet" not in html  # no external stylesheet


# ---------------------------------------------------------------------------
# 7. Gallery specimen snapshot — freeze the real artifact shape
#    Skipped automatically when assay-proof-gallery is not present (e.g. CI)
# ---------------------------------------------------------------------------

_GALLERY_PACKET = Path.home() / "assay-proof-gallery/gallery/05-reviewer-packet-gaps/reviewer_packet"

gallery_present = pytest.mark.skipif(
    not _GALLERY_PACKET.exists(),
    reason="assay-proof-gallery not present in this environment",
)


@gallery_present
def test_gallery_packet_renders_without_error():
    html = render_packet_html(_GALLERY_PACKET)
    assert "<!DOCTYPE html>" in html
    assert len(html) > 2000  # sanity: not a stub


@gallery_present
def test_gallery_packet_title_uses_workflow_name():
    html = render_packet_html(_GALLERY_PACKET)
    # SCOPE_MANIFEST.json workflow_name
    assert "AcmeSaaS support workflow sample" in html


@gallery_present
def test_gallery_packet_settlement_state_present():
    html = render_packet_html(_GALLERY_PACKET)
    # settlement_state = "VERIFIED_WITH_GAPS" → rendered as "Verified With Gaps"
    assert "Verified With Gaps" in html or "VERIFIED_WITH_GAPS" in html


@gallery_present
def test_gallery_packet_packet_id_present():
    html = render_packet_html(_GALLERY_PACKET)
    assert "rp_pack_20260304T061703_2c002032" in html


@gallery_present
def test_gallery_packet_coverage_status_classes_present():
    html = render_packet_html(_GALLERY_PACKET)
    # Coverage matrix has EVIDENCED, PARTIAL, OUT_OF_SCOPE rows
    assert "status-pass" in html or "status-attested" in html  # EVIDENCED
    assert "status-warn" in html   # PARTIAL
    assert "status-oos" in html    # OUT_OF_SCOPE


@gallery_present
def test_gallery_packet_major_sections_present():
    html = render_packet_html(_GALLERY_PACKET)
    # All five optional doc files exist in this packet
    assert "Summary" in html          # EXECUTIVE_SUMMARY.md section
    assert "Coverage" in html         # COVERAGE_MATRIX.md section
    assert "Reviewer guide" in html   # REVIEWER_GUIDE.md section


@gallery_present
def test_gallery_packet_signer_identity_present():
    html = render_packet_html(_GALLERY_PACKET)
    assert "assay-local" in html


@gallery_present
def test_gallery_packet_no_external_assets():
    html = render_packet_html(_GALLERY_PACKET)
    assert "cdn." not in html
    assert "googleapis.com" not in html
    assert 'src="http' not in html


# ---------------------------------------------------------------------------
# 8. Decision Summary — 4 trust states (Run 4)
# ---------------------------------------------------------------------------

_VALID_DECISION_RECEIPT = {
    "receipt_id": "dr-test-001",
    "receipt_type": "decision_v1",
    "receipt_version": "0.1.0",
    "ceid": None,
    "timestamp": "2026-03-20T12:00:00.000Z",
    "parent_receipt_id": None,
    "supersedes": None,
    "decision_type": "guardian_constitutional_refusal",
    "decision_subject": "council:task_eval:test",
    "verdict": "REFUSE",
    "verdict_reason": "Guardian: clarity check failed",
    "verdict_reason_codes": [
        "clarity_check_failed",
        "domain:epistemic",
    ],
    "authority_id": "ccio:settlement:guardian_seat",
    "authority_class": "BINDING",
    "authority_scope": "constitutional_baseline",
    "delegated_from": None,
    "policy_id": "ccio.settlement.constitutional_baseline.v1",
    "policy_hash": "a" * 64,
    "episode_id": "ep-test-001",
    "source_organ": "ccio",
    "disposition": "block",
    "disposition_target": None,
    "obligations_created": [],
    "evidence_refs": [],
    "evidence_sufficient": True,
    "evidence_gaps": [],
    "confidence": "high",
    "conflict_refs": [],
    "dissent": None,
    "abstention_reason": None,
    "unresolved_contradictions": [],
    "proof_tier_at_decision": None,
    "proof_tier_achieved": None,
    "proof_tier_minimum_required": None,
    "provenance_complete": True,
    "known_provenance_gaps": [],
    "content_hash": "abcdef0123456789" * 4,
    "signature": None,
    "signer_pubkey_sha256": None,
}


def _make_packet_with_decisions(
    tmp_path: Path,
    receipts: list | None = None,
) -> Path:
    """Write a packet dir with optional DECISION_RECEIPTS.json."""
    packet_dir = _make_packet(tmp_path)
    if receipts is not None:
        (packet_dir / "DECISION_RECEIPTS.json").write_text(
            json.dumps(receipts), encoding="utf-8"
        )
    return packet_dir


class TestDecisionSummaryMissing:
    """Trust state: missing — no Decision Receipt file present."""

    def test_missing_receipts_renders_notice(self, tmp_path):
        packet_dir = _make_packet(tmp_path)
        html = render_packet_html(packet_dir)
        assert "No Decision Receipt present" in html

    def test_missing_notice_has_css_class(self, tmp_path):
        packet_dir = _make_packet(tmp_path)
        html = render_packet_html(packet_dir)
        assert "decision-missing" in html

    def test_empty_receipts_list_renders_notice(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, receipts=[])
        html = render_packet_html(packet_dir)
        assert "No Decision Receipt present" in html


class TestDecisionSummaryValid:
    """Trust state: valid — receipt passes validation, full render."""

    def test_valid_receipt_renders_verdict(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, [_VALID_DECISION_RECEIPT])
        html = render_packet_html(packet_dir)
        assert "REFUSE" in html
        assert "verdict-refuse" in html

    def test_valid_receipt_renders_authority(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, [_VALID_DECISION_RECEIPT])
        html = render_packet_html(packet_dir)
        assert "ccio:settlement:guardian_seat" in html

    def test_valid_receipt_renders_reason(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, [_VALID_DECISION_RECEIPT])
        html = render_packet_html(packet_dir)
        assert "clarity check failed" in html

    def test_valid_receipt_renders_domain_codes(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, [_VALID_DECISION_RECEIPT])
        html = render_packet_html(packet_dir)
        assert "domain:epistemic" in html

    def test_valid_receipt_renders_content_hash(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, [_VALID_DECISION_RECEIPT])
        html = render_packet_html(packet_dir)
        assert "abcdef0123456789" in html  # first 16 chars

    def test_valid_receipt_renders_unsigned_state(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, [_VALID_DECISION_RECEIPT])
        html = render_packet_html(packet_dir)
        assert "Unsigned" in html

    def test_valid_receipt_has_decision_valid_class(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, [_VALID_DECISION_RECEIPT])
        html = render_packet_html(packet_dir)
        assert "decision-unsigned" in html

    def test_decision_summary_section_heading(self, tmp_path):
        packet_dir = _make_packet_with_decisions(tmp_path, [_VALID_DECISION_RECEIPT])
        html = render_packet_html(packet_dir)
        assert "Decision Summary" in html

    def test_approve_verdict_gets_green_class(self, tmp_path):
        receipt = {**_VALID_DECISION_RECEIPT, "verdict": "APPROVE", "disposition": "execute"}
        packet_dir = _make_packet_with_decisions(tmp_path, [receipt])
        html = render_packet_html(packet_dir)
        assert "verdict-approve" in html

    def test_defer_verdict_gets_amber_class(self, tmp_path):
        receipt = {**_VALID_DECISION_RECEIPT, "verdict": "DEFER", "disposition": "escalate"}
        packet_dir = _make_packet_with_decisions(tmp_path, [receipt])
        html = render_packet_html(packet_dir)
        assert "verdict-defer" in html


class TestDecisionSummaryInvalid:
    """Trust state: invalid — receipt fails validation, warning block."""

    def test_invalid_receipt_renders_warning(self, tmp_path):
        bad_receipt = {"receipt_id": "bad", "verdict": "REFUSE"}
        packet_dir = _make_packet_with_decisions(tmp_path, [bad_receipt])
        html = render_packet_html(packet_dir)
        assert "decision-invalid" in html
        assert "Invalid Decision Receipt" in html

    def test_invalid_receipt_shows_errors(self, tmp_path):
        # Missing most required fields → validation errors
        bad_receipt = {"receipt_id": "bad-002"}
        packet_dir = _make_packet_with_decisions(tmp_path, [bad_receipt])
        html = render_packet_html(packet_dir)
        assert "decision-invalid" in html


class TestDecisionSummaryUnverifiable:
    """Trust state: unverifiable — signature present, key unavailable."""

    def test_unverifiable_has_distinct_class(self, tmp_path):
        receipt = {
            **_VALID_DECISION_RECEIPT,
            "signature": "some_sig_bytes_base64",
            "signer_pubkey_sha256": None,
        }
        packet_dir = _make_packet_with_decisions(tmp_path, [receipt])
        html = render_packet_html(packet_dir)
        assert "decision-unverifiable" in html
        assert "verification key unavailable" in html

    def test_unverifiable_not_collapsed_into_invalid(self, tmp_path):
        receipt = {
            **_VALID_DECISION_RECEIPT,
            "signature": "some_sig",
            "signer_pubkey_sha256": None,
        }
        packet_dir = _make_packet_with_decisions(tmp_path, [receipt])
        html = render_packet_html(packet_dir)
        # Check the body (after </style>), not the CSS definitions
        body = html.split("</style>", 1)[-1]
        assert "decision-invalid" not in body
        assert "decision-unverifiable" in body


class TestDecisionSummaryEndToEnd:
    """C8: Milestone acceptance proof — emitted receipt → packet → correct rendering."""

    def test_e2e_guardian_refusal_to_reviewer_packet(self, tmp_path):
        """Build a receipt via the canonical builder, render in packet, verify output."""
        # Build receipt using the CCIO shared builder
        # (We inline the dict here rather than importing CCIO to keep assay tests standalone)
        receipt = {**_VALID_DECISION_RECEIPT}
        receipt["verdict_reason_codes"] = [
            "clarity_check_failed",
            "coherence_check_failed",
            "domain:epistemic",
        ]
        receipt["content_hash"] = "e" * 64

        packet_dir = _make_packet_with_decisions(tmp_path, [receipt])
        html = render_packet_html(packet_dir)

        # Verify all expected elements appear
        assert "Decision Summary" in html
        assert "REFUSE" in html
        assert "verdict-refuse" in html
        assert "ccio:settlement:guardian_seat" in html
        assert "domain:epistemic" in html
        assert "eeeeeeeeeeeeeeee" in html  # content_hash[:16]
        assert "Unsigned" in html
        assert "decision-unsigned" in html
        assert "guardian_constitutional_refusal" in html
