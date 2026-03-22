"""First Constitutional Circulation Loop — acceptance tests.

Tests the minimal end-to-end loop:
  Guardian refuses → human overrides → obligation created → assay why joins the chain

Design note: These are acceptance tests for constitutional circulation, not
unit tests for individual components. They prove the organism can emit truth,
record governance debt, and explain itself to an outsider.

The override is represented as a Decision Receipt with authority_class=OVERRIDING.
This is an intentional compression (reusing existing schema), not eternal doctrine.
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from assay.decision_receipt import validate_decision_receipt
from assay.obligation import (
    Obligation,
    ObligationStore,
    create_override_obligation,
    discharge_obligation,
)
from assay.override import (
    build_override_decision_receipt,
    validate_override_receipt,
)
from assay.store import AssayStore
from assay.why import (
    ReceiptIndex,
    explain_why,
    render_text,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_guardian_refusal(
    receipt_id: str = "r_refusal_001",
    episode_id: str = "ep_test_001",
    decision_subject: str = "action:login_bypass",
) -> dict:
    """Build a Guardian refusal Decision Receipt (the kind CCIO would emit)."""
    return {
        "receipt_id": receipt_id,
        "receipt_type": "decision_v1",
        "receipt_version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision_type": "guardian_constitutional_refusal",
        "decision_subject": decision_subject,
        "verdict": "REFUSE",
        "verdict_reason": "Dignity floor violation: action would optimize past honesty threshold",
        "verdict_reason_codes": [
            "admissibility:dignity_floor",
            "domain:constitutional",
        ],
        "authority_id": "ccio:settlement:guardian_seat",
        "authority_class": "BINDING",
        "authority_scope": "constitutional_baseline",
        "policy_id": "ccio.settlement.constitutional_baseline.v1",
        "policy_hash": "a" * 64,
        "episode_id": episode_id,
        "disposition": "block",
        "evidence_sufficient": True,
        "provenance_complete": True,
        "source_organ": "ccio",
        "confidence": "high",
    }


@pytest.fixture
def tmp_store(tmp_path):
    """Temporary AssayStore + ObligationStore for test isolation."""
    store_dir = tmp_path / ".assay"
    store_dir.mkdir()
    return {
        "assay_store": AssayStore(base_dir=store_dir),
        "obligation_store": ObligationStore(base_dir=store_dir),
        "store_dir": store_dir,
    }


# ---------------------------------------------------------------------------
# T1: Guardian refusal emits valid Decision Receipt
# ---------------------------------------------------------------------------

class TestT1GuardianRefusal:
    def test_refusal_receipt_is_valid(self):
        refusal = _make_guardian_refusal()
        result = validate_decision_receipt(refusal)
        assert result.valid, f"Validation errors: {[e.message for e in result.errors]}"

    def test_refusal_has_correct_verdict_and_disposition(self):
        refusal = _make_guardian_refusal()
        assert refusal["verdict"] == "REFUSE"
        assert refusal["disposition"] == "block"
        assert refusal["authority_class"] == "BINDING"

    def test_refusal_content_hash_is_deterministic(self):
        """Same inputs produce same receipt structure (minus timestamp)."""
        r1 = _make_guardian_refusal()
        r2 = _make_guardian_refusal()
        # Strip timestamps for determinism check
        r1.pop("timestamp")
        r2.pop("timestamp")
        assert r1 == r2


# ---------------------------------------------------------------------------
# T2: Override emits valid Decision Receipt that supersedes refusal
# ---------------------------------------------------------------------------

class TestT2OverrideReceipt:
    def test_override_receipt_passes_schema_validation(self):
        refusal = _make_guardian_refusal()
        obligation_id = "OB-test000001"
        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=[obligation_id],
        )
        result = validate_decision_receipt(override)
        assert result.valid, f"Validation errors: {[e.message for e in result.errors]}"

    def test_override_has_overriding_authority(self):
        refusal = _make_guardian_refusal()
        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=["OB-test000001"],
        )
        assert override["authority_class"] == "OVERRIDING"
        assert override["delegated_from"] is not None
        assert override["delegated_from"] == "ccio:settlement:guardian_seat"

    def test_override_supersedes_refusal(self):
        refusal = _make_guardian_refusal()
        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=["OB-test000001"],
        )
        assert override["supersedes"] == refusal["receipt_id"]
        assert override["verdict"] == "APPROVE"
        assert override["disposition"] == "execute"

    def test_override_carries_obligation_ids(self):
        refusal = _make_guardian_refusal()
        ob_ids = ["OB-test000001", "OB-test000002"]
        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=ob_ids,
        )
        assert override["obligations_created"] == ob_ids

    def test_override_passes_override_specific_validation(self):
        refusal = _make_guardian_refusal()
        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=["OB-test000001"],
        )
        errors = validate_override_receipt(override)
        assert errors == [], f"Override validation errors: {errors}"

    def test_override_rejects_short_justification(self):
        refusal = _make_guardian_refusal()
        with pytest.raises(ValueError, match="justification must be >= 20"):
            build_override_decision_receipt(
                superseded_receipt=refusal,
                actor_id="dr.smith@hospital.org",
                justification="too short",
                obligation_ids=["OB-test000001"],
            )

    def test_override_rejects_empty_obligations(self):
        refusal = _make_guardian_refusal()
        with pytest.raises(ValueError, match="governance fraud"):
            build_override_decision_receipt(
                superseded_receipt=refusal,
                actor_id="dr.smith@hospital.org",
                justification="Emergency clinical need — patient in acute distress, requires immediate action",
                obligation_ids=[],
            )

    def test_override_rejects_approve_supersession(self):
        """Cannot override an APPROVE verdict."""
        approve = _make_guardian_refusal()
        approve["verdict"] = "APPROVE"
        approve["disposition"] = "execute"
        with pytest.raises(ValueError, match="REFUSE/DEFER/CONFLICT"):
            build_override_decision_receipt(
                superseded_receipt=approve,
                actor_id="dr.smith@hospital.org",
                justification="Emergency clinical need — patient in acute distress, requires immediate action",
                obligation_ids=["OB-test000001"],
            )


# ---------------------------------------------------------------------------
# T3: Obligation created from override receipt
# ---------------------------------------------------------------------------

class TestT3ObligationLifecycle:
    def test_obligation_creation(self):
        refusal = _make_guardian_refusal()
        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=["OB-placeholder"],
        )
        ob = create_override_obligation(
            source_receipt_id=override["receipt_id"],
            superseded_receipt_id=refusal["receipt_id"],
            created_by_actor="dr.smith@hospital.org",
        )
        assert ob.obligation_id.startswith("OB-")
        assert ob.source_receipt_id == override["receipt_id"]
        assert ob.superseded_receipt_id == refusal["receipt_id"]
        assert ob.status == "open"
        assert ob.severity == "HIGH"
        assert ob.obligation_type == "override_review"
        assert ob.due_at > ob.created_at

    def test_obligation_persistence(self, tmp_store):
        ob = create_override_obligation(
            source_receipt_id="r_override_001",
            superseded_receipt_id="r_refusal_001",
            created_by_actor="dr.smith@hospital.org",
        )
        store = tmp_store["obligation_store"]
        store.save(ob)

        loaded = store.get(ob.obligation_id)
        assert loaded is not None
        assert loaded.obligation_id == ob.obligation_id
        assert loaded.status == "open"
        assert loaded.source_receipt_id == "r_override_001"

    def test_obligation_discharge(self, tmp_store):
        ob = create_override_obligation(
            source_receipt_id="r_override_001",
            superseded_receipt_id="r_refusal_001",
            created_by_actor="dr.smith@hospital.org",
        )
        store = tmp_store["obligation_store"]
        store.save(ob)

        discharged = discharge_obligation(ob, discharge_receipt_id="r_review_001")
        store.save(discharged)

        loaded = store.get(ob.obligation_id)
        assert loaded.status == "discharged"
        assert loaded.discharge_receipt_id == "r_review_001"

    def test_list_pending(self, tmp_store):
        store = tmp_store["obligation_store"]
        ob1 = create_override_obligation(
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor_a",
            obligation_id="OB-pending001",
        )
        ob2 = create_override_obligation(
            source_receipt_id="r_2",
            superseded_receipt_id="r_0",
            created_by_actor="actor_b",
            obligation_id="OB-pending002",
        )
        store.save(ob1)
        store.save(ob2)

        discharged = discharge_obligation(ob1, discharge_receipt_id="r_review_x")
        store.save(discharged)

        pending = store.list_pending()
        assert len(pending) == 1
        assert pending[0].obligation_id == "OB-pending002"

    def test_obligation_validation_rejects_bad_state(self):
        ob = Obligation(
            obligation_id="OB-bad",
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            owner="actor",
            obligation_type="override_review",
            severity="HIGH",
            status="discharged",  # but no discharge_receipt_id
            created_at="2026-01-01T00:00:00Z",
            due_at="2026-01-08T00:00:00Z",
        )
        errors = ob.validate()
        assert any("discharge_receipt_id" in e for e in errors)


# ---------------------------------------------------------------------------
# T4: `assay why <receipt-id>` returns complete chain
# ---------------------------------------------------------------------------

class TestT4WhyCommand:
    def _setup_full_loop(self, tmp_store):
        """Create refusal → override → obligation, return all artifacts."""
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        # Step 1: Guardian refusal
        refusal = _make_guardian_refusal(receipt_id="r_refusal_100")

        # Step 2: Create obligation (need ID before building override receipt)
        ob = create_override_obligation(
            source_receipt_id="r_override_100",  # will match override below
            superseded_receipt_id="r_refusal_100",
            created_by_actor="dr.smith@hospital.org",
            obligation_id="OB-loop000001",
        )
        ob_store.save(ob)

        # Step 3: Override receipt
        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=["OB-loop000001"],
            receipt_id="r_override_100",
        )

        # Store receipts in index
        index = ReceiptIndex(store=assay_store)
        index.add(refusal)
        index.add(override)

        return refusal, override, ob, index, ob_store

    def test_why_returns_complete_chain(self, tmp_store):
        refusal, override, ob, index, ob_store = self._setup_full_loop(tmp_store)

        result = explain_why(
            "r_override_100",
            receipt_index=index,
            obligation_store=ob_store,
        )

        # Receipt found
        assert result.receipt.receipt_id == "r_override_100"
        assert result.receipt.verdict == "APPROVE"
        assert result.receipt.authority_class == "OVERRIDING"

        # Superseded refusal found
        assert result.superseded_receipt is not None
        assert result.superseded_receipt.receipt_id == "r_refusal_100"
        assert result.superseded_receipt.verdict == "REFUSE"

        # Obligation found
        assert len(result.obligations) == 1
        assert result.obligations[0].obligation_id == "OB-loop000001"
        assert result.obligations[0].status == "open"

        # No missing links
        assert result.missing_links == []

    def test_why_json_output_has_expected_shape(self, tmp_store):
        refusal, override, ob, index, ob_store = self._setup_full_loop(tmp_store)

        result = explain_why(
            "r_override_100",
            receipt_index=index,
            obligation_store=ob_store,
        )
        d = result.to_dict()

        assert d["receipt_id"] == "r_override_100"
        assert d["verdict"] == "APPROVE"
        assert "supersedes" in d
        assert d["supersedes"]["receipt_id"] == "r_refusal_100"
        assert d["supersedes"]["relation"] == "supersedes"
        assert "obligations" in d
        assert d["obligations"][0]["obligation_id"] == "OB-loop000001"
        assert "missing_links" not in d  # should be absent when empty

    def test_why_text_output_contains_all_artifacts(self, tmp_store):
        refusal, override, ob, index, ob_store = self._setup_full_loop(tmp_store)

        result = explain_why(
            "r_override_100",
            receipt_index=index,
            obligation_store=ob_store,
        )
        text = render_text(result)

        assert "r_override_100" in text
        assert "r_refusal_100" in text
        assert "OB-loop000001" in text
        assert "OVERRIDING" in text
        assert "OPEN" in text  # obligation status

    def test_why_on_plain_refusal(self, tmp_store):
        """Why on a refusal (no override) should work cleanly."""
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]
        refusal = _make_guardian_refusal(receipt_id="r_refusal_solo")

        index = ReceiptIndex(store=assay_store)
        index.add(refusal)

        result = explain_why(
            "r_refusal_solo",
            receipt_index=index,
            obligation_store=ob_store,
        )

        assert result.receipt.receipt_id == "r_refusal_solo"
        assert result.receipt.verdict == "REFUSE"
        assert result.superseded_receipt is None
        assert result.obligations == []
        assert result.missing_links == []


# ---------------------------------------------------------------------------
# T5: `assay why` with discharged obligation
# ---------------------------------------------------------------------------

class TestT5DischargedObligation:
    def test_why_shows_discharged_obligation(self, tmp_store):
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        refusal = _make_guardian_refusal(receipt_id="r_refusal_200")

        ob = create_override_obligation(
            source_receipt_id="r_override_200",
            superseded_receipt_id="r_refusal_200",
            created_by_actor="dr.smith@hospital.org",
            obligation_id="OB-discharge01",
        )
        ob_store.save(ob)

        # Discharge the obligation
        discharged = discharge_obligation(ob, discharge_receipt_id="r_review_200")
        ob_store.save(discharged)

        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=["OB-discharge01"],
            receipt_id="r_override_200",
        )

        index = ReceiptIndex(store=assay_store)
        index.add(refusal)
        index.add(override)

        result = explain_why(
            "r_override_200",
            receipt_index=index,
            obligation_store=ob_store,
        )

        assert len(result.obligations) == 1
        assert result.obligations[0].status == "discharged"
        assert result.obligations[0].discharge_receipt_id == "r_review_200"

        d = result.to_dict()
        assert d["obligations"][0]["status"] == "discharged"
        assert d["obligations"][0]["discharge_receipt_id"] == "r_review_200"


# ---------------------------------------------------------------------------
# T6: Honesty on broken links (missing obligation record)
# ---------------------------------------------------------------------------

class TestT6MissingLinkHonesty:
    def test_why_warns_on_missing_obligation(self, tmp_store):
        """Override receipt references obligation that doesn't exist in store.

        The system must report missing links honestly, not produce fake coherence.
        """
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        refusal = _make_guardian_refusal(receipt_id="r_refusal_300")

        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="dr.smith@hospital.org",
            justification="Emergency clinical need — patient in acute distress, requires immediate action",
            obligation_ids=["OB-ghost000001"],  # This obligation does NOT exist in store
            receipt_id="r_override_300",
        )

        index = ReceiptIndex(store=assay_store)
        index.add(refusal)
        index.add(override)

        result = explain_why(
            "r_override_300",
            receipt_index=index,
            obligation_store=ob_store,
        )

        # Must report the missing link
        assert len(result.missing_links) >= 1
        missing_ids = [ml.referenced_id for ml in result.missing_links]
        assert "OB-ghost000001" in missing_ids

        # Text output must contain warning
        text = render_text(result)
        assert "MISSING" in text
        assert "OB-ghost000001" in text

        # JSON output must include missing_links
        d = result.to_dict()
        assert "missing_links" in d
        assert any(ml["referenced_id"] == "OB-ghost000001" for ml in d["missing_links"])

    def test_why_warns_on_missing_superseded_receipt(self, tmp_store):
        """Override supersedes a receipt that's not in the index."""
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        # Build override manually (can't use builder because we want a missing refusal)
        override = {
            "receipt_id": "r_override_400",
            "receipt_type": "decision_v1",
            "receipt_version": "0.1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision_type": "human_authority_override",
            "decision_subject": "action:test",
            "verdict": "APPROVE",
            "verdict_reason": "Emergency override for testing missing link honesty",
            "authority_id": "human:test@test.org",
            "authority_class": "OVERRIDING",
            "authority_scope": "constitutional_baseline",
            "delegated_from": "ccio:settlement:guardian_seat",
            "policy_id": "test.policy.v1",
            "policy_hash": "b" * 64,
            "episode_id": "ep_test_missing",
            "disposition": "execute",
            "evidence_sufficient": True,
            "provenance_complete": True,
            "supersedes": "r_ghost_refusal",  # NOT in index
            "obligations_created": [],
        }

        index = ReceiptIndex(store=assay_store)
        index.add(override)

        result = explain_why(
            "r_override_400",
            receipt_index=index,
            obligation_store=ob_store,
        )

        assert len(result.missing_links) >= 1
        missing_ids = [ml.referenced_id for ml in result.missing_links]
        assert "r_ghost_refusal" in missing_ids
        assert any(ml.relation == "supersedes" for ml in result.missing_links)

    def test_why_on_nonexistent_receipt(self, tmp_store):
        """Querying a receipt that doesn't exist at all."""
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]
        index = ReceiptIndex(store=assay_store)

        result = explain_why(
            "r_does_not_exist",
            receipt_index=index,
            obligation_store=ob_store,
        )

        assert result.receipt.verdict == "unknown"
        assert len(result.missing_links) >= 1
        assert "not found" in result.execution_why.lower()


# ---------------------------------------------------------------------------
# T7: Mixed obligation resolution (one found, one missing)
# ---------------------------------------------------------------------------

class TestT7MixedObligationResolution:
    def test_why_with_partial_obligation_resolution(self, tmp_store):
        """Override references two obligations; one exists, one doesn't."""
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        refusal = _make_guardian_refusal(receipt_id="r_refusal_500")

        # Create only one of the two obligations
        ob_real = create_override_obligation(
            source_receipt_id="r_override_500",
            superseded_receipt_id="r_refusal_500",
            created_by_actor="actor@org",
            obligation_id="OB-real000001",
        )
        ob_store.save(ob_real)

        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="actor@org",
            justification="Dual obligation test — one real, one ghost obligation reference",
            obligation_ids=["OB-real000001", "OB-ghost000002"],
            receipt_id="r_override_500",
        )

        index = ReceiptIndex(store=assay_store)
        index.add(refusal)
        index.add(override)

        result = explain_why(
            "r_override_500",
            receipt_index=index,
            obligation_store=ob_store,
        )

        # One obligation found, one missing
        assert len(result.obligations) == 1
        assert result.obligations[0].obligation_id == "OB-real000001"

        assert len(result.missing_links) == 1
        assert result.missing_links[0].referenced_id == "OB-ghost000002"
        assert result.missing_links[0].relation == "obligation"


# ---------------------------------------------------------------------------
# T8: Multiple obligation snapshots resolve to newest
# ---------------------------------------------------------------------------

class TestT8ObligationSnapshotResolution:
    def test_newest_snapshot_wins(self, tmp_store):
        """Multiple saves of same obligation_id — latest state wins."""
        ob_store = tmp_store["obligation_store"]

        ob_v1 = create_override_obligation(
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            obligation_id="OB-snapshot01",
        )
        ob_store.save(ob_v1)
        assert ob_store.get("OB-snapshot01").status == "open"

        # Discharge it
        ob_v2 = discharge_obligation(ob_v1, discharge_receipt_id="r_review_1")
        ob_store.save(ob_v2)
        assert ob_store.get("OB-snapshot01").status == "discharged"

        # Save another open obligation with different ID
        ob_other = create_override_obligation(
            source_receipt_id="r_2",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            obligation_id="OB-snapshot02",
        )
        ob_store.save(ob_other)

        # Original still discharged (not corrupted by later writes)
        loaded = ob_store.get("OB-snapshot01")
        assert loaded.status == "discharged"
        assert loaded.discharge_receipt_id == "r_review_1"

    def test_pending_list_reflects_latest_state(self, tmp_store):
        """list_pending only returns obligations whose latest snapshot is open."""
        ob_store = tmp_store["obligation_store"]

        ob1 = create_override_obligation(
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            obligation_id="OB-pend01",
        )
        ob2 = create_override_obligation(
            source_receipt_id="r_2",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            obligation_id="OB-pend02",
        )
        ob_store.save(ob1)
        ob_store.save(ob2)
        assert len(ob_store.list_pending()) == 2

        # Discharge ob1
        ob_store.save(discharge_obligation(ob1, discharge_receipt_id="r_rev"))
        pending = ob_store.list_pending()
        assert len(pending) == 1
        assert pending[0].obligation_id == "OB-pend02"


# ---------------------------------------------------------------------------
# T9: Circular receipt linkage fails safely
# ---------------------------------------------------------------------------

class TestT9CycleDetection:
    def test_parent_cycle_detected_and_reported(self, tmp_store):
        """A→B→A cycle in parent_receipt_id must not recurse forever."""
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        receipt_a = {
            "receipt_id": "r_cycle_a",
            "receipt_type": "decision_v1",
            "receipt_version": "0.1.0",
            "timestamp": "2026-03-21T00:00:00Z",
            "decision_type": "test",
            "decision_subject": "cycle_test",
            "verdict": "REFUSE",
            "authority_id": "test",
            "authority_class": "BINDING",
            "authority_scope": "test",
            "policy_id": "test",
            "policy_hash": "c" * 64,
            "episode_id": "ep_cycle",
            "disposition": "block",
            "evidence_sufficient": True,
            "provenance_complete": True,
            "parent_receipt_id": "r_cycle_b",  # points to B
        }
        receipt_b = {
            **receipt_a,
            "receipt_id": "r_cycle_b",
            "parent_receipt_id": "r_cycle_a",  # points back to A
        }

        index = ReceiptIndex(store=assay_store)
        index.add(receipt_a)
        index.add(receipt_b)

        result = explain_why(
            "r_cycle_a",
            receipt_index=index,
            obligation_store=ob_store,
            trace_depth=10,
        )

        # Should NOT have 10 parents — cycle should be caught
        assert len(result.parent_chain) == 1  # only B before cycle detected
        assert any("cycle" in ml.message.lower() for ml in result.missing_links)

    def test_self_referencing_parent_caught(self, tmp_store):
        """Receipt with parent_receipt_id pointing to itself."""
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        receipt = {
            "receipt_id": "r_self",
            "receipt_type": "decision_v1",
            "receipt_version": "0.1.0",
            "timestamp": "2026-03-21T00:00:00Z",
            "decision_type": "test",
            "decision_subject": "self_ref",
            "verdict": "REFUSE",
            "authority_id": "test",
            "authority_class": "BINDING",
            "authority_scope": "test",
            "policy_id": "test",
            "policy_hash": "d" * 64,
            "episode_id": "ep_self",
            "disposition": "block",
            "evidence_sufficient": True,
            "provenance_complete": True,
            "parent_receipt_id": "r_self",  # self-reference
        }

        index = ReceiptIndex(store=assay_store)
        index.add(receipt)

        result = explain_why(
            "r_self",
            receipt_index=index,
            obligation_store=ob_store,
            trace_depth=10,
        )

        # Self-reference caught immediately
        assert len(result.parent_chain) == 0
        assert any("cycle" in ml.message.lower() for ml in result.missing_links)


# ---------------------------------------------------------------------------
# T10: JSON output includes edge types
# ---------------------------------------------------------------------------

class TestT10EdgeTypesInJson:
    def test_supersedes_edge_has_relation_type(self, tmp_store):
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        refusal = _make_guardian_refusal(receipt_id="r_ref_600")
        ob = create_override_obligation(
            source_receipt_id="r_ovr_600",
            superseded_receipt_id="r_ref_600",
            created_by_actor="actor",
            obligation_id="OB-edge001",
        )
        ob_store.save(ob)

        override = build_override_decision_receipt(
            superseded_receipt=refusal,
            actor_id="actor",
            justification="Edge type test — verifying relation types in JSON output",
            obligation_ids=["OB-edge001"],
            receipt_id="r_ovr_600",
        )

        index = ReceiptIndex(store=assay_store)
        index.add(refusal)
        index.add(override)

        result = explain_why("r_ovr_600", receipt_index=index, obligation_store=ob_store)
        d = result.to_dict()

        # Supersedes edge has relation type
        assert d["supersedes"]["relation"] == "supersedes"

    def test_parent_chain_has_relation_type(self, tmp_store):
        assay_store = tmp_store["assay_store"]
        ob_store = tmp_store["obligation_store"]

        parent = {
            "receipt_id": "r_parent_700",
            "receipt_type": "decision_v1",
            "receipt_version": "0.1.0",
            "timestamp": "2026-03-21T00:00:00Z",
            "decision_type": "test",
            "decision_subject": "edge_test",
            "verdict": "REFUSE",
            "authority_id": "test",
            "authority_class": "BINDING",
            "authority_scope": "test",
            "policy_id": "test",
            "policy_hash": "e" * 64,
            "episode_id": "ep_edge",
            "disposition": "block",
            "evidence_sufficient": True,
            "provenance_complete": True,
        }
        child = {
            **parent,
            "receipt_id": "r_child_700",
            "parent_receipt_id": "r_parent_700",
        }

        index = ReceiptIndex(store=assay_store)
        index.add(parent)
        index.add(child)

        result = explain_why(
            "r_child_700",
            receipt_index=index,
            obligation_store=ob_store,
            trace_depth=5,
        )
        d = result.to_dict()

        assert "parent_chain" in d
        assert len(d["parent_chain"]) == 1
        assert d["parent_chain"][0]["relation"] == "derived_from"


# ---------------------------------------------------------------------------
# T11: Doctor obligation check (downstream consumer)
# ---------------------------------------------------------------------------

class TestT11DoctorObligationCheck:
    def test_doctor_passes_with_no_obligations(self, tmp_store):
        from assay.doctor import _check_obligation_001
        # Monkeypatch the obligation store's base_dir
        import assay.obligation as ob_mod
        original = ob_mod.assay_home
        ob_mod.assay_home = lambda: tmp_store["store_dir"]
        try:
            result = _check_obligation_001()
            assert result.status.value == "pass"
            assert result.evidence["open_count"] == 0
        finally:
            ob_mod.assay_home = original

    def test_doctor_warns_on_open_not_overdue(self, tmp_store):
        from assay.doctor import _check_obligation_001
        import assay.obligation as ob_mod

        ob_store = tmp_store["obligation_store"]
        ob = create_override_obligation(
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            due_days=30,  # far future
        )
        ob_store.save(ob)

        original = ob_mod.assay_home
        ob_mod.assay_home = lambda: tmp_store["store_dir"]
        try:
            result = _check_obligation_001()
            assert result.status.value == "warn"
            assert result.evidence["open_count"] == 1
            assert result.evidence["overdue_count"] == 0
        finally:
            ob_mod.assay_home = original

    def test_doctor_fails_on_overdue_obligation(self, tmp_store):
        from assay.doctor import _check_obligation_001
        import assay.obligation as ob_mod

        ob_store = tmp_store["obligation_store"]
        ob = create_override_obligation(
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            due_days=-1,  # already past due
        )
        ob_store.save(ob)

        original = ob_mod.assay_home
        ob_mod.assay_home = lambda: tmp_store["store_dir"]
        try:
            result = _check_obligation_001()
            assert result.status.value == "fail"
            assert result.severity.value == "high"
            assert result.evidence["overdue_count"] >= 1
            assert "overdue" in result.message.lower()
            assert result.fix is not None
            assert "assay why" in result.fix
        finally:
            ob_mod.assay_home = original
