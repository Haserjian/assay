"""Commitment-Fulfillment Wedge — Slice 1.

Doctrine source: loom-staging docs/architecture/authority_nouns.md (commit 9c5921d5, frozen).

Scope: commitments only. Obligations (forward-looking inherited duty) are
deferred to Slice 2 pending adjudication of the pre-existing
src/assay/obligation.py namespace (which holds override-debt semantics,
not inherited-duty semantics).

Proves:
    1. Event-type strings match doctrine exactly (anti-drift canary).
    2. PolicyResolver resolves file:// refs, checks policy_hash match,
       and raises NotImplementedError for kind="registry".
    3. commitment.registered requires a resolvable policy_hash.
    4. result.observed carries non-adjudicating references only.
    5. fulfillment.commitment_kept | commitment_broken close a commitment.
    6. A commitment has zero or one terminal fulfillment (uniqueness).
    7. DOCTOR_COMMITMENT_001 detects overdue open commitments.
    8. Detector is pure-read.

This file mirrors tests/assay/test_contradiction_detector.py structurally.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from assay.commitment_closure_detector import (
    CommitmentClosureResult,
    OpenOverdueCommitment,
    check_commitment_health,
    detect_open_overdue_commitments,
)
from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
    CommitmentRegistrationArtifact,
    FulfillmentBrokenArtifact,
    FulfillmentKeptArtifact,
    ReceiptStoreIntegrityError,
    ResultObservationArtifact,
    TerminalFulfillmentError,
    UnanchoredFulfillmentError,
    emit_commitment_registration,
    emit_fulfillment_broken,
    emit_fulfillment_kept,
    emit_result_observation,
)
from assay.episode import open_episode
from assay.policy_resolver import (
    PolicyResolutionError,
    PolicyResolver,
    resolve_policy,
)
from assay.store import AssayStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_store(tmp_path):
    """Isolated per-test AssayStore."""
    return AssayStore(base_dir=tmp_path / "assay_store")


@pytest.fixture
def compile_receipt(tmp_path) -> tuple[Path, str]:
    """Write a minimal COMPILE_RECEIPT.json fixture and return (path, policy_hash)."""
    policy_body = b"base-profile-v0\n"
    policy_hash = "sha256:" + hashlib.sha256(policy_body).hexdigest()
    receipt = {
        "compile_receipt_version": "0.1",
        "policy_hash": policy_hash,
        "compiled_at": "2026-04-20T12:00:00Z",
        "profile": "base",
        "sources": {
            "law_md_hash": "sha256:" + "a" * 64,
            "profile_toml_hash": "sha256:" + "b" * 64,
        },
        "generator_version": "0.2.0",
    }
    path = tmp_path / "COMPILE_RECEIPT.json"
    path.write_text(json.dumps(receipt))
    return path, policy_hash


def _ref(path: Path) -> str:
    return f"file://{path}"


# ---------------------------------------------------------------------------
# Helpers: direct writes (detector tests)
# ---------------------------------------------------------------------------


def _write_registered(
    store,
    commitment_id,
    *,
    episode_id="ep_test",
    due_at=None,
    timestamp="2026-01-01T00:00:00.000Z",
):
    data = {
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": commitment_id,
        "episode_id": episode_id,
        "actor_id": "actor_test",
        "text": "Ship the widget by Friday.",
        "commitment_type": "delivery",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": timestamp,
    }
    if due_at is not None:
        data["due_at"] = due_at
    store.append_dict(data)


def _write_kept(store, commitment_id, result_id, *, episode_id="ep_test"):
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        "fulfillment_id": f"ful_{commitment_id}_kept",
        "episode_id": episode_id,
        "commitment_id": commitment_id,
        "result_id": result_id,
        "evaluator": "test",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-01-02T00:00:00.000Z",
    })


def _write_broken(store, commitment_id, result_id, *, episode_id="ep_test", reason="missed_deadline"):
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
        "fulfillment_id": f"ful_{commitment_id}_broken",
        "episode_id": episode_id,
        "commitment_id": commitment_id,
        "result_id": result_id,
        "evaluator": "test",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "violation_reason": reason,
        "timestamp": "2026-01-02T00:00:00.000Z",
    })


def _write_result(store, result_id, *, episode_id="ep_test", references=None):
    store.append_dict({
        "type": RESULT_OBSERVATION_RECEIPT_TYPE,
        "result_id": result_id,
        "episode_id": episode_id,
        "text": "Widget shipped.",
        "evidence_uri": "file:///tmp/widget.log",
        "policy_hash": "sha256:" + "c" * 64,
        "references": references or [],
        "timestamp": "2026-01-01T12:00:00.000Z",
    })


# ---------------------------------------------------------------------------
# 1. Anti-drift canary — serialized event type strings match doctrine
# ---------------------------------------------------------------------------


class TestEventTypeStrings:
    """Serialized receipt_type strings must match doctrine exactly.

    Python class names may be ergonomic; doctrine wire strings may not drift.
    """

    def test_commitment_registration_type_literal(self):
        assert COMMITMENT_REGISTRATION_RECEIPT_TYPE == "commitment.registered"

    def test_result_observation_type_literal(self):
        assert RESULT_OBSERVATION_RECEIPT_TYPE == "result.observed"

    def test_fulfillment_kept_type_literal(self):
        assert FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE == "fulfillment.commitment_kept"

    def test_fulfillment_broken_type_literal(self):
        assert FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE == "fulfillment.commitment_broken"


# ---------------------------------------------------------------------------
# 2. PolicyResolver
# ---------------------------------------------------------------------------


class TestPolicyResolver:
    """Minimal reusable resolver for COMPILE_RECEIPT.json."""

    def test_uri_kind_resolves_matching_hash(self, compile_receipt):
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        resolved = resolve_policy(resolver)
        assert resolved["policy_hash"] == policy_hash
        assert resolved["compile_receipt_version"] == "0.1"

    def test_uri_kind_rejects_hash_mismatch(self, compile_receipt):
        path, _policy_hash = compile_receipt
        resolver = PolicyResolver(
            kind="uri",
            ref=_ref(path),
            policy_hash="sha256:" + "f" * 64,
        )
        with pytest.raises(PolicyResolutionError):
            resolve_policy(resolver)

    def test_uri_kind_missing_file_raises(self, tmp_path):
        resolver = PolicyResolver(
            kind="uri",
            ref=f"file://{tmp_path / 'missing.json'}",
            policy_hash="sha256:" + "0" * 64,
        )
        with pytest.raises(PolicyResolutionError):
            resolve_policy(resolver)

    def test_registry_kind_raises_not_implemented(self):
        resolver = PolicyResolver(
            kind="registry",
            ref="policy://base/v0.1",
            policy_hash="sha256:" + "0" * 64,
        )
        with pytest.raises(NotImplementedError):
            resolve_policy(resolver)


# ---------------------------------------------------------------------------
# 3. commitment.registered — requires resolvable policy_hash
# ---------------------------------------------------------------------------


def _build_commitment(
    policy_hash: str,
    resolver_dict: dict,
    *,
    commitment_id: str = "cmt_001",
    due_at: str | None = None,
) -> CommitmentRegistrationArtifact:
    return CommitmentRegistrationArtifact(
        commitment_id=commitment_id,
        timestamp="2026-04-20T12:00:00.000Z",
        episode_id="ep_test",
        actor_id="actor_alice",
        text="Ship the widget by Friday.",
        commitment_type="delivery",
        policy_hash=policy_hash,
        policy_resolver=resolver_dict,
        due_at=due_at,
    )


class TestCommitmentRegistrationGuards:
    """Registration requires a resolver whose COMPILE_RECEIPT matches policy_hash."""

    def test_register_with_matching_resolver_succeeds(self, tmp_store, compile_receipt):
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)

        with open_episode(store=tmp_store) as ep:
            artifact = _build_commitment(policy_hash, resolver.to_dict())
            returned = emit_commitment_registration(ep, artifact)

        assert returned.commitment_id == "cmt_001"
        entries = tmp_store.read_trace(tmp_store.trace_id)
        types = [e.get("type") for e in entries]
        assert COMMITMENT_REGISTRATION_RECEIPT_TYPE in types

    def test_register_with_hash_mismatch_raises(self, tmp_store, compile_receipt):
        path, policy_hash = compile_receipt
        bad_hash = "sha256:" + "f" * 64
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=bad_hash)

        with open_episode(store=tmp_store) as ep:
            artifact = _build_commitment(bad_hash, resolver.to_dict())
            with pytest.raises(PolicyResolutionError):
                emit_commitment_registration(ep, artifact)

    def test_register_missing_compile_receipt_raises(self, tmp_store, tmp_path):
        bad_hash = "sha256:" + "0" * 64
        resolver = PolicyResolver(
            kind="uri",
            ref=f"file://{tmp_path / 'nope.json'}",
            policy_hash=bad_hash,
        )
        with open_episode(store=tmp_store) as ep:
            artifact = _build_commitment(bad_hash, resolver.to_dict())
            with pytest.raises(PolicyResolutionError):
                emit_commitment_registration(ep, artifact)

    def test_artifact_policy_hash_must_equal_resolver_policy_hash(
        self, tmp_store, compile_receipt
    ):
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)

        with open_episode(store=tmp_store) as ep:
            artifact = _build_commitment(
                policy_hash="sha256:" + "9" * 64,
                resolver_dict=resolver.to_dict(),
            )
            with pytest.raises(PolicyResolutionError):
                emit_commitment_registration(ep, artifact)


# ---------------------------------------------------------------------------
# 4. result.observed — non-adjudicating
# ---------------------------------------------------------------------------


class TestResultObservation:
    """result.observed carries references only; it never closes a commitment."""

    def test_result_artifact_has_no_fulfills_field(self):
        artifact = ResultObservationArtifact(
            result_id="res_001",
            timestamp="2026-01-01T12:00:00.000Z",
            episode_id="ep_test",
            text="Widget shipped.",
            evidence_uri="file:///tmp/widget.log",
            policy_hash="sha256:" + "c" * 64,
            policy_resolver={"kind": "uri", "ref": "file:///tmp/r.json",
                             "policy_hash": "sha256:" + "c" * 64},
            references=[{"kind": "commitment", "id": "cmt_001"}],
        )
        d = artifact.to_dict()
        assert "fulfills" not in d
        assert "closes" not in d
        assert d["references"] == [{"kind": "commitment", "id": "cmt_001"}]

    def test_result_observed_does_not_close_commitment(self, tmp_store):
        """Emitting result.observed referencing a commitment leaves it OPEN."""
        tmp_store.start_trace()
        _write_registered(
            tmp_store, "cmt_open", due_at="2020-01-01T00:00:00Z"
        )
        _write_result(
            tmp_store,
            "res_001",
            references=[{"kind": "commitment", "id": "cmt_open"}],
        )

        result = detect_open_overdue_commitments(tmp_store)
        ids = {c.commitment_id for c in result.open_commitments}
        assert "cmt_open" in ids


# ---------------------------------------------------------------------------
# 5. fulfillment.commitment_kept | commitment_broken — terminal closure
# ---------------------------------------------------------------------------


class TestTerminalClosure:
    """A terminal fulfillment closes exactly the named commitment."""

    def test_kept_closes_exactly_one_commitment(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_A", due_at="2020-01-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_B", due_at="2020-01-01T00:00:00Z")
        _write_result(tmp_store, "res_1",
                      references=[{"kind": "commitment", "id": "cmt_A"}])
        _write_kept(tmp_store, "cmt_A", "res_1")

        result = detect_open_overdue_commitments(tmp_store)
        open_ids = {c.commitment_id for c in result.open_commitments}
        assert "cmt_A" not in open_ids
        assert "cmt_B" in open_ids

    def test_broken_closes_exactly_one_commitment(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_A", due_at="2020-01-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_B", due_at="2020-01-01T00:00:00Z")
        _write_result(tmp_store, "res_1",
                      references=[{"kind": "commitment", "id": "cmt_A"}])
        _write_broken(tmp_store, "cmt_A", "res_1", reason="missed_deadline")

        result = detect_open_overdue_commitments(tmp_store)
        open_ids = {c.commitment_id for c in result.open_commitments}
        assert "cmt_A" not in open_ids
        assert "cmt_B" in open_ids


# ---------------------------------------------------------------------------
# 6. Terminal uniqueness — no competing terminals per commitment
# ---------------------------------------------------------------------------


def _register_and_observe(ep, tmp_store, compile_receipt_tuple, commitment_id):
    """Register a commitment and observe one result referencing it."""
    path, policy_hash = compile_receipt_tuple
    resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
    cmt = _build_commitment(policy_hash, resolver.to_dict(), commitment_id=commitment_id)
    emit_commitment_registration(ep, cmt)

    result = ResultObservationArtifact(
        result_id=f"res_{commitment_id}",
        timestamp="2026-04-20T13:00:00.000Z",
        episode_id=ep.episode_id,
        text="Outcome observed.",
        evidence_uri="file:///tmp/ev.log",
        policy_hash=policy_hash,
        policy_resolver=resolver.to_dict(),
        references=[{"kind": "commitment", "id": commitment_id}],
    )
    emit_result_observation(ep, result)
    return resolver, policy_hash, f"res_{commitment_id}"


def _kept_artifact(ep_id, commitment_id, result_id, policy_hash, resolver_dict):
    return FulfillmentKeptArtifact(
        fulfillment_id=f"ful_{commitment_id}_k1",
        timestamp="2026-04-20T14:00:00.000Z",
        episode_id=ep_id,
        commitment_id=commitment_id,
        result_id=result_id,
        evaluator="test",
        evaluator_version="0.1",
        policy_hash=policy_hash,
        policy_resolver=resolver_dict,
    )


def _broken_artifact(ep_id, commitment_id, result_id, policy_hash, resolver_dict):
    return FulfillmentBrokenArtifact(
        fulfillment_id=f"ful_{commitment_id}_b1",
        timestamp="2026-04-20T14:00:00.000Z",
        episode_id=ep_id,
        commitment_id=commitment_id,
        result_id=result_id,
        evaluator="test",
        evaluator_version="0.1",
        policy_hash=policy_hash,
        policy_resolver=resolver_dict,
        violation_reason="missed_deadline",
    )


class TestTerminalUniqueness:
    """A commitment has zero or one terminal fulfillment."""

    def test_duplicate_kept_raises(self, tmp_store, compile_receipt):
        with open_episode(store=tmp_store) as ep:
            resolver, ph, rid = _register_and_observe(ep, tmp_store, compile_receipt, "cmt_u1")
            kept = _kept_artifact(ep.episode_id, "cmt_u1", rid, ph, resolver.to_dict())
            emit_fulfillment_kept(ep, kept)

            kept2 = _kept_artifact(ep.episode_id, "cmt_u1", rid, ph, resolver.to_dict())
            kept2.fulfillment_id = "ful_cmt_u1_k2"
            with pytest.raises(TerminalFulfillmentError):
                emit_fulfillment_kept(ep, kept2)

    def test_kept_then_broken_raises(self, tmp_store, compile_receipt):
        with open_episode(store=tmp_store) as ep:
            resolver, ph, rid = _register_and_observe(ep, tmp_store, compile_receipt, "cmt_u2")
            kept = _kept_artifact(ep.episode_id, "cmt_u2", rid, ph, resolver.to_dict())
            emit_fulfillment_kept(ep, kept)

            broken = _broken_artifact(ep.episode_id, "cmt_u2", rid, ph, resolver.to_dict())
            with pytest.raises(TerminalFulfillmentError):
                emit_fulfillment_broken(ep, broken)

    def test_broken_then_kept_raises(self, tmp_store, compile_receipt):
        with open_episode(store=tmp_store) as ep:
            resolver, ph, rid = _register_and_observe(ep, tmp_store, compile_receipt, "cmt_u3")
            broken = _broken_artifact(ep.episode_id, "cmt_u3", rid, ph, resolver.to_dict())
            emit_fulfillment_broken(ep, broken)

            kept = _kept_artifact(ep.episode_id, "cmt_u3", rid, ph, resolver.to_dict())
            with pytest.raises(TerminalFulfillmentError):
                emit_fulfillment_kept(ep, kept)


# ---------------------------------------------------------------------------
# 7. Detector — DOCTOR_COMMITMENT_001 semantics
# ---------------------------------------------------------------------------


class TestDetector:
    """detect_open_overdue_commitments flags overdue open commitments."""

    def test_overdue_unfulfilled_is_open(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_late", due_at="2020-01-01T00:00:00Z")
        result = detect_open_overdue_commitments(tmp_store)
        assert not result.clean
        assert result.total_open_found == 1
        assert result.open_commitments[0].commitment_id == "cmt_late"

    def test_not_yet_due_is_clean(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_future", due_at="2099-01-01T00:00:00Z")
        result = detect_open_overdue_commitments(tmp_store)
        assert result.clean
        assert result.total_open_found == 0

    def test_no_due_at_is_perpetual_clean(self, tmp_store):
        """Slice 1 conservative: no due_at → never overdue."""
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_perpetual", due_at=None)
        result = detect_open_overdue_commitments(tmp_store)
        assert result.clean

    def test_kept_closes_overdue(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_done", due_at="2020-01-01T00:00:00Z")
        _write_result(tmp_store, "res_x",
                      references=[{"kind": "commitment", "id": "cmt_done"}])
        _write_kept(tmp_store, "cmt_done", "res_x")
        result = detect_open_overdue_commitments(tmp_store)
        assert result.clean

    def test_broken_closes_overdue(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_failed", due_at="2020-01-01T00:00:00Z")
        _write_result(tmp_store, "res_x",
                      references=[{"kind": "commitment", "id": "cmt_failed"}])
        _write_broken(tmp_store, "cmt_failed", "res_x")
        result = detect_open_overdue_commitments(tmp_store)
        assert result.clean

    def test_empty_store_is_clean(self, tmp_store):
        result = detect_open_overdue_commitments(tmp_store)
        assert result.clean
        assert result.total_registered_found == 0

    def test_detector_is_pure_read(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_read", due_at="2020-01-01T00:00:00Z")
        before = tmp_store.read_trace(tmp_store.trace_id)
        detect_open_overdue_commitments(tmp_store)
        after = tmp_store.read_trace(tmp_store.trace_id)
        assert len(before) == len(after)

    def test_result_has_scanned_at(self, tmp_store):
        result = detect_open_overdue_commitments(tmp_store)
        assert result.scanned_at != ""

    def test_to_dict_round_trip(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_dict", due_at="2020-01-01T00:00:00Z")
        d = detect_open_overdue_commitments(tmp_store).to_dict()
        assert d["clean"] is False
        assert d["total_open_found"] == 1
        assert d["open_commitments"][0]["commitment_id"] == "cmt_dict"


# ---------------------------------------------------------------------------
# 8. Health check
# ---------------------------------------------------------------------------


class TestCheckCommitmentHealth:
    def test_health_true_when_clean(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_ok", due_at="2099-01-01T00:00:00Z")
        assert check_commitment_health(tmp_store, loud=False) is True

    def test_health_false_when_overdue(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_late", due_at="2020-01-01T00:00:00Z")
        assert check_commitment_health(tmp_store, loud=False) is False

    def test_health_empty_store_is_clean(self, tmp_store):
        assert check_commitment_health(tmp_store, loud=False) is True


# ---------------------------------------------------------------------------
# 9. Doctor integration
# ---------------------------------------------------------------------------


class TestDoctorIntegration:
    def test_commitment_check_runs_with_check_orphans(self, tmp_store):
        from assay.doctor import CheckStatus, Profile, run_doctor

        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_doc", due_at="2020-01-01T00:00:00Z")
        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=True)

        ids = [c.id for c in report.checks]
        assert "DOCTOR_COMMITMENT_001" in ids

        cmt_result = next(c for c in report.checks if c.id == "DOCTOR_COMMITMENT_001")
        assert cmt_result.status == CheckStatus.FAIL
        assert "1 overdue commitment" in cmt_result.message

    def test_commitment_check_passes_when_clean(self, tmp_store):
        from assay.doctor import CheckStatus, Profile, run_doctor

        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_clean", due_at="2020-01-01T00:00:00Z")
        _write_result(tmp_store, "res_ok",
                      references=[{"kind": "commitment", "id": "cmt_clean"}])
        _write_kept(tmp_store, "cmt_clean", "res_ok")

        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=True)
        cmt_result = next(c for c in report.checks if c.id == "DOCTOR_COMMITMENT_001")
        assert cmt_result.status == CheckStatus.PASS

    def test_commitment_check_not_in_default_run(self, tmp_store):
        from assay.doctor import Profile, run_doctor

        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_default", due_at="2020-01-01T00:00:00Z")
        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=False)
        ids = [c.id for c in report.checks]
        assert "DOCTOR_COMMITMENT_001" not in ids


# ---------------------------------------------------------------------------
# 10. OpenOverdueCommitment forensic fields
# ---------------------------------------------------------------------------


class TestForensicFields:
    def test_open_overdue_has_forensic_fields(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(
            tmp_store,
            "cmt_forensic",
            episode_id="ep_forensic",
            due_at="2020-01-01T00:00:00Z",
        )
        result = detect_open_overdue_commitments(tmp_store)
        c = result.open_commitments[0]
        assert c.commitment_id == "cmt_forensic"
        assert c.episode_id == "ep_forensic"
        assert c.due_at == "2020-01-01T00:00:00Z"
        assert c.registered_at != ""
        assert c.trace_id != ""


# ---------------------------------------------------------------------------
# 11. Repair — policy binding enforced on result + fulfillment
# ---------------------------------------------------------------------------


class TestPolicyBindingOnNonRegistrationEmits:
    """result.observed and fulfillment.commitment_* must clear the same
    policy-binding bar as commitment.registered.
    """

    def test_result_observation_rejects_mismatched_hash(self, tmp_store, compile_receipt):
        path, policy_hash = compile_receipt
        # Resolver binds to the real hash; artifact declares a different one.
        resolver_dict = {
            "kind": "uri",
            "ref": _ref(path),
            "policy_hash": policy_hash,
        }
        bad_artifact_hash = "sha256:" + "9" * 64
        artifact = ResultObservationArtifact(
            result_id="res_bad_binding",
            timestamp="2026-04-20T12:00:00.000Z",
            episode_id="ep_bad",
            text="bad.",
            evidence_uri="file:///tmp/bad.log",
            policy_hash=bad_artifact_hash,
            policy_resolver=resolver_dict,
            references=[],
        )
        with open_episode(store=tmp_store) as ep:
            with pytest.raises(PolicyResolutionError):
                emit_result_observation(ep, artifact)

    def test_result_observation_rejects_missing_compile_receipt(
        self, tmp_store, tmp_path
    ):
        bad_hash = "sha256:" + "0" * 64
        resolver_dict = {
            "kind": "uri",
            "ref": f"file://{tmp_path / 'nope.json'}",
            "policy_hash": bad_hash,
        }
        artifact = ResultObservationArtifact(
            result_id="res_no_file",
            timestamp="2026-04-20T12:00:00.000Z",
            episode_id="ep_nope",
            text="x",
            evidence_uri="file:///tmp/x.log",
            policy_hash=bad_hash,
            policy_resolver=resolver_dict,
            references=[],
        )
        with open_episode(store=tmp_store) as ep:
            with pytest.raises(PolicyResolutionError):
                emit_result_observation(ep, artifact)

    def _prep(self, tmp_store, compile_receipt, commitment_id):
        """Register and observe for a fulfillment policy-binding test."""
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        ep = open_episode(store=tmp_store)
        cmt = _build_commitment(policy_hash, resolver.to_dict(),
                                commitment_id=commitment_id)
        emit_commitment_registration(ep, cmt)
        result = ResultObservationArtifact(
            result_id=f"res_{commitment_id}",
            timestamp="2026-04-20T13:00:00.000Z",
            episode_id=ep.episode_id,
            text="observation.",
            evidence_uri="file:///tmp/e.log",
            policy_hash=policy_hash,
            policy_resolver=resolver.to_dict(),
            references=[{"kind": "commitment", "id": commitment_id}],
        )
        emit_result_observation(ep, result)
        return ep, resolver, policy_hash, result.result_id

    def test_fulfillment_kept_rejects_mismatched_hash(self, tmp_store, compile_receipt):
        ep, resolver, policy_hash, rid = self._prep(
            tmp_store, compile_receipt, "cmt_kept_bad"
        )
        try:
            bad_hash = "sha256:" + "9" * 64
            kept = FulfillmentKeptArtifact(
                fulfillment_id="ful_bad",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_kept_bad",
                result_id=rid,
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=bad_hash,
                policy_resolver=resolver.to_dict(),  # mismatches bad_hash
            )
            with pytest.raises(PolicyResolutionError):
                emit_fulfillment_kept(ep, kept)
        finally:
            ep.close()

    def test_fulfillment_broken_rejects_mismatched_hash(self, tmp_store, compile_receipt):
        ep, resolver, policy_hash, rid = self._prep(
            tmp_store, compile_receipt, "cmt_broken_bad"
        )
        try:
            bad_hash = "sha256:" + "9" * 64
            broken = FulfillmentBrokenArtifact(
                fulfillment_id="ful_bad_b",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_broken_bad",
                result_id=rid,
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=bad_hash,
                policy_resolver=resolver.to_dict(),
                violation_reason="x",
            )
            with pytest.raises(PolicyResolutionError):
                emit_fulfillment_broken(ep, broken)
        finally:
            ep.close()


# ---------------------------------------------------------------------------
# 12. Repair — fulfillment existence anchors
# ---------------------------------------------------------------------------


class TestFulfillmentExistenceAnchors:
    """fulfillment.commitment_* must anchor to real commitment + result receipts."""

    def test_kept_rejects_missing_commitment(self, tmp_store, compile_receipt):
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        with open_episode(store=tmp_store) as ep:
            # Observe a result but never register the commitment.
            result = ResultObservationArtifact(
                result_id="res_orphan",
                timestamp="2026-04-20T13:00:00.000Z",
                episode_id=ep.episode_id,
                text="x",
                evidence_uri="file:///tmp/x.log",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
                references=[],
            )
            emit_result_observation(ep, result)
            kept = FulfillmentKeptArtifact(
                fulfillment_id="ful_no_cmt",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_does_not_exist",
                result_id="res_orphan",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
            )
            with pytest.raises(UnanchoredFulfillmentError):
                emit_fulfillment_kept(ep, kept)

    def test_kept_rejects_missing_result(self, tmp_store, compile_receipt):
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        with open_episode(store=tmp_store) as ep:
            cmt = _build_commitment(policy_hash, resolver.to_dict(),
                                    commitment_id="cmt_no_res")
            emit_commitment_registration(ep, cmt)
            kept = FulfillmentKeptArtifact(
                fulfillment_id="ful_no_res",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_no_res",
                result_id="res_does_not_exist",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
            )
            with pytest.raises(UnanchoredFulfillmentError):
                emit_fulfillment_kept(ep, kept)

    def test_broken_rejects_missing_commitment(self, tmp_store, compile_receipt):
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        with open_episode(store=tmp_store) as ep:
            result = ResultObservationArtifact(
                result_id="res_orphan_b",
                timestamp="2026-04-20T13:00:00.000Z",
                episode_id=ep.episode_id,
                text="x",
                evidence_uri="file:///tmp/x.log",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
                references=[],
            )
            emit_result_observation(ep, result)
            broken = FulfillmentBrokenArtifact(
                fulfillment_id="ful_b_no_cmt",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_ghost",
                result_id="res_orphan_b",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
                violation_reason="x",
            )
            with pytest.raises(UnanchoredFulfillmentError):
                emit_fulfillment_broken(ep, broken)

    def test_broken_rejects_missing_result(self, tmp_store, compile_receipt):
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        with open_episode(store=tmp_store) as ep:
            cmt = _build_commitment(policy_hash, resolver.to_dict(),
                                    commitment_id="cmt_b_no_res")
            emit_commitment_registration(ep, cmt)
            broken = FulfillmentBrokenArtifact(
                fulfillment_id="ful_b_no_res",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_b_no_res",
                result_id="res_ghost",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
                violation_reason="x",
            )
            with pytest.raises(UnanchoredFulfillmentError):
                emit_fulfillment_broken(ep, broken)

    def test_existence_check_is_type_aware(self, tmp_store, compile_receipt):
        """A receipt with matching id but wrong receipt_type does not count."""
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        tmp_store.start_trace()
        # Write a receipt that has result_id="res_fake" but wrong type.
        tmp_store.append_dict({
            "type": "model.invoked",  # NOT result.observed
            "result_id": "res_fake",
            "episode_id": "ep_spoof",
            "timestamp": "2026-01-01T00:00:00Z",
        })
        # Register a real commitment so that anchor ≠ commitment failure.
        with open_episode(store=tmp_store) as ep:
            cmt = _build_commitment(policy_hash, resolver.to_dict(),
                                    commitment_id="cmt_type_aware")
            emit_commitment_registration(ep, cmt)
            kept = FulfillmentKeptArtifact(
                fulfillment_id="ful_type_aware",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_type_aware",
                result_id="res_fake",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
            )
            with pytest.raises(UnanchoredFulfillmentError):
                emit_fulfillment_kept(ep, kept)


# ---------------------------------------------------------------------------
# 13. Repair — detector rejects fabricated terminals
# ---------------------------------------------------------------------------


class TestDetectorRejectsFabricatedTerminals:
    """Defense-in-depth: a fabricated terminal (direct append_dict, bypassing the
    emitter) must not suppress detection. The detector requires the terminal
    to anchor to a real result.observed receipt.
    """

    def test_fabricated_terminal_without_result_does_not_close(self, tmp_store):
        """A terminal whose result_id has no matching result.observed is ignored."""
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_fab", due_at="2020-01-01T00:00:00Z")
        # Fabricate a terminal without a corresponding result.observed.
        _write_kept(tmp_store, "cmt_fab", "res_does_not_exist")

        result = detect_open_overdue_commitments(tmp_store)
        open_ids = {c.commitment_id for c in result.open_commitments}
        assert "cmt_fab" in open_ids
        assert not result.clean

    def test_fabricated_terminal_for_unregistered_commitment_ignored(self, tmp_store):
        """A terminal naming an unregistered commitment does not appear in closed_ids."""
        tmp_store.start_trace()
        # Only a terminal — no commitment.registered, no result.observed.
        _write_kept(tmp_store, "cmt_ghost", "res_ghost")
        result = detect_open_overdue_commitments(tmp_store)
        assert result.clean  # nothing registered, nothing to flag
        assert result.total_closed_found == 0


# ---------------------------------------------------------------------------
# 14. Repair — terminal uniqueness survives list_traces() truncation
# ---------------------------------------------------------------------------


class TestTerminalUniquenessGlobalScan:
    """The uniqueness guard scans every JSONL file on disk, not list_traces()."""

    def test_uniqueness_survives_list_traces_cap(self, tmp_store, compile_receipt):
        """Monkey-patching list_traces to return empty does not bypass uniqueness.

        This test would fail under the old implementation (which relied on
        ``list_traces(limit=10_000)``): a capped or empty list_traces would
        hide the prior terminal and allow a duplicate.
        """
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)

        # Emit legitimate commitment + result + terminal.
        with open_episode(store=tmp_store) as ep:
            cmt = _build_commitment(policy_hash, resolver.to_dict(),
                                    commitment_id="cmt_cap")
            emit_commitment_registration(ep, cmt)
            result = ResultObservationArtifact(
                result_id="res_cap",
                timestamp="2026-04-20T13:00:00.000Z",
                episode_id=ep.episode_id,
                text="x",
                evidence_uri="file:///tmp/x.log",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
                references=[{"kind": "commitment", "id": "cmt_cap"}],
            )
            emit_result_observation(ep, result)
            kept = FulfillmentKeptArtifact(
                fulfillment_id="ful_cap_1",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_cap",
                result_id="res_cap",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
            )
            emit_fulfillment_kept(ep, kept)

        # Blind list_traces: simulates a cap that hides older traces.
        tmp_store.list_traces = lambda limit=20: []

        # A second terminal attempt must still be rejected (uniqueness holds
        # because _iter_all_receipts walks the filesystem, not list_traces).
        with open_episode(store=tmp_store) as ep2:
            result2 = ResultObservationArtifact(
                result_id="res_cap2",
                timestamp="2026-04-20T15:00:00.000Z",
                episode_id=ep2.episode_id,
                text="x",
                evidence_uri="file:///tmp/x.log",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
                references=[{"kind": "commitment", "id": "cmt_cap"}],
            )
            emit_result_observation(ep2, result2)
            kept2 = FulfillmentKeptArtifact(
                fulfillment_id="ful_cap_2",
                timestamp="2026-04-20T16:00:00.000Z",
                episode_id=ep2.episode_id,
                commitment_id="cmt_cap",
                result_id="res_cap2",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
            )
            with pytest.raises(TerminalFulfillmentError):
                emit_fulfillment_kept(ep2, kept2)


# ---------------------------------------------------------------------------
# 15. Repair — result anchor is commitment-specific, not bare existence
# ---------------------------------------------------------------------------


def _register_cmt(ep, policy_hash, resolver, cmt_id):
    cmt = _build_commitment(policy_hash, resolver.to_dict(), commitment_id=cmt_id)
    emit_commitment_registration(ep, cmt)


def _observe_res(ep, policy_hash, resolver, result_id, commitment_ref_ids):
    refs = [{"kind": "commitment", "id": c} for c in commitment_ref_ids]
    res = ResultObservationArtifact(
        result_id=result_id,
        timestamp="2026-04-20T13:00:00.000Z",
        episode_id=ep.episode_id,
        text="x",
        evidence_uri="file:///tmp/x.log",
        policy_hash=policy_hash,
        policy_resolver=resolver.to_dict(),
        references=refs,
    )
    emit_result_observation(ep, res)


class TestCommitmentSpecificResultAnchor:
    """result.observed must explicitly reference the commitment being closed."""

    def test_kept_rejects_result_observed_for_different_commitment(
        self, tmp_store, compile_receipt
    ):
        """A result.observed that references cmt_B must not close cmt_A."""
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        with open_episode(store=tmp_store) as ep:
            _register_cmt(ep, policy_hash, resolver, "cmt_A")
            _register_cmt(ep, policy_hash, resolver, "cmt_B")
            # res_B is for cmt_B, not cmt_A.
            _observe_res(ep, policy_hash, resolver, "res_B",
                         commitment_ref_ids=["cmt_B"])
            kept = FulfillmentKeptArtifact(
                fulfillment_id="ful_wrong_anchor",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_A",
                result_id="res_B",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
            )
            with pytest.raises(UnanchoredFulfillmentError):
                emit_fulfillment_kept(ep, kept)

    def test_broken_rejects_result_observed_for_different_commitment(
        self, tmp_store, compile_receipt
    ):
        path, policy_hash = compile_receipt
        resolver = PolicyResolver(kind="uri", ref=_ref(path), policy_hash=policy_hash)
        with open_episode(store=tmp_store) as ep:
            _register_cmt(ep, policy_hash, resolver, "cmt_X")
            _register_cmt(ep, policy_hash, resolver, "cmt_Y")
            _observe_res(ep, policy_hash, resolver, "res_Y",
                         commitment_ref_ids=["cmt_Y"])
            broken = FulfillmentBrokenArtifact(
                fulfillment_id="ful_wrong_broken",
                timestamp="2026-04-20T14:00:00.000Z",
                episode_id=ep.episode_id,
                commitment_id="cmt_X",
                result_id="res_Y",
                evaluator="test",
                evaluator_version="0.1",
                policy_hash=policy_hash,
                policy_resolver=resolver.to_dict(),
                violation_reason="attempted misclose",
            )
            with pytest.raises(UnanchoredFulfillmentError):
                emit_fulfillment_broken(ep, broken)

    def test_detector_reports_open_when_anchor_references_wrong_commitment(
        self, tmp_store
    ):
        """Even if the fabricator bypasses the emitter, the detector refuses."""
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_A", due_at="2020-01-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_B", due_at="2020-01-01T00:00:00Z")
        # Observation references cmt_B, not cmt_A.
        _write_result(tmp_store, "res_B",
                      references=[{"kind": "commitment", "id": "cmt_B"}])
        # Fabricated terminal tries to close cmt_A with res_B.
        _write_kept(tmp_store, "cmt_A", "res_B")
        result = detect_open_overdue_commitments(tmp_store)
        open_ids = {c.commitment_id for c in result.open_commitments}
        assert "cmt_A" in open_ids  # not closed
        assert "cmt_B" in open_ids  # never attempted


# ---------------------------------------------------------------------------
# 16. Repair — detector preserves order
# ---------------------------------------------------------------------------


class TestDetectorPreservesOrder:
    """A later observation cannot retroactively legitimize a prior terminal."""

    def test_terminal_written_before_observation_does_not_close(self, tmp_store):
        """Forged terminal first, then observation — commitment stays open."""
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_forged", due_at="2020-01-01T00:00:00Z")
        # Forged terminal BEFORE any result.observed.
        _write_kept(tmp_store, "cmt_forged", "res_late")
        # Observation appended AFTER — would have anchored, had order allowed.
        _write_result(
            tmp_store,
            "res_late",
            references=[{"kind": "commitment", "id": "cmt_forged"}],
        )
        result = detect_open_overdue_commitments(tmp_store)
        open_ids = {c.commitment_id for c in result.open_commitments}
        assert "cmt_forged" in open_ids

    def test_proper_order_closes(self, tmp_store):
        """Registered, then observed (with ref), then terminal — closes cleanly."""
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_ord", due_at="2020-01-01T00:00:00Z")
        _write_result(
            tmp_store,
            "res_ord",
            references=[{"kind": "commitment", "id": "cmt_ord"}],
        )
        _write_kept(tmp_store, "cmt_ord", "res_ord")
        result = detect_open_overdue_commitments(tmp_store)
        assert result.clean

    def test_terminal_before_registration_does_not_close(self, tmp_store):
        """Terminal preceding its own registration is invalid (ordering)."""
        tmp_store.start_trace()
        # Terminal appears BEFORE registration.
        _write_kept(tmp_store, "cmt_early", "res_early")
        # Then registration.
        _write_registered(tmp_store, "cmt_early", due_at="2020-01-01T00:00:00Z")
        # Then observation with correct ref.
        _write_result(
            tmp_store,
            "res_early",
            references=[{"kind": "commitment", "id": "cmt_early"}],
        )
        result = detect_open_overdue_commitments(tmp_store)
        open_ids = {c.commitment_id for c in result.open_commitments}
        assert "cmt_early" in open_ids


# ---------------------------------------------------------------------------
# 17. Repair — corruption fails closed as ReceiptStoreIntegrityError
# ---------------------------------------------------------------------------


def _corrupt_current_trace(store):
    """Append a malformed JSON line to the most recent trace file."""
    trace_files = sorted(store.base_dir.rglob("trace_*.jsonl"))
    assert trace_files, "expected at least one trace file"
    target = trace_files[-1]
    with open(target, "a") as handle:
        handle.write("{this is not valid json\n")


class TestCorruptionFailsClosed:
    """Malformed JSON / unreadable files surface as integrity errors."""

    def test_detector_raises_on_malformed_json_line(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_int", due_at="2099-01-01T00:00:00Z")
        _corrupt_current_trace(tmp_store)
        with pytest.raises(ReceiptStoreIntegrityError):
            detect_open_overdue_commitments(tmp_store)

    def test_iter_all_receipts_raises_on_malformed_json(self, tmp_store):
        """Direct: _iter_all_receipts must raise rather than skip a bad line."""
        from assay.commitment_fulfillment import _iter_all_receipts

        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_iter", due_at="2099-01-01T00:00:00Z")
        _corrupt_current_trace(tmp_store)
        with pytest.raises(ReceiptStoreIntegrityError):
            list(_iter_all_receipts(tmp_store))

    def test_missing_store_seq_fails_closed(self, tmp_store):
        """A receipt lacking _store_seq must surface as an integrity failure."""
        from assay.commitment_fulfillment import _iter_all_receipts

        tmp_store.start_trace()
        # Write a legitimate receipt via append_dict (gets _store_seq stamped),
        # then manually inject a line without _store_seq into the same file.
        _write_registered(tmp_store, "cmt_seq", due_at="2099-01-01T00:00:00Z")
        trace_files = sorted(tmp_store.base_dir.rglob("trace_*.jsonl"))
        target = trace_files[-1]
        with open(target, "a") as handle:
            handle.write('{"type": "result.observed", "result_id": "sneaky"}\n')
        with pytest.raises(ReceiptStoreIntegrityError):
            list(_iter_all_receipts(tmp_store))

    def test_duplicate_store_seq_fails_closed(self, tmp_store):
        """Two receipts carrying the same _store_seq must raise integrity error."""
        from assay.commitment_fulfillment import _iter_all_receipts

        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_dup", due_at="2099-01-01T00:00:00Z")
        # Inject a second receipt with a duplicate _store_seq.
        trace_files = sorted(tmp_store.base_dir.rglob("trace_*.jsonl"))
        target = trace_files[-1]
        # The legitimate registration above got _store_seq=1 (or similar); we
        # re-use 0 which AssayStore assigned to "episode.opened"/first write.
        with open(target, "a") as handle:
            handle.write(
                '{"type": "result.observed", "result_id": "dup", '
                '"_trace_id": "trace_dup", "_stored_at": "2026-01-01T00:00:00Z", '
                '"_store_seq": 0}\n'
            )
        with pytest.raises(ReceiptStoreIntegrityError):
            list(_iter_all_receipts(tmp_store))

    def test_non_monotonic_store_seq_within_file_fails_closed(self, tmp_store):
        """A within-file seq regression (tampering) surfaces as integrity error."""
        from assay.commitment_fulfillment import _iter_all_receipts

        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_mono", due_at="2099-01-01T00:00:00Z")
        # Append a line with a _store_seq LOWER than any legitimate seq in the file.
        trace_files = sorted(tmp_store.base_dir.rglob("trace_*.jsonl"))
        target = trace_files[-1]
        with open(target, "a") as handle:
            handle.write(
                '{"type": "result.observed", "result_id": "back", '
                '"_trace_id": "trace_back", "_stored_at": "2026-01-01T00:00:00Z", '
                '"_store_seq": -5}\n'
            )
        with pytest.raises(ReceiptStoreIntegrityError):
            list(_iter_all_receipts(tmp_store))

    def test_emit_path_fails_closed_when_older_trace_corrupt(
        self, tmp_store
    ):
        """An older corrupted trace must surface as integrity failure on ANY write.

        Under the strict rollout contract, a corrupt corpus fails every
        write from the first attempt onward — including the implicit
        episode.opened write inside ``open_episode``. This is the correct
        semantic: if the store is lying, the next write must not make it
        lie more.
        """
        # Pre-plant a corrupted trace that sort-orders BEFORE any real trace.
        older_dir = tmp_store.base_dir / "2020-01-01"
        older_dir.mkdir(parents=True, exist_ok=True)
        (older_dir / "trace_20200101T000000_beefbeef.jsonl").write_text(
            "{ this is not valid json\n"
        )

        # Any write attempt must raise — we exercise the most basic one.
        tmp_store.start_trace(trace_id="trace_attempt")
        with pytest.raises(ReceiptStoreIntegrityError):
            tmp_store.append_dict({"type": "probe"})


# ---------------------------------------------------------------------------
# 18. Repair — order is _store_seq, not lexicographic trace path
# ---------------------------------------------------------------------------


class TestStoreSeqIsCausalOrder:
    """The detector's causal order comes from _store_seq, not trace filename order.

    Reviewer repro: AssayStore.start_trace(trace_id=...) accepts arbitrary
    trace IDs, so ``sorted(rglob("trace_*.jsonl"))`` does NOT reflect write
    chronology. A forged terminal in a trace whose name sorts LAST but was
    written FIRST must not be closed by an observation in a trace that sorts
    first but was written later.
    """

    def test_forged_terminal_in_trace_z_not_legitimized_by_later_trace_a(
        self, tmp_store
    ):
        """trace_zzz written first, trace_aaa written later; closure must not happen."""
        # trace_z is written FIRST chronologically (gets low _store_seq),
        # but its path sorts AFTER trace_a alphabetically.
        tmp_store.start_trace(trace_id="trace_zzzzzzzz_ffffffff")
        _write_registered(tmp_store, "cmt_cross", due_at="2020-01-01T00:00:00Z")
        # Forged terminal — no observation yet at this receipt-order point.
        _write_kept(tmp_store, "cmt_cross", "res_cross")

        # trace_a is written LATER (gets higher _store_seq), but its path
        # sorts BEFORE trace_z. A path-sorted scan would see the observation
        # before the terminal and wrongly close the commitment.
        tmp_store.start_trace(trace_id="trace_aaaaaaaa_00000000")
        _write_result(
            tmp_store,
            "res_cross",
            references=[{"kind": "commitment", "id": "cmt_cross"}],
        )

        result = detect_open_overdue_commitments(tmp_store)
        open_ids = {c.commitment_id for c in result.open_commitments}
        assert "cmt_cross" in open_ids, (
            "Detector must use _store_seq for causal order, not trace-path sort. "
            "Under path-sort, trace_a (observation) would precede trace_z (terminal) "
            "and close the commitment; under _store_seq, the forged terminal has "
            "lower seq and is invalid at its encounter point."
        )

    def test_proper_cross_trace_order_closes(self, tmp_store):
        """Inverted trace names: writes in causal order despite adversarial sort.

        trace_zzz receives register+observe FIRST (lower _store_seq), trace_aaa
        receives the terminal LATER (higher _store_seq). Under path-sort, this
        would look like terminal precedes registration (wrongly invalid). Under
        _store_seq, this is proper causal order and closes correctly.
        """
        tmp_store.start_trace(trace_id="trace_zzzzzzzz_00000000")
        _write_registered(tmp_store, "cmt_cross_ok", due_at="2020-01-01T00:00:00Z")
        _write_result(
            tmp_store,
            "res_cross_ok",
            references=[{"kind": "commitment", "id": "cmt_cross_ok"}],
        )

        tmp_store.start_trace(trace_id="trace_aaaaaaaa_00000000")
        _write_kept(tmp_store, "cmt_cross_ok", "res_cross_ok")

        result = detect_open_overdue_commitments(tmp_store)
        assert result.clean, (
            "Proper causal order (register → observe → terminal) must close, "
            "even when trace names invert the lexicographic order."
        )

    def test_store_seq_is_stamped_on_every_write(self, tmp_store):
        """append_dict and append both stamp monotonic _store_seq."""
        tmp_store.start_trace()
        tmp_store.append_dict({"type": "alpha", "n": 1})
        tmp_store.append_dict({"type": "beta", "n": 2})
        tmp_store.append_dict({"type": "gamma", "n": 3})

        trace_files = sorted(tmp_store.base_dir.rglob("trace_*.jsonl"))
        entries = []
        for f in trace_files:
            with open(f) as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        seqs = [e.get("_store_seq") for e in entries]
        assert None not in seqs, f"missing _store_seq somewhere: {seqs}"
        # Strictly increasing
        assert all(a < b for a, b in zip(seqs, seqs[1:])), f"non-monotonic: {seqs}"


# ---------------------------------------------------------------------------
# 19. Repair — cross-process-safe _store_seq allocator
# ---------------------------------------------------------------------------


def _collect_all_store_seqs(base_dir):
    """Helper: read every _store_seq in every trace file under base_dir."""
    seqs = []
    for trace_file in sorted(base_dir.rglob("trace_*.jsonl")):
        with open(trace_file) as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                entry = json.loads(stripped)
                seq = entry.get("_store_seq")
                if seq is not None:
                    seqs.append(seq)
    return seqs


class TestStoreSeqAllocatorIsCrossProcessSafe:
    """Two independent AssayStore instances sharing base_dir must never
    allocate the same _store_seq.
    """

    def test_two_instances_share_base_dir_unique_seqs(self, tmp_path):
        """Two AssayStore instances, same base_dir, writes interleaved."""
        base_dir = tmp_path / "shared"
        store_a = AssayStore(base_dir=base_dir)
        store_b = AssayStore(base_dir=base_dir)
        store_a.start_trace(trace_id="trace_shared_a")
        store_b.start_trace(trace_id="trace_shared_b")

        # Interleave writes across instances.
        for i in range(5):
            store_a.append_dict({"type": "from_a", "i": i})
            store_b.append_dict({"type": "from_b", "i": i})

        seqs = _collect_all_store_seqs(base_dir)
        assert len(seqs) == 10, f"expected 10 seqs, got {seqs}"
        assert len(set(seqs)) == 10, f"duplicate _store_seq: {seqs}"

    def test_multiprocess_writers_allocate_unique_seqs(self, tmp_path):
        """Two OS processes writing to the same base_dir must not collide."""
        import multiprocessing as mp

        base_dir = tmp_path / "mp"
        base_dir.mkdir(parents=True, exist_ok=True)

        ctx = mp.get_context("spawn")
        procs = [
            ctx.Process(
                target=_mp_writer_body,
                args=(str(base_dir), f"trace_mp_{i}", 10),
            )
            for i in range(2)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
            assert p.exitcode == 0, (
                f"subprocess exited {p.exitcode}; "
                "see stderr above for allocator failure."
            )

        seqs = _collect_all_store_seqs(base_dir)
        assert len(seqs) == 20, f"expected 20 seqs, got {len(seqs)}: {seqs}"
        assert len(set(seqs)) == 20, f"duplicate _store_seq across processes: {seqs}"

    def test_detector_accepts_store_after_concurrent_writes(self, tmp_path):
        """Concurrent-writer output must still pass _iter_all_receipts integrity."""
        from assay.commitment_fulfillment import _iter_all_receipts

        base_dir = tmp_path / "post_mp"
        store_a = AssayStore(base_dir=base_dir)
        store_b = AssayStore(base_dir=base_dir)
        store_a.start_trace(trace_id="trace_post_a")
        store_b.start_trace(trace_id="trace_post_b")
        for i in range(5):
            store_a.append_dict({"type": "from_a", "i": i})
            store_b.append_dict({"type": "from_b", "i": i})

        # Scan uses either store instance — they share base_dir.
        entries = list(_iter_all_receipts(store_a))
        assert len(entries) == 10
        seqs = [e["_store_seq"] for e in entries]
        # Sort is inherent to _iter_all_receipts.
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == 10


# Module-level helper (must be picklable for multiprocessing "spawn").
def _mp_writer_body(base_dir_str, trace_id, count):
    """Write ``count`` receipts from a subprocess to the named base_dir."""
    from assay.store import AssayStore as _AssayStore

    store = _AssayStore(base_dir=Path(base_dir_str))
    store.start_trace(trace_id=trace_id)
    for i in range(count):
        store.append_dict({"type": "subproc", "trace_id": trace_id, "i": i})


# ---------------------------------------------------------------------------
# 20. Repair — legacy-store migration path
# ---------------------------------------------------------------------------


class TestLegacyStoreMigration:
    """Backfill _store_seq on pre-Slice-1 stores without silent reinterpretation."""

    def _write_legacy_entry(self, path, entry):
        """Write a single legacy receipt (no _store_seq) to path."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as handle:
            handle.write(json.dumps(entry) + "\n")

    def test_migration_backfills_pure_legacy_store(self, tmp_path):
        from assay.store_seq_migration import migrate_legacy_store_seq

        base_dir = tmp_path / "legacy"
        day = base_dir / "2026-04-20"
        # Three legacy entries across two trace files, no _store_seq.
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "alpha", "_trace_id": "trace_20260420T010000_aaaaaaaa",
             "_stored_at": "2026-04-20T01:00:00Z"},
        )
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "beta", "_trace_id": "trace_20260420T010000_aaaaaaaa",
             "_stored_at": "2026-04-20T01:00:01Z"},
        )
        self._write_legacy_entry(
            day / "trace_20260420T020000_bbbbbbbb.jsonl",
            {"type": "gamma", "_trace_id": "trace_20260420T020000_bbbbbbbb",
             "_stored_at": "2026-04-20T02:00:00Z"},
        )

        store = AssayStore(base_dir=base_dir)
        result = migrate_legacy_store_seq(store)

        assert result.receipts_backfilled == 3
        assert result.next_seq == 3
        assert result.ordering_basis == "path_then_line"

        seqs = _collect_all_store_seqs(base_dir)
        assert sorted(seqs) == [0, 1, 2]

    def test_migration_enables_subsequent_writes_to_continue_sequence(
        self, tmp_path
    ):
        from assay.store_seq_migration import migrate_legacy_store_seq

        base_dir = tmp_path / "legacy_continue"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "old"},
        )
        store = AssayStore(base_dir=base_dir)
        migrate_legacy_store_seq(store)

        # New write continues the monotonic sequence.
        store.start_trace()
        store.append_dict({"type": "new_after_migration"})
        seqs = _collect_all_store_seqs(base_dir)
        assert sorted(seqs) == [0, 1]

    def test_migration_refuses_mixed_state(self, tmp_path):
        from assay.store_seq_migration import (
            StoreMigrationError,
            migrate_legacy_store_seq,
        )

        base_dir = tmp_path / "mixed"
        day = base_dir / "2026-04-20"
        # One legacy, one already-migrated.
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "legacy"},
        )
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "new", "_store_seq": 42},
        )
        store = AssayStore(base_dir=base_dir)
        with pytest.raises(StoreMigrationError):
            migrate_legacy_store_seq(store)

    def test_migration_refuses_duplicate_existing_seqs(self, tmp_path):
        from assay.store_seq_migration import (
            StoreMigrationError,
            migrate_legacy_store_seq,
        )

        base_dir = tmp_path / "dupseq"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "x", "_store_seq": 5},
        )
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "y", "_store_seq": 5},
        )
        store = AssayStore(base_dir=base_dir)
        with pytest.raises(StoreMigrationError):
            migrate_legacy_store_seq(store)

    def test_migration_is_idempotent(self, tmp_path):
        from assay.store_seq_migration import migrate_legacy_store_seq

        base_dir = tmp_path / "idem"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "alpha"},
        )
        store = AssayStore(base_dir=base_dir)
        first = migrate_legacy_store_seq(store)
        second = migrate_legacy_store_seq(store)
        assert first.receipts_backfilled == 1
        assert second.receipts_backfilled == 0
        assert second.ordering_basis == "already_migrated"

    def test_migration_makes_legacy_store_detector_ready(self, tmp_path):
        """After migration, _iter_all_receipts succeeds on previously-legacy data."""
        from assay.commitment_fulfillment import _iter_all_receipts
        from assay.store_seq_migration import migrate_legacy_store_seq

        base_dir = tmp_path / "post_migrate"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "legacy1"},
        )
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "legacy2"},
        )
        store = AssayStore(base_dir=base_dir)

        # Before migration: detector fails closed.
        with pytest.raises(ReceiptStoreIntegrityError):
            list(_iter_all_receipts(store))

        migrate_legacy_store_seq(store)

        # After migration: detector walks cleanly.
        entries = list(_iter_all_receipts(store))
        assert len(entries) == 2
        assert [e["_store_seq"] for e in entries] == [0, 1]


# ---------------------------------------------------------------------------
# 21. Repair — write path refuses unmigrated legacy stores
# ---------------------------------------------------------------------------


class TestWritePathRefusesLegacyStore:
    """A single ordinary write must NOT be able to strand a legacy store in
    mixed state. The write path must refuse until migration has run.
    """

    def _write_legacy_entry(self, path, entry):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as handle:
            handle.write(json.dumps(entry) + "\n")

    def test_append_dict_refuses_unmigrated_legacy_store(self, tmp_path):
        from assay.store import MigrationRequiredError

        base_dir = tmp_path / "refuse_legacy"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "legacy_alpha"},
        )
        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_attempted_write")
        with pytest.raises(MigrationRequiredError):
            store.append_dict({"type": "new_write"})

    def test_refusal_does_not_create_mixed_state(self, tmp_path):
        """Refused write must leave legacy files and .store_seq untouched."""
        from assay.store import MigrationRequiredError

        base_dir = tmp_path / "refuse_unmutated"
        day = base_dir / "2026-04-20"
        legacy_path = day / "trace_20260420T010000_aaaaaaaa.jsonl"
        self._write_legacy_entry(legacy_path, {"type": "legacy_x"})
        legacy_bytes_before = legacy_path.read_bytes()

        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_untouched")
        with pytest.raises(MigrationRequiredError):
            store.append_dict({"type": "new"})

        # Legacy file unchanged.
        assert legacy_path.read_bytes() == legacy_bytes_before
        # .store_seq counter MUST NOT have been created.
        assert not (base_dir / ".store_seq").exists(), (
            "refused write must not create .store_seq — that would make the "
            "next write think the store is pre-initialized and bypass the "
            "legacy guard."
        )
        # And the migration path still works.
        from assay.store_seq_migration import migrate_legacy_store_seq

        result = migrate_legacy_store_seq(store)
        assert result.receipts_backfilled == 1

    def test_post_migration_writes_succeed_and_continue_sequence(self, tmp_path):
        from assay.store_seq_migration import migrate_legacy_store_seq

        base_dir = tmp_path / "post_ok"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "legacy_seed"},
        )
        store = AssayStore(base_dir=base_dir)
        migrate_legacy_store_seq(store)

        store.start_trace(trace_id="trace_post_mig")
        store.append_dict({"type": "fresh_after_migration"})

        seqs = _collect_all_store_seqs(base_dir)
        assert sorted(seqs) == [0, 1]

    def test_append_method_also_refuses_legacy_store(self, tmp_path):
        """BaseModel.append() path must refuse the same way as append_dict."""
        from assay._receipts.compat.pyd import BaseModel as _PydBase
        from assay.store import MigrationRequiredError

        class _Tiny(_PydBase):
            type: str
            receipt_id: str

        base_dir = tmp_path / "refuse_legacy_append"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "legacy_append"},
        )
        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_append_attempt")
        with pytest.raises(MigrationRequiredError):
            store.append(_Tiny(type="probe", receipt_id="r_probe"))

    def test_cli_migrates_legacy_store(self, tmp_path):
        """`python -m assay.store_seq_migration <base_dir>` migrates successfully."""
        import subprocess
        import sys

        base_dir = tmp_path / "cli_legacy"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "cli_legacy_1"},
        )
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "cli_legacy_2"},
        )

        proc = subprocess.run(
            [sys.executable, "-m", "assay.store_seq_migration", str(base_dir)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, (
            f"CLI migration failed: stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        assert "receipts_backfilled=2" in proc.stdout
        assert "ordering_basis=path_then_line" in proc.stdout

        seqs = _collect_all_store_seqs(base_dir)
        assert sorted(seqs) == [0, 1]

    def test_cli_returns_nonzero_on_mixed_state(self, tmp_path):
        """CLI must exit nonzero when migration refuses mixed state."""
        import subprocess
        import sys

        base_dir = tmp_path / "cli_mixed"
        day = base_dir / "2026-04-20"
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "legacy_cli"},
        )
        self._write_legacy_entry(
            day / "trace_20260420T010000_aaaaaaaa.jsonl",
            {"type": "migrated_cli", "_store_seq": 42},
        )

        proc = subprocess.run(
            [sys.executable, "-m", "assay.store_seq_migration", str(base_dir)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 3, (
            f"expected exit 3 on mixed state, got {proc.returncode}: "
            f"stderr={proc.stderr!r}"
        )
        assert "migration refused" in proc.stderr.lower()

    def test_cli_rejects_missing_argument(self, tmp_path):
        """Usage error exits 2."""
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "assay.store_seq_migration"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 2


# ---------------------------------------------------------------------------
# 22. Repair — strict write-path validation for corrupt and mixed stores
# ---------------------------------------------------------------------------


class TestWritePathStrictCorpusValidation:
    """``.store_seq`` is NOT a health certificate. The write path must
    validate the full trace corpus on every write and fail closed on
    corruption or mixed state, regardless of whether ``.store_seq`` exists.
    """

    def _write_legacy_entry(self, path, entry):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as handle:
            handle.write(json.dumps(entry) + "\n")

    def test_corrupt_trace_without_counter_refuses_write(self, tmp_path):
        """Malformed JSON + absent .store_seq → write refused as integrity error."""
        from assay.store import ReceiptStoreIntegrityError

        base_dir = tmp_path / "corrupt_no_counter"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        (day / "trace_20260420T000000_aaaaaaaa.jsonl").write_text(
            "{this is not valid json\n"
        )
        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_attempt")
        with pytest.raises(ReceiptStoreIntegrityError):
            store.append_dict({"type": "probe"})

    def test_corrupt_trace_refusal_does_not_create_counter_file(self, tmp_path):
        """Refused write on corrupt store must not silently create .store_seq."""
        from assay.store import ReceiptStoreIntegrityError

        base_dir = tmp_path / "corrupt_no_side_effect"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        (day / "trace_20260420T000000_aaaaaaaa.jsonl").write_text(
            "{bad\n"
        )
        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_attempt")
        with pytest.raises(ReceiptStoreIntegrityError):
            store.append_dict({"type": "probe"})
        assert not (base_dir / ".store_seq").exists()

    def test_corrupt_trace_with_existing_counter_still_refuses(self, tmp_path):
        """.store_seq existence must not pardon a corrupt corpus."""
        from assay.store import ReceiptStoreIntegrityError

        base_dir = tmp_path / "corrupt_with_counter"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        # Legitimate stamped receipt.
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "legit", "_store_seq": 0},
        )
        # Counter says next_seq=1.
        (base_dir / ".store_seq").write_text("1")
        # Now append malformed JSON to the same file.
        with open(day / "trace_20260420T000000_aaaaaaaa.jsonl", "a") as handle:
            handle.write("{gibberish\n")

        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_corrupt_attempt")
        with pytest.raises(ReceiptStoreIntegrityError):
            store.append_dict({"type": "probe"})

    def test_mixed_state_with_existing_counter_refuses_write(self, tmp_path):
        """Mixed state with .store_seq must still refuse writes."""
        from assay.store import ReceiptStoreIntegrityError

        base_dir = tmp_path / "mixed_with_counter"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "legacy_half"},
        )
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "stamped_half", "_store_seq": 0},
        )
        (base_dir / ".store_seq").write_text("1")

        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_mixed_attempt")
        with pytest.raises(ReceiptStoreIntegrityError):
            store.append_dict({"type": "probe"})

    def test_healthy_current_store_allows_writes(self, tmp_path):
        """All receipts stamped + valid counter → writes proceed normally."""
        base_dir = tmp_path / "healthy_current"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "first", "_store_seq": 0},
        )
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "second", "_store_seq": 1},
        )
        (base_dir / ".store_seq").write_text("2")

        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_healthy_new")
        store.append_dict({"type": "fresh"})

        seqs = _collect_all_store_seqs(base_dir)
        assert sorted(seqs) == [0, 1, 2]

    def test_current_store_without_counter_reconstructs_from_corpus(self, tmp_path):
        """All receipts stamped + absent .store_seq → write reconstructs next seq.

        This is the "pardon-less" path: even without the counter file,
        strict validation must pass first, then next_seq is derived as
        ``max(_store_seq) + 1`` under the flock.
        """
        base_dir = tmp_path / "current_no_counter"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "stamped_0", "_store_seq": 0},
        )
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "stamped_1", "_store_seq": 1},
        )
        # .store_seq deliberately absent.
        assert not (base_dir / ".store_seq").exists()

        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_reconstruct")
        store.append_dict({"type": "resumed"})

        seqs = _collect_all_store_seqs(base_dir)
        assert sorted(seqs) == [0, 1, 2]
        # Counter now persisted.
        assert (base_dir / ".store_seq").read_text().strip() == "3"

    def test_duplicate_store_seq_in_corpus_refuses_write(self, tmp_path):
        """Two stamped receipts with the same _store_seq is integrity corruption,
        not a legacy/migration situation. Write must be refused with
        ReceiptStoreIntegrityError regardless of .store_seq counter.
        """
        from assay.store import ReceiptStoreIntegrityError

        base_dir = tmp_path / "dup_corpus"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "a", "_store_seq": 5},
        )
        # Second file (sorts later); second receipt has same seq=5.
        self._write_legacy_entry(
            day / "trace_20260420T000001_bbbbbbbb.jsonl",
            {"type": "b", "_store_seq": 5},
        )
        (base_dir / ".store_seq").write_text("6")

        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_dup_attempt")
        with pytest.raises(ReceiptStoreIntegrityError):
            store.append_dict({"type": "probe"})

    def test_within_file_store_seq_regression_refuses_write(self, tmp_path):
        """A stamped file whose _store_seq regresses (10 then 3) is corrupt.
        Write must be refused."""
        from assay.store import ReceiptStoreIntegrityError

        base_dir = tmp_path / "regress_corpus"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        f = day / "trace_20260420T000000_aaaaaaaa.jsonl"
        self._write_legacy_entry(f, {"type": "first", "_store_seq": 10})
        self._write_legacy_entry(f, {"type": "regress", "_store_seq": 3})
        (base_dir / ".store_seq").write_text("11")

        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_regress_attempt")
        with pytest.raises(ReceiptStoreIntegrityError):
            store.append_dict({"type": "probe"})

    def test_non_integer_store_seq_is_integrity_error_not_migration(self, tmp_path):
        """A receipt with _store_seq set to a non-integer is corpus corruption,
        not legacy data. The error must be ReceiptStoreIntegrityError —
        sending operators to migration would mislead them (migration would
        refuse the store anyway).
        """
        from assay.store import MigrationRequiredError, ReceiptStoreIntegrityError

        base_dir = tmp_path / "non_int_corpus"
        day = base_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "x", "_store_seq": "oops"},
        )

        store = AssayStore(base_dir=base_dir)
        store.start_trace(trace_id="trace_nonint_attempt")
        with pytest.raises(ReceiptStoreIntegrityError) as exc_info:
            store.append_dict({"type": "probe"})
        # Important: NOT MigrationRequiredError — "oops" is not legacy data.
        assert not isinstance(exc_info.value, MigrationRequiredError)

    def test_error_taxonomy_distinguishes_legacy_from_corrupt(self, tmp_path):
        """Pure legacy → MigrationRequiredError; mixed/corrupt → integrity error."""
        from assay.store import MigrationRequiredError, ReceiptStoreIntegrityError

        # Pure legacy.
        legacy_dir = tmp_path / "legacy_taxo"
        day = legacy_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "legacy_only"},
        )
        store_legacy = AssayStore(base_dir=legacy_dir)
        store_legacy.start_trace(trace_id="trace_legacy_attempt")
        with pytest.raises(MigrationRequiredError):
            store_legacy.append_dict({"type": "probe"})

        # Mixed.
        mixed_dir = tmp_path / "mixed_taxo"
        day = mixed_dir / "2026-04-20"
        day.mkdir(parents=True, exist_ok=True)
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "leg"},
        )
        self._write_legacy_entry(
            day / "trace_20260420T000000_aaaaaaaa.jsonl",
            {"type": "stamped", "_store_seq": 99},
        )
        store_mixed = AssayStore(base_dir=mixed_dir)
        store_mixed.start_trace(trace_id="trace_mixed_attempt")
        with pytest.raises(ReceiptStoreIntegrityError):
            store_mixed.append_dict({"type": "probe"})
