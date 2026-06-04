from __future__ import annotations

from assay.claim_gate.detectors import detect_collection
from assay.claim_gate.diff_source import diff_pairs_from_texts


def test_detects_prototype_to_production_and_guarantee_transition() -> None:
    pairs = diff_pairs_from_texts(
        "README.md",
        "This experimental prototype may help evaluate agent workflows.\n",
        "This production-ready framework guarantees safe autonomous agent execution.\n",
    )

    transitions, non_claims = detect_collection(pairs)

    assert non_claims == []
    assert {item.transition_class for item in transitions} == {
        "prototype_to_production",
        "possible_to_guaranteed",
    }
    first = transitions[0]
    assert first.file == "README.md"
    assert first.before_span.start_line == 1
    assert first.after_span.text == (
        "This production-ready framework guarantees safe autonomous agent execution."
    )


def test_future_goal_language_is_recorded_as_non_claim() -> None:
    pairs = diff_pairs_from_texts(
        "ROADMAP.md",
        "",
        "Future goal: production-grade execution safety.\n",
    )

    transitions, non_claims = detect_collection(pairs)

    assert transitions == []
    assert len(non_claims) == 1
    assert non_claims[0].reason == "bounded_or_aspirational_marker:future goal"
    assert non_claims[0].span.start_line == 1


def test_generic_allow_marker_does_not_hide_hard_escalation() -> None:
    pairs = diff_pairs_from_texts(
        "README.md",
        "This prototype may help evaluate agent workflows.\n",
        "This experimental prototype guarantees safe autonomous execution.\n",
    )

    transitions, non_claims = detect_collection(
        pairs,
        allow_markers=("prototype", "experimental"),
    )

    assert non_claims == []
    assert {item.transition_class for item in transitions} == {
        "possible_to_guaranteed",
    }


def test_mixed_hunk_records_non_claim_without_hiding_transition() -> None:
    pairs = diff_pairs_from_texts(
        "README.md",
        "This may help evaluate agent workflows.\n",
        "Future work: improve docs.\nThis guarantees safe autonomous execution.\n",
    )

    transitions, non_claims = detect_collection(pairs)

    assert {item.transition_class for item in transitions} == {
        "possible_to_guaranteed",
    }
    assert len(non_claims) == 1
    assert non_claims[0].reason == "bounded_or_aspirational_marker:future work"
    assert non_claims[0].span.start_line == 1
    assert transitions[0].after_span.start_line == 2
