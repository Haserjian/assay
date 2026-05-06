"""Tests for the v0 AuthorityChain validator.

Each failing fixture is one mutation off the smoke baseline so the cause of
illegitimacy is easy to inspect.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from assay.runtime.authority_chain_validator import (
    AuthorityChainValidator,
    ChainStatus,
    ReasonCode,
)


_NOW = datetime(2026, 5, 4, tzinfo=timezone.utc)


def _artifact(role: str, **extra: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "schema_version": "0.1",
        "canonical_hash": "sha256:demo",
        "signature": "sig",
        "signed_by": f"{role}-key",
        "role": role,
        "requires_log_inclusion": True,
    }
    base.update(extra)
    return base


def _smoke_chain_template() -> Dict[str, Any]:
    chain: Dict[str, Any] = {
        "claim_ref": "claim-1",
        "normalization_receipt_ref": "norm-1",
        "claim_type_ref": "claimtype-safe-patch-local",
        "charter_clause_ref": "charter-clause-local-code",
        "invariant_library_ref": "invlib-1",
        "verifier_contract_ref": "contract-1",
        "verifier_receipt_refs": ["receipt-tests", "receipt-lint"],
        "scope_composition_proof_ref": "scope-proof-1",
        "adjudication_receipt_ref": "adj-1",
        "action_receipt_ref": "action-1",
        "rollback_contract_ref": "rollback-1",
        "revoked_artifact_refs": [],
        "log_inclusion_proofs": {
            ref: {
                "log_index": "1",
                "integrated_time": "2026-05-04T00:00:00Z",
            }
            for ref in (
                "claim-1",
                "norm-1",
                "claimtype-safe-patch-local",
                "charter-clause-local-code",
                "invlib-1",
                "contract-1",
                "receipt-tests",
                "receipt-lint",
                "scope-proof-1",
                "adj-1",
                "action-1",
                "rollback-1",
            )
        },
        "authority": {
            "claim_tier": "B",
            "evidence_tier": "B",
            "action_domain_authorized": True,
        },
        "artifacts": {},
    }
    chain["artifacts"] = {
        "claim-1": _artifact("claimant", text="this patch is safe"),
        "norm-1": _artifact(
            "normalizer",
            candidate_claim_types=[
                {
                    "claim_type_ref": "claimtype-safe-patch-local",
                    "viable": True,
                    "strictness_rank": 10,
                }
            ],
            selected="claimtype-safe-patch-local",
            ambiguity_flag=False,
        ),
        "claimtype-safe-patch-local": _artifact("principal"),
        "charter-clause-local-code": _artifact("principal-charter"),
        "invlib-1": _artifact("principal-library"),
        "contract-1": _artifact(
            "compiler",
            compiled_by="deterministic_contract_compiler",
            claim_type_ref="claimtype-safe-patch-local",
            invariant_library_ref="invlib-1",
            required_receipts=["affected_tests", "lint"],
        ),
        "receipt-tests": _artifact(
            "verifier-tests",
            contract_ref="contract-1",
            claim_ref="claim-1",
            question_shape="affected_module_tests",
            receipt_kind="affected_tests",
            tier_demotion_at="2026-06-01T00:00:00Z",
        ),
        "receipt-lint": _artifact(
            "verifier-lint",
            contract_ref="contract-1",
            claim_ref="claim-1",
            question_shape="lint",
            receipt_kind="lint",
            tier_demotion_at="2026-06-01T00:00:00Z",
        ),
        "scope-proof-1": _artifact(
            "scope-prover",
            monotone=True,
            composite_scope_exceeds_union=False,
        ),
        "adj-1": _artifact(
            "adjudicator",
            move="match",
            claim_ref="claim-1",
            final=True,
            earliest_adjudicable_at="2026-05-04T00:00:00Z",
            truth_bearing_free_text=False,
        ),
        "action-1": _artifact("executor"),
        "rollback-1": _artifact("rollback-author"),
    }
    return chain


def _build_smoke_chain() -> Dict[str, Any]:
    return copy.deepcopy(_smoke_chain_template())


# ---------------------------------------------------------------- happy path

def test_valid_authority_chain_smoke() -> None:
    chain = _build_smoke_chain()
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.LEGITIMATE, result.findings
    assert result.reason == ReasonCode.OK


# ---------------------------------------------------------- failing fixtures

def test_missing_log_inclusion_is_illegitimate() -> None:
    chain = _build_smoke_chain()
    chain["log_inclusion_proofs"].pop("receipt-tests")
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.ILLEGITIMATE, result.findings
    assert result.reason == ReasonCode.MISSING_LOG_INCLUSION


def test_non_strict_claimtype_selection_is_illegitimate() -> None:
    chain = _build_smoke_chain()
    norm = chain["artifacts"]["norm-1"]
    norm["candidate_claim_types"] = [
        {
            "claim_type_ref": "claimtype-safe-patch-local",
            "viable": True,
            "strictness_rank": 10,
        },
        {
            "claim_type_ref": "claimtype-safe-patch-production",
            "viable": True,
            "strictness_rank": 20,
        },
    ]
    # selected stays "claimtype-safe-patch-local"; selection_authority not set
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.ILLEGITIMATE, result.findings
    assert result.reason == ReasonCode.NON_STRICT_CLAIMTYPE_SELECTED


def test_stale_receipt_downgrades() -> None:
    chain = _build_smoke_chain()
    chain["artifacts"]["receipt-tests"]["tier_demotion_at"] = (
        "2026-05-01T00:00:00Z"
    )
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.DOWNGRADED, result.findings
    assert result.reason == ReasonCode.STALE_RECEIPT


def test_invalid_timestamp_is_structured_illegitimate() -> None:
    chain = _build_smoke_chain()
    chain["artifacts"]["receipt-tests"]["tier_demotion_at"] = "not-a-time"
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.ILLEGITIMATE, result.findings
    assert result.reason == ReasonCode.NONCANONICAL_ARTIFACT


def test_scope_extrapolation_is_illegitimate() -> None:
    chain = _build_smoke_chain()
    chain["artifacts"]["scope-proof-1"]["composite_scope_exceeds_union"] = True
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.ILLEGITIMATE, result.findings
    assert result.reason == ReasonCode.SCOPE_COMPOSITION_EXTRAPOLATED


def test_action_without_rollback_is_illegitimate() -> None:
    chain = _build_smoke_chain()
    chain["rollback_contract_ref"] = None
    # The action artifact does not declare charter_allows_irreversible.
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.ILLEGITIMATE, result.findings
    assert result.reason == ReasonCode.ACTION_WITHOUT_ROLLBACK


def test_self_signed_adjudication_is_illegitimate() -> None:
    chain = _build_smoke_chain()
    chain["artifacts"]["adj-1"]["role"] = "simulator"
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.ILLEGITIMATE, result.findings
    assert result.reason == ReasonCode.SELF_SIGNED_FORBIDDEN


def test_premature_final_adjudication_is_provisional() -> None:
    chain = _build_smoke_chain()
    chain["artifacts"]["adj-1"]["earliest_adjudicable_at"] = (
        (_NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    )
    chain["artifacts"]["adj-1"]["final"] = True
    result = AuthorityChainValidator(now=_NOW).validate(chain)
    assert result.status == ChainStatus.PROVISIONAL, result.findings
    assert result.reason == ReasonCode.TOO_EARLY_FOR_FINAL_ADJUDICATION
