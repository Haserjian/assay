# VendorQ Provider Interface

VendorQ supports external answer providers via the `ASSAY_VENDORQ_PROVIDER` environment variable.

## Contract

A provider is a Python class with an optional `compile_answer` method:

```python
class MyProvider:
    def compile_answer(
        self,
        question: dict,
        evidence_index: dict,
        policy: dict,
        org_profile: dict | None,
    ) -> dict | None:
        """Compile a single VendorQ answer.

        Args:
            question: Normalized question dict (question_id, question_text, type_hint, required_format).
            evidence_index: Full evidence index with packs, by_pack, receipts.
            policy: Policy profile dict (name, freshness_window_days, allow_commitments, etc.).
            org_profile: Optional organization profile dict.

        Returns:
            A vendorq.answer.v1-conformant answer dict, or None to fall back to the default compiler.

        The returned dict MUST include all required fields from vendorq.answer.v1.schema.json:
            question_id, answer_id, status, answer_mode, claim_type,
            answer_bool, answer_value, details, confidence,
            evidence_refs, review_required, review_reason,
            review_owner_hint, risk_flags, missing_evidence_requests
        """
        ...
```

## Activation

```bash
export ASSAY_VENDORQ_PROVIDER=my_enterprise_module:EnterpriseProvider
assay vendorq compile --questions questions.json --pack ./pack --policy conservative --out answers.json
```

The provider is loaded once per compile invocation. If `compile_answer` returns `None` for a given question, the default heuristic compiler handles it.

## Fail-Closed Behavior

- Invalid `ASSAY_VENDORQ_PROVIDER` format (missing `:`) raises `VendorQInputError`.
- Import failure raises `VendorQInputError`.
- Class instantiation failure raises `VendorQInputError`.
- A compile warning is emitted when a provider override is active.

## Schema Enforcement

Provider-generated answers are validated against `vendorq.answer.v1.schema.json` at the payload level. If any answer violates the schema, `compile_answers_payload` raises `VendorQInputError`.

The deterministic verifier (VQ001-VQ010) runs identically regardless of whether answers came from the default compiler or a provider.

## Stub Provider

```python
"""Minimal VendorQ provider stub."""
from __future__ import annotations
from typing import Any, Dict, Optional


class StubProvider:
    """Returns None for all questions, deferring to default compiler."""

    def compile_answer(
        self,
        question: Dict[str, Any],
        evidence_index: Dict[str, Any],
        policy: Dict[str, Any],
        org_profile: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        return None
```

Save as `stub_provider.py` and activate:

```bash
export ASSAY_VENDORQ_PROVIDER=stub_provider:StubProvider
```

## Extension Points

Providers can implement richer answer compilation by:

1. Loading private playbook templates (SOC 2 / ISO 27001 / AI governance mappings).
2. Ranking evidence refs by recency, relevance, or receipt type.
3. Applying tone profiles (conservative, enterprise, government).
4. Mapping questions to compliance framework controls.

The open-core verifier enforces the same 10 rules (VQ001-VQ010) on all answers regardless of source.
