"""Trust evaluation layer for Assay proof packs.

Implements the four-stage model from docs/TRUST_POLICY_CONSTITUTION.md:
  classify → verify → authorize → accept

This layer consumes verification results; it does not modify the verifier.
Enforcement is a caller choice.
"""
