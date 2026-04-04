# Verifier Parity Tests

These tests enforce the cross-surface invariant checks described in SECURITY_INVARIANTS.md.

They run both the Python and TypeScript verifiers against the regression corpus
and assert identical pass/fail outcomes. Any divergence is a blocking failure.

## Test files to implement

- `test_verifier_parity.py` — INV-01: required field parity
- `test_passthrough_enforcement.py` — INV-02: token passthrough in both verifiers
- `test_invariants.py` — INV-04, INV-07, INV-08: PQ posture, ASCII-only field-name validation, and dual-signature warning behavior

## Corpus

Fixtures are in `tests/contracts/vectors/regression/`.
Each `*_spec.json` describes expected behavior for both implementations.

## Running

```bash
pytest tests/contracts/parity/ -v
```

These must pass before any release build.
