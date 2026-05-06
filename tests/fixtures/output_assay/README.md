# Output Assay Calibration Fixtures

This fixture tree is the executable contract surface for Output Assay v0
calibration.

It tests:

- observation behavior
- Guardian gating labels
- promotion-eligibility labels

It does not test:

- external truth
- model-provider behavior
- analyzer logic
- kernel mutation

Invariant: golden expectations are calibration labels, not kernel receipts.

Seed fixtures in this scaffold intentionally stay small. They exist to pin the
file shape and validator behavior before the full 20-fixture set is authored.
