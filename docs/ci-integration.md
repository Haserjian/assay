# Assay in CI

CI is where evidence discipline stops being optional.

Without CI, generating and verifying evidence is possible but depends on
someone remembering to do it. With CI, every pull request produces and
verifies an evidence pack before the change is accepted.

That is the real shift: not automation for convenience, but merge
enforcement for control.

## What CI adds

| Without CI | With CI |
|------------|---------|
| Evidence generation is manual | Every PR produces an evidence pack |
| Verification happens if someone remembers | Verification is required before merge |
| Governance drift is invisible | Lockfile catches semantic changes |
| Regressions surface in review (maybe) | Regressions block the build |
| Audit evidence is assembled after the fact | Audit evidence is a build artifact |

## The adoption path

Most teams should start narrow and tighten over time.

### Stage 1: Generate and verify

Run your code under Assay in CI. Verify the resulting evidence pack.
This alone gives you a per-PR evidence trail.

```yaml
- run: assay run -c receipt_completeness -- python my_app.py
- run: assay verify-pack ./proof_pack_*/
```

### Stage 2: Enforce claims

Require that behavioral claims pass before the build goes green.
An honest failure (integrity PASS, claims FAIL) blocks the merge --
which is the system working correctly.

```yaml
- run: assay verify-pack ./proof_pack_*/ --require-claim-pass
```

### Stage 3: Lock verification semantics

Pin your claim set with a lockfile so verification criteria cannot
silently weaken between runs.

```bash
assay lock write --cards receipt_completeness -o assay.lock
```

```yaml
- run: assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
```

### Stage 4: Gate on regressions

Compare against a baseline pack. Block merges that introduce cost,
latency, or error regressions.

```yaml
- run: assay diff ./baseline_pack/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0
```

## The fastest start

Use `assay ci init github` to generate a complete workflow file:

```bash
assay ci init github --run-command "python my_app.py"
```

This writes `.github/workflows/assay-verify.yml` with score gating,
pack verification, and report upload pre-configured.

Or use the [Assay Verify Action](https://github.com/Haserjian/assay-verify-action)
directly for a minimal setup that posts results as a PR comment.

## Exit codes in CI

The exit code contract is designed for CI gates:

| Code | Meaning | CI behavior |
|------|---------|-------------|
| 0 | Integrity PASS, claims PASS | Build passes |
| 1 | Integrity PASS, claims FAIL | Build fails (honest failure -- evidence is genuine, behavior didn't meet standards) |
| 2 | Integrity FAIL | Build fails (tampering, corruption, or lock drift) |

Exit 1 is not a tool failure. It means the system produced authentic
evidence that it did not meet the declared behavioral requirements.
That is Assay working correctly.

## Terminology

- **Evidence pack**: the signed, verifiable bundle produced by `assay run`
- **Lockfile**: a machine-readable contract that pins which claims are
  checked and how, preventing silent governance drift
- **Gate**: a CI check that blocks merge based on evidence pack results
- **Honest failure**: integrity PASS with claims FAIL -- genuine evidence
  proving the run did not meet standards

## Read next

- [Start Here](START_HERE.md) -- six steps from install to evidence in CI
- [Quickstart](README_quickstart.md) -- full command reference and Golden Path
- [Assay Verify Action](https://github.com/Haserjian/assay-verify-action) -- GitHub Action for PR-level verification
- [For Compliance Teams](for-compliance.md) -- what auditors see
