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

### Stage 5: Enforce org signer trust in CI

Once the basic pack/claim gate is real, bootstrap a concrete `ci-org`
signer in CI and require that the generated pack is accepted for
`ci_gate`.

This is the first point where CI stops asking only "did the pack verify?"
and starts asking "was it signed by the right authority for this context?"

Required CI material:

- repo variable: `ASSAY_CI_ORG_MAIN_FINGERPRINT`
- repo secrets: `ASSAY_CI_ORG_MAIN_PUB_B64`, `ASSAY_CI_ORG_MAIN_KEY_B64`

Current repo bootstrap path:

- `.github/workflows/ci-org-trust-gate.yml`
- `scripts/ci/bootstrap_ci_org_signer.py`
- `scripts/ci/build_ci_attestation_pack.py`

The workflow imports `ci-org-main` into a fresh `ASSAY_HOME`, writes a
temporary trust overlay rooted in `trust/`, builds a CI-bound proof pack,
and then requires:

- `ci_gate` acceptance
- `publication` acceptance
- clean trust-policy load
- matching `GITHUB_SHA` in the embedded CI binding

Example verify step:

```yaml
- run: |
    assay verify-pack ci_org_smoke_pack \
      --require-claim-pass \
      --require-ci-binding \
      --expected-commit-sha "$GITHUB_SHA" \
      --trust-target ci_gate \
      --trust-policy-dir "$RUNNER_TEMP/ci-org-trust" \
      --enforce-trust-gate
```

Important nuance:

- `--enforce-trust-gate` only hard-fails `ci_gate` on explicit reject
- trust load errors remain advisory at the CLI layer
- the workflow must therefore also inspect the JSON output and fail if:
  - `trust.load_errors` is non-empty
  - `trust.acceptance.decision` is not `accept`

This repo's committed `trust/signers.yaml` intentionally ships with
`signers: []`. The workflow overlay is a bootstrap move for the first real
`ci-org` rollout, not the final policy shape. Once a stable org fingerprint
is ready to pin in-repo, commit that signer entry and delete the overlay
step.

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

### Stage 6: Compiled packet gate

Stages 1–5 gate on evidence pack integrity and behavioral claims. The compiled
packet gate answers a different question: **is this packet admissible as a
reviewer-ready trust artifact?**

A compiled packet bundles a proof pack with a questionnaire, authored claim
bindings, and a declared subject. The gate enforces that the packet is
structurally INTACT, subject-bound, and fully bundled for offline verification.

```yaml
- name: Compile packet
  run: |
    assay packet compile \
      --draft ./draft/ \
      --packs ./proof_pack_*/ \
      --subject-type artifact \
      --subject-id "${{ github.repository }}@${{ github.sha }}" \
      --subject-digest "sha256:${{ env.ARTIFACT_SHA256 }}" \
      --output ./compiled_packet/

- name: Gate on packet admissibility
  run: bash scripts/assay-gate.sh ./compiled_packet/
  # Exit 0 = INTACT + admissible → proceed
  # Exit 1 = blocked → review assay packet verify --json output
```

The gate script captures verifier stdout (JSON) and stderr (diagnostics) in
separate streams. On failure it prints captured stderr so crash traces appear
in CI logs rather than a silent empty-output message.

**Naming note:** "Gate" in Stages 1–4 means `assay diff` regression thresholds
(cost/latency/errors). The packet gate in Stage 6 is `scripts/assay-gate.sh`
with different semantics: it enforces compiled packet admissibility, not
behavioral regression. Both are fail-closed; they gate on different questions.

See [docs/packets.md](packets.md) and
[docs/specs/COMPILED_PACKET_VERIFY_CONTRACT.md](specs/COMPILED_PACKET_VERIFY_CONTRACT.md).

---

## Terminology

- **Evidence pack**: the signed, verifiable bundle produced by `assay run`
- **Compiled packet**: a sealed, signed bundle of questionnaire claims and evidence —
  the reviewer-ready trust artifact a third party can verify offline
- **Diff gate**: `assay diff` regression thresholds on cost, latency, errors (Stages 1–4)
- **Packet gate**: `scripts/assay-gate.sh` — enforces compiled packet admissibility (Stage 6)
- **Lockfile**: a machine-readable contract that pins which claims are
  checked and how, preventing silent governance drift
- **Honest failure**: integrity PASS with claims FAIL -- genuine evidence
  proving the run did not meet standards

## Read next

- [Start Here](START_HERE.md) -- six steps from install to evidence in CI
- [Quickstart](README_quickstart.md) -- full command reference and Golden Path
- [Assay Verify Action](https://github.com/Haserjian/assay-verify-action) -- GitHub Action for PR-level verification
- [For Compliance Teams](for-compliance.md) -- what auditors see
- [Packet Systems](packets.md) -- compiled packet vs reviewer packet
