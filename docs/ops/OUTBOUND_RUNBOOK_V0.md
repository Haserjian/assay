# Outbound Runbook v0

One-screen operator note. Not a doc. Freeze of the first-contact package.

---

## Lead artifact: Comparability demo

```bash
cd ~/assay-toolkit
bash examples/llm_judge/run_demo.sh --non-interactive
```

Shows: +11.1% apparent gain → DENIED (model + prompt drift) → rerun → SATISFIED at +4.7%.

The 6.4% difference was judge drift, not system improvement.

## Support artifact: Gallery reviewer/compliance packets

```
https://github.com/Haserjian/assay-proof-gallery/tree/main/gallery/05-reviewer-packet-gaps
https://github.com/Haserjian/assay-proof-gallery/tree/main/gallery/06-naic-aiset-mapping
```

05: buyer-facing reviewer packet with gaps (VERIFIED_WITH_GAPS settlement)
06: NAIC AISET compliance mapping (14 questions across 4 categories)

Both under automated contract — CI rebuilds and verifies.

## Bootstrap trial

**Repo:** `~/agent-template`
**Command:**
```bash
cd ~/agent-template
assay trust bootstrap --profile reviewer
```

**Pass criteria:**
1. Workflow installs and runs without YAML or version breakage
2. Generated trust policy loads without `load_errors`
3. Reviewer profile produces warning posture (not hard failure)
4. PR UI makes the result legible to a non-Assay operator
5. Remediation path is obvious from the output (register signer)

**Fail criteria:**
- Any `load_errors` in trust evaluation
- Workflow syntax error or action resolution failure
- PR comment is empty, garbled, or absent
- User cannot determine next step from the output

**Command to open trial:**
```bash
cd ~/agent-template
assay trust bootstrap --profile reviewer
git checkout -b trial/trust-bootstrap
git add trust/ .github/workflows/assay-verify.yml
git commit -m "ci: trial trust bootstrap (reviewer profile)"
git push -u origin trial/trust-bootstrap
gh pr create --title "Trial: trust bootstrap reviewer profile" --body "Bootstrap trial. Expect trust evaluation with unrecognized signer warning."
```

**Trial result (2026-03-28, Haserjian/agent-template#1):**
- Bootstrap command: succeeded (4 files generated)
- Workflow install: succeeded (SHA resolved, assay-ai installed)
- Workflow execution: failed — no proof_pack_*/ directories (require-pack: true)
- Trust evaluation: not reached (action exits before trust eval when no packs)
- PR annotation: ::warning:: emitted correctly
- PR comment: not produced (action didn't reach comment step)
- Conclusion: bootstrap is mechanically correct. Empty repos need
  proof packs before trust evaluation fires. Guidance added to
  bootstrap output and emitted README.

## What this is not

- Not a product launch
- Not a broad validation campaign
- Not a reason to open twelve more repos

One demo. One gallery link. One bootstrap trial. Then learn from contact.
