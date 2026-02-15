# Assay for Compliance Teams

When someone asks "show me evidence of what your AI system did," Assay
produces a portable, independently verifiable evidence bundle. No server
access required.

## What Assay Produces

A **evidence pack** is a self-contained evidence bundle for a single AI system run.
Five files. One Ed25519 signature. Independently verifiable.

| File | What it contains |
|------|-----------------|
| `receipt_pack.jsonl` | Structured evidence records (one per LLM call or governance event) |
| `pack_manifest.json` | SHA-256 hashes of every file in the pack |
| `pack_signature.sig` | Ed25519 signature over the manifest |
| `verify_report.json` | Machine-readable verification results |
| `verify_transcript.md` | Human-readable verification narrative |

## What Receipts Record

Each receipt captures metadata about one event (e.g., an LLM API call).

**Included by default:** model name, provider, timestamp, prompt hash,
response hash, token counts, call site identifier.

**Not included by default:** prompt text, response text, API keys, PII.
Full content capture is opt-in and off by default.

## What Verification Checks

Running `assay verify-pack ./proof_pack_*/` answers two questions:

1. **Integrity**: Were these files tampered with after creation?
   Ed25519 signature verification, SHA-256 manifest hashes, file completeness.

2. **Claims**: Does this evidence satisfy the declared governance checks?
   Receipt types, counts, field values, coverage against a contract.

| Result | Exit Code | Meaning |
|--------|-----------|---------|
| Integrity PASS, Claims PASS | 0 | Evidence is authentic, behavior meets declared standards |
| Integrity PASS, Claims FAIL | 1 | Evidence is authentic but standards were violated (honest failure) |
| Integrity FAIL | 2 | Evidence has been tampered with |
| Bad input | 3 | Invalid arguments or missing files |

Exit code 1 (honest failure) is not a bug. It means the evidence is real
and it shows something went wrong. Systems that can prove they failed
honestly are more trustworthy than systems that always claim to pass.

## What an Auditor Review Looks Like

1. Receive a evidence pack directory from the engineering team
2. Install Assay: `pip install assay-ai`
3. Verify independently: `assay verify-pack ./proof_pack_*/`
4. Read the summary: `assay explain ./proof_pack_*/`

The `explain` command produces a plain-English summary covering:

- What happened (receipts, models, timestamps, token counts)
- Integrity status (signature and hash verification)
- Claim results (each governance check, pass or fail)
- What the pack proves
- What the pack does NOT prove

No access to the original server, database, or API keys required.

## What Assay Proves and Does Not Prove

**Proves:**

- Evidence files have not been modified since signing
- All declared call sites emitted receipts (if a completeness contract is used)
- Declared governance checks passed or failed against authentic evidence

**Does not prove:**

- That receipts accurately represent what happened at runtime
- That every action was captured (only contracted call sites are checked)
- That timestamps correspond to real-world time (local clock is used)
- That the signing key was not compromised

For stronger guarantees, Assay supports:

- **Transparency logs** -- external append-only timestamp anchor ([assay-ledger](https://github.com/Haserjian/assay-ledger))
- **CI-held org keys** -- separates the signing key from the developer
- **External timestamping** (RFC 3161) -- third-party proof of "before this date"

## Framework Alignment

Assay evidence packs may support evidence requirements in:

- **SOC 2 (CC7.2)** -- monitoring and detection of anomalies in system operations
- **ISO 42001** -- AI management system documentation and evidence requirements
- **EU AI Act (Articles 12 & 19)** -- tamper-resistant logging for high-risk AI systems (obligations effective August 2, 2026)
- **NIST AI RMF** -- governance, accountability, and documentation practices

Assay is one building block for these requirements.
It does not constitute full compliance on its own.
See [compliance-citations.md](compliance-citations.md) for exact regulatory references.

## CI Integration

Evidence packs can be generated and verified automatically in CI:

```bash
# 1) Generate pack during test run
assay run -c receipt_completeness -- python test_app.py

# 2) Verify integrity + claims against locked policy
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass

# 3) Enforce operational gates (cost/error regression thresholds)
assay diff ./baseline_pack/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0 --gate-strict
```

Exit code 0 = merge allowed.
Exit code 1 = claims/gates failed (honest failure or regression).
Exit code 2 = tampering/lock drift.
Exit code 3 = bad input.

Run `assay ci init github` to generate a GitHub Actions workflow that
does this automatically on every pull request.

## Engineering Handoff Checklist

If engineering reports "no receipts emitted," use this runbook:

```bash
assay scan .
assay scan . --report
assay run -- python app.py
assay doctor
```

This distinguishes "no supported call sites," "not instrumented," and
"run command wiring issue" (`--` separator).
