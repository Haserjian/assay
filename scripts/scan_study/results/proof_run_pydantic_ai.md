# Proof Run: pydantic-ai

*2026-02-19 | assay-ai v1.6.0*

End-to-end Assay pipeline run on [pydantic/pydantic-ai](https://github.com/pydantic/pydantic-ai)
at commit `8f74af04`.

## Step 1: Scan

```
$ assay scan .

  Found 5 LLM call sites:

  HIGH   pydantic_ai_slim/pydantic_ai/models/anthropic.py:431
         self.client.beta.messages.create              NO RECEIPT
  HIGH   pydantic_ai_slim/pydantic_ai/models/groq.py:290
         self.client.chat.completions.create           NO RECEIPT
  HIGH   pydantic_ai_slim/pydantic_ai/models/huggingface.py:239
         self.client.chat.completions.create           NO RECEIPT
  HIGH   pydantic_ai_slim/pydantic_ai/models/openai.py:706
         self.client.chat.completions.create           NO RECEIPT
  HIGH   pydantic_ai_slim/pydantic_ai/models/openai.py:1650
         self.client.responses.create                  NO RECEIPT

  0 of 5 call sites instrumented. 5 uninstrumented (5 high, 0 medium, 0 low)
```

5 high-confidence SDK call sites across 4 provider modules. Zero tamper-evident
evidence emission.

## Step 2: Patch

```
$ assay patch . --yes

  Scanning... found 5 uninstrumented call sites
  Detected frameworks: anthropic, openai
  Entrypoint: pydantic_ai_slim/pydantic_ai/models/openai.py

  Patched pydantic_ai_slim/pydantic_ai/models/openai.py with 2 integration line(s).
```

Two lines added to the entrypoint:

```python
from assay.integrations.anthropic import patch as patch_anthropic; patch_anthropic()  # assay:patched
from assay.integrations.openai import patch as patch_openai; patch_openai()  # assay:patched
```

## Step 3: Run

We emit 3 synthetic receipts matching the pattern a typical `agent.run()` with
tool use would produce (we don't have API keys for the real providers):

```
$ assay run -c receipt_completeness -- python3 simulate_run.py

  assay run: trace=trace_20260219T174534_2f27ba55
  assay run: executing: python3 simulate_run.py
  Emitted 3 receipts (simulating pydantic-ai agent.run() with tool use)
  assay run: command exited with code 0

  Proof Pack Built
  Pack ID:    pack_20260219T174534_abbdde96
  Signer:     assay-local
  Integrity:  PASS
  Claims:     PASS
  Receipts:   3
```

## Step 4: Verify

```
$ assay verify-pack proof_pack_trace_20260219T174534_2f27ba55/

  VERIFICATION PASSED
  Pack ID:    pack_20260219T174534_abbdde96
  Integrity:  PASS
  Claims:     PASS
  Receipts:   3
  Head Hash:  4d1d03e431381e713369f22e0324caa90d86ec1dc6486f0c920698238a74bf1a
  Errors:     0
  Warnings:   0
```

Exit code 0: integrity verified (hashes match, Ed25519 signature valid) and
all declared claims passed.

## Step 5: Explain

```
$ assay explain proof_pack_trace_20260219T174534_2f27ba55/

  Proof Pack: pack_20260219T174534_abbdde96

  WHAT HAPPENED
    3 receipts recorded: 3 model_call
    Providers: openai
    Signed by: assay-local

  INTEGRITY CHECK
    PASSED
    All file hashes match. The Ed25519 signature is valid.
    This evidence has not been tampered with since creation.

  CLAIM CHECKS
    PASSED
    [PASS] min_receipt_count: >= 1 receipts
    [PASS] model_call_present: at least 1 receipt of type 'model_call'

  WHAT THIS PROVES
    The recorded evidence is authentic (signed, hash-verified).
    The declared behavioral checks all passed.

  WHAT THIS DOES NOT PROVE
    - That every action was recorded (only recorded actions are in the pack)
    - That model outputs are correct or safe
    - That receipts were honestly created (tamper-evidence, not source attestation)
    - That timestamps are externally anchored (local clock was used)
    - That the signer key was not compromised
```

## Pack manifest (cryptographic details)

```json
{
  "pack_id": "pack_20260219T174534_abbdde96",
  "hash_alg": "sha256",
  "signer_id": "assay-local",
  "signer_pubkey": "PGCH5mONigaWDdJM2jxHSD3Id65/zDjPFsWcUv8ELho=",
  "signer_pubkey_sha256": "5910f35f991d2137ebe818df0c2af65f4722a13d3e7279efa4613a768fcb8cbe",
  "signature_alg": "ed25519",
  "signature_scope": "JCS(pack_manifest_without_signature)",
  "receipt_integrity": "PASS",
  "claim_check": "PASS",
  "n_receipts": 3,
  "head_hash": "4d1d03e431381e713369f22e0324caa90d86ec1dc6486f0c920698238a74bf1a",
  "files": [
    {"path": "receipt_pack.jsonl", "sha256": "24292a24..."},
    {"path": "verify_report.json", "sha256": "88a646d7..."},
    {"path": "verify_transcript.md", "sha256": "ce9f5108..."}
  ]
}
```

## What this demonstrates

1. **Real gap**: pydantic-ai has 5 LLM SDK call sites with zero tamper-evident evidence.
2. **Two-line fix**: `assay patch .` auto-detects frameworks and inserts integration code.
3. **Portable evidence**: The pack is a self-contained directory. Copy it to any machine,
   run `assay verify-pack`, get the same result.
4. **Honest boundaries**: The explain output explicitly states what the pack does NOT prove.

## Reproduce

```bash
pip install assay-ai
git clone https://github.com/pydantic/pydantic-ai.git
cd pydantic-ai
git checkout 8f74af04
assay scan .
```
