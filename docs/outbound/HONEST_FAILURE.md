# What "Honest Failure" Means

Most governance tools give you two outcomes: pass or fail.
Assay gives you four.

| Exit code | Meaning |
|-----------|---------|
| **0** | Evidence is authentic. Standards met. |
| **1** | Evidence is authentic. Standards violated. |
| **2** | Evidence has been tampered with. |
| **3** | Bad input (missing files, invalid arguments). |

Exit code 1 is the important one.

## Why exit 1 matters

When a system exits 1, it is saying: "I collected real evidence,
I signed it, I verified the signatures — and the evidence shows
that something failed. The failure is real and the evidence is intact."

That is a **proof of honest failure**. The system did not hide
the problem. It did not silently pass. It reported the violation
with authentic, tamper-evident evidence.

## Example

Your eval pipeline runs an LLM-as-judge comparison. The comparability
check finds that the judge model version changed between runs:

```
COMPARABILITY VERDICT: DENIED

  judge_model_version
    baseline: gpt-4o-2024-08-06
    candidate: gpt-4o-2024-11-20
    rule: exact
    Model version updates can silently shift scoring behavior.

  Claim status: INADMISSIBLE
  Blocked: promotion, leaderboard_entry, benchmark_claim
```

Exit code: 1. Not 0 (the comparison is not valid). Not 2 (nothing
was tampered). The evidence is authentic, the denial is real, and
the claim is blocked.

## Why this matters commercially

A system that always passes is not trustworthy — it is untested.

A system that can prove it caught a problem is more credible than
one that never reports problems. When your compliance team or
auditor asks "how do you know this works?", exit 1 is the answer:
the system denied an invalid claim, and here is the signed evidence.

Honest failure is not a bug. It is the proof that the governance
layer is working.

## Where you see it

- `assay verify-pack` returns exit 1 when evidence is authentic but claims fail
- `assay compare` returns exit 1 when the comparison is DENIED or DOWNGRADED
- `assay gate compare` returns exit 1 when the gate blocks an inadmissible claim
- The [proof gallery](https://github.com/Haserjian/assay-proof-gallery) scenario 02 (insurance honest-fail) demonstrates this with a real signed proof pack
- The [browser verifier](https://haserjian.github.io/assay-proof-gallery/verify.html) shows honest-fail verdicts client-side
