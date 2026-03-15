# Golden Path

The 60-second first-contact conversion spec for Assay.

**Status:** Draft. This drives README top, `--help`, demo ordering, and landing page.

---

## The spec (one screen)

**Audience:** Engineering lead or security engineer shipping AI features.
60 seconds of patience.

**Promise (one sentence):**
Assay compiles signed evidence for AI systems that a third party can verify offline.

**Command (one):**
```bash
pip install assay-ai && assay try
```

**Artifact:** A signed proof pack — manifest, Ed25519 signature, tamper
challenge that breaks on modification. Real cryptography, not a screenshot.

**Feeling after 60 seconds:** "This actually works. I can see the
signature. I can see it break. This is verifiable, not vibes."

**Next step (one fork):**
- "I ship AI features and need audit trails" → `assay start`
- "I want the governance lifecycle" → `assay passport demo`

---

## First-contact admissibility test

After 60 seconds a stranger must be able to answer:

1. What is Assay for? → signed AI evidence
2. Why does the artifact matter? → third-party offline verification
3. Why should I believe it? → I just saw tamper detection work
4. What do I do next? → one clear path

If any answer is missing, the first-contact surface is not admissible.

---

## What this must fix

### 1. Six competing entry points
`quickstart`, `try`, `start`, `onboard`, `demo-pack`, `demo-challenge`
all claim to be first. Fix: `assay try` is THE entry. Others are
discoverable later. Not deletion — demotion.

### 2. 46+ top-level commands in `--help`
Fix: Show 5-7 primary commands. Rest behind `assay commands` or grouped.
Preserve capability, withdraw first-contact authority.

### 3. Passport demo opens with Grade D
Teaches "Assay judges" before "Assay compiles evidence." Fix: Passport
is the second step. First contact = proof pack + tamper challenge.

### 4. README is reference, not runway
Fix: Top 20 lines mirror this spec. Sentence → command → artifact →
why → next step.

---

## Anti-goals

- No new command families for the golden path
- No getting-started wizard or interactive prompts
- No landing page before this spec is stable
- No new public nouns

## Governing law

No first-touch surface may force the user to choose the product's ontology.
That choice belongs to the product, not the visitor.
