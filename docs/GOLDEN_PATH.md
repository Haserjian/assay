# Golden Path

The 60-second first-contact conversion spec for Assay.

**Status:** Draft. This drives README top, `--help`, demo ordering, and landing page.

---

## The spec (one screen)

**Audience:** Engineering lead or security engineer shipping AI features.
60 seconds of patience.

**Promise (one sentence):**
Assay instruments supported AI workflows, records signed evidence during real runs, and can hand another team a reviewer-ready artifact they can verify offline.

**Command (one):**
```bash
pip install assay-ai && assay try
```

**Artifact:** A reviewer-ready evidence packet backed by a signed proof pack — manifest, Ed25519 signature, tamper challenge that breaks on modification. Real cryptography, not a screenshot.

**Feeling after 60 seconds:** "This actually works. I can see the
signature. I can see it break. I can imagine handing this to another
team. This is verifiable, not vibes."

**Next step (one fork):**
- "I need a packet another team can review" → reviewer packet flow
- "I ship AI features and need instrumentation" → `assay start`

**Boundary discipline:**
- First-contact story = evidence compiler for existing AI execution
- Episode/checkpoint APIs = advanced bridge capability, not first-contact copy

---

## First-contact admissibility test

After 60 seconds a stranger must be able to answer:

1. What is Assay for? → reviewer-ready AI evidence packets
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

### 3. Packet path is buried under generic instrumentation
The current front door proves tamper detection but does not quickly show the buyer-facing packet path. Fix: first contact proves the trust root, then explicitly forks to reviewer packet workflow or instrumentation.

### 4. README still risks blending the wedge with the bridge
Fix: Top lines must keep the primary public story boringly clear. Runtime membrane language stays visible only as advanced capability.

---

## Anti-goals

- No new command families for the golden path
- No getting-started wizard or interactive prompts
- No landing page before this spec is stable
- No new public nouns

## Vocabulary guardrail

- **Reviewer-ready evidence packet** is the outward-facing artifact name.
- **Proof pack** remains the nested trust root term.
- **VendorQ** is the workflow/compiler name.

Do not casually swap these in first-contact surfaces.

## Governing law

No first-touch surface may force the user to choose the product's ontology.
That choice belongs to the product, not the visitor.
