# Assay Product Roadmap & Strategic Analysis

*2026-02-08 | Pre-launch synthesis*

## The Core Problem

Assay has strong cryptographic bones and a weak activation journey. The trust engine works. The user experience feels like a toolbox, not a guided path. Every stage of the user journey has a conversion gap:

```
HN post -> pip install -> assay scan -> ??? -> assay run -> proof pack -> ??? -> paid pilot
```

The two `???` are where everyone leaves.

---

## 1. Activation Gaps (P0 -- fix before or immediately after launch)

### 1.1 Scan-to-fix dead end

**Problem:** `assay scan` shows findings with a generic quick-fix snippet. User doesn't know which integration to use, where to put the patch, or what to do next. If scan finds nothing, it's a complete dead end.

**Fix:** Scan output must end with a tailored, copy-pasteable sequence:

```
Found 12 OpenAI call sites in 4 files. 0 instrumented.

Next steps for this project:

  1. Add to your entrypoint (e.g., main.py):
     from assay.integrations.openai import patch; patch()

  2. Generate your first proof pack:
     assay run -c receipt_completeness -- python main.py

  3. Verify it:
     assay verify-pack ./proof_pack_*/

  4. Lock your audit posture:
     assay lock write
```

The scan already knows which SDK is in use (OpenAI vs Anthropic vs LangChain). Use that to tailor the patch instruction.

When scan finds zero call sites:
```
No recognized LLM SDK calls detected.

If you use a custom wrapper, you can emit receipts directly:
  from assay.store import emit_receipt
  emit_receipt("model_call", {"prompt_hash": ..., "response_hash": ...})

Or run with runtime patching anyway:
  assay run -- python your_app.py
```

**Effort:** ~2 hours. Modify scan output in `commands.py`.

### 1.2 Proof pack comprehension gap

**Problem:** A stranger opens `proof_pack_<hash>/` and sees five files with technical names. Even `verify_transcript.md` assumes familiarity. Non-engineers can't extract value from the artifact.

**Fix:** Build `assay explain ./proof_pack_*/`

```
$ assay explain ./proof_pack_abc123/

This proof pack contains evidence from a run on 2026-02-10.

What happened:
  5 LLM calls were recorded (4 model_call, 1 guardian_verdict)
  All calls went through the OpenAI provider (gpt-4)

Integrity: PASSED
  All file hashes match. The Ed25519 signature is valid.
  This evidence has not been tampered with since creation.

Claims: PASSED
  receipt_completeness: at least one model call recorded
  guardian_enforcement: a guardian verdict was issued

What this proves:
  The recorded evidence is authentic and satisfies the declared checks.

What this does NOT prove:
  - That every action was recorded (only recorded actions are in the pack)
  - That the model outputs are correct or safe
  - That the signer key wasn't compromised
  - That timestamps are externally anchored

To verify independently: assay verify-pack ./proof_pack_abc123/
```

This is the artifact Sarah pastes into a vendor security questionnaire. It's the document Marcus forwards to his auditor. Without it, proof packs only speak to engineers.

**Effort:** ~2-3 hours. New command in `commands.py`, reads `verify_report.json` + `receipt_pack.jsonl`.

### 1.3 No transformation story

**Problem:** The scan study shows the gap. The CLI shows the tool. Nobody shows the before-and-after. There's no "caught a lie" moment.

**Fix:** Build `assay demo-incident`

- Act 1: Agent configured for gpt-4 + guardian check. Run. Pack produced. PASS/PASS.
- Act 2: Model swapped to gpt-3.5-turbo, guardian removed. Run again. Integrity PASS, Claims FAIL. Receipts show the model swap.
- Act 3: `assay explain` on both packs shows exactly what changed.

This is the "holy shit" demo. It's concrete, visceral, and it works for engineers and executives alike. Also the basis for the asciinema recording.

**Effort:** ~3 hours. New demo command using echo backend (no API key needed).

---

## 2. Onboarding & CI (P1 -- week after launch)

### 2.1 `assay onboard`

Interactive command that chains: doctor -> scan -> recommend patch -> run -> verify.

```
$ assay onboard

Step 1: Checking environment... OK (keystore ready)
Step 2: Scanning project...
  Found 8 OpenAI call sites in 3 files.
Step 3: Framework detected: OpenAI SDK
  Recommended patch location: src/main.py
Step 4: Apply patch? [Y/n]
Step 5: Running first proof pack...
Step 6: Verifying... Integrity PASS, Claims PASS

Your first proof pack is in ./proof_pack_*/
Next: run `assay ci init github` to enforce in CI.
```

**Effort:** ~3 hours. Orchestrates existing commands with interactive prompts.

### 2.2 `assay ci init github`

Generates `.github/workflows/assay-verify.yml` with:
- Step to run app under `assay run`
- Step to verify pack
- Step to upload artifact
- Uses `Haserjian/assay-verify-action@v1`

Asks one question: "What's your run command?" (default: `assay run -- python -m pytest`)

**Effort:** ~1-2 hours. Template generation.

### 2.3 `assay scan --patch --dry-run`

Shows a unified diff of exactly what would be added and where. Does NOT auto-apply unless `--apply` is passed. Safe edits only: insert `patch()` in detected entrypoints.

Entrypoint detection heuristics:
- `if __name__ == "__main__":`
- `uvicorn.run`, `app = FastAPI()`, `Flask(__name__)`
- `pyproject.toml` console scripts
- If ambiguous: "Found 3 candidates, pick one with `--entrypoint path`"

**Effort:** ~3-4 hours. New `patcher.py` module + entrypoint detection.

---

## 3. Self-Selling Artifacts (P1)

### 3.1 Challenge Pack

A zip with two proof packs -- one valid, one tampered (one byte flipped in `receipt_pack.jsonl`).

```bash
assay verify-pack ./challenge_good/    # exit 0
assay verify-pack ./challenge_bad/     # exit 2
```

Works on anyone, even if they have no LLM calls. Conference demo, hiring question, tweet, blog post. The visceral "your machine decides" moment.

**Effort:** ~1-2 hours. Script to generate + a small repo (`assay-challenge-pack`).

### 3.2 Asciinema recording

30-60 second terminal recording of the full journey: scan -> patch -> run -> verify. Pin to README. Link from HN post.

**Effort:** 30 min.

### 3.3 "Assay Verified" badge

For repos that pass `assay scan --ci` and/or `assay verify-pack` in CI. Defer until there's adoption signal.

---

## 4. Persona Communication

### Who encounters Assay and what they need

| Persona | What they need | Current gap |
|---------|---------------|-------------|
| Engineer (HN drive-by) | 60-second scan -> fix -> verify path | Scan dead-ends, no guided fix |
| Engineer (serious eval) | Integration docs, streaming support, perf numbers | Sparse docs, unknown overhead |
| Security lead | Chain-of-custody summary, trust boundary clarity | No explain command, no security view |
| Compliance/auditor | Plain-English proof pack summary, what's proven vs not | Pack files are opaque to non-engineers |
| VP/exec | Risk reduction story, pilot scope, reference customer | No landing page, no case study, no demo video |
| Framework maintainer | Non-adversarial framing, integration PR | Scan study positions them as "having a gap" |

### README fix (immediate)

Top of README should open with 3 non-technical sentences:

```
Assay produces tamper-evident audit trails for AI systems.
When someone asks "prove what your AI did," Assay gives you a signed
evidence bundle they can verify independently -- no access to your
systems required.
```

Then the exit code contract. Then the install command. Technical details below the fold.

---

## 5. Engineering Risks to Address

### 5.1 Monkey-patch fragility

The `patch()` integrations wrap SDK internals. When OpenAI/Anthropic ship breaking changes, patches break. Need:
- Version detection in each integration
- CI matrix test that installs latest SDK versions and runs a minimal patched call
- Graceful degradation (warn, don't crash) if patch target doesn't exist

### 5.2 Receipt storage in production

`~/.loom/assay/<date>/<trace>.jsonl` doesn't work in containers (ephemeral fs), serverless (no persistent disk), or distributed systems (receipts on different machines).

Design (not build yet): pluggable receipt sink via `ASSAY_RECEIPT_SINK=`:
- `file` (default, current behavior)
- `stdout` (container-friendly, JSONL to stdout)
- `http` (POST to collector endpoint)
- `s3` (later)

Even documenting this answers the "what about Kubernetes?" question.

### 5.3 Streaming support

Most production OpenAI calls use `stream=True`. Questions to answer:
- Does the patch handle streaming responses?
- Is the response hash computed on fully accumulated content?
- Does the receipt include `streaming: true` metadata?

If not supported yet: detect streaming and emit a receipt with a clear limitation note.

### 5.4 Performance overhead

Run one microbenchmark and publish the number. "Receipt emission adds X ms and Y KB per call on average." Even rough numbers beat "unknown."

### 5.5 Custom wrapper detection

Many codebases wrap LLM calls: `def call_llm(prompt): return client.chat.completions.create(...)`. Scanner catches the wrapper definition (LOW) but doesn't trace call graphs. A repo with 1 wrapper and 50 callers shows as 1 finding. Known limitation, but worth stating proactively.

---

## 6. Semantic Clarity

### The four-layer trust model (make explicit everywhere)

| Layer | Question it answers | Exit behavior |
|-------|-------------------|---------------|
| Integrity | Was evidence tampered after creation? | FAIL = exit 2 |
| Claims | Did this run satisfy declared behavior checks? | FAIL = exit 1 |
| Lockfile | Were verification semantics pinned and unchanged? | FAIL = exit 2 |
| Witness | Who besides me attested this? At what strength? | Informational |

Most user confusion comes from collapsing these into one "verified" bucket. Every report/explain output should split them.

### What Assay does NOT prove (repeat everywhere)

- That every action was recorded (only recorded actions are verifiable)
- That the model output is correct or safe
- That receipts were honestly created (tamper-evidence != source attestation)
- That timestamps are externally anchored
- That the signer key wasn't compromised

### "Honest failure" is the stickiest idea

"Integrity PASS + Claims FAIL = honest failure report, not a cover-up."

This should be in the first 3 sentences of every piece of content. It's counterintuitive, memorable, and differentiating.

---

## 7. Revenue Strategy

### The ladder

| Layer | What | Price | When |
|-------|------|-------|------|
| Free CLI | scan, run, verify, doctor, demo-pack | $0 | Now |
| Pilot sprint | Instrument codebase, deliver working proof pack pipeline in CI | $5-15k | Now (post launch) |
| Retainer | Keep lockfile current, instrument new call sites, respond to drift | $2-5k/mo | After first sprint |
| Cloud | Hosted verification, team dashboards, audit exports | Per-seat/pack | Only if 5+ customers ask |

### Pilot CTA (use this text)

"I'm taking 3 integration pilots this month. Fixed scope, 1 week: I instrument your LLM pipeline, wire CI verification, and deliver a working proof pack flow. You keep everything. [email/DM]."

Framing is collaborative ("I learn where the tool breaks") not commercial.

### Conversion path

1. Stranger runs `assay scan`, sees gap
2. Stranger produces first proof pack via `assay run`
3. Stranger asks "how do I do this for my whole codebase?" or "how do I explain this to my auditor?"
4. That question is the pilot conversation
5. Sprint delivers: every call site instrumented, lockfile in CI, proof packs on every merge
6. Lockfile creates switching cost -> retainer

---

## 8. What NOT to Build

- **General CI init** (too many CI systems) -- just GitHub Actions for now
- **Auto-apply patches** without diff preview -- liability
- **Badge generator** before adoption signal exists
- **Persona-specific doc pages** before knowing what each persona actually needs
- **Usage telemetry** -- undermines trust message
- **Monthly content calendar** -- run the scan again when you have something to say
- **Cloud/SaaS** -- only after 5+ paying customers asking for it

---

## 9. Priority Order

### Before Tuesday (4 hours)

1. Better scan output with framework-specific next steps (~1.5 hr)
2. Asciinema recording of scan + demo-pack (~30 min)
3. 3 non-technical sentences at top of README (~15 min)
4. Pilot CTA visible in HN post (~15 min)
5. "Honest failure" in opening of every post (~15 min)

### Week 1 after launch (based on signal)

6. `assay explain` command (~2-3 hr)
7. `assay demo-incident` -- model-swap story (~3 hr)
8. Challenge Pack (~1-2 hr)

### Week 2 (based on signal)

9. `assay onboard` -- interactive wizard (~3 hr)
10. `assay scan --patch --dry-run` (~3-4 hr)
11. `assay ci init github` (~1-2 hr)

### Week 3-4 (only if users ask)

12. Persona explain views
13. SDK compatibility CI matrix
14. Receipt sink abstraction
15. Coverage score + badge

---

## 10. Success Measurement

### 7-day gates after posting

- 3+ external repos run `assay scan`
- 1+ team asks for integration help
- 1+ pilot call booked

### Signal channels (no telemetry needed)

- GitHub issues and stars
- PyPI download stats (pypistats.org/packages/assay-ai)
- HN/Reddit/Discord comments and DMs
- Direct emails/DMs from pilot CTA

### Decision rules

- Got usage + pilot demand -> keep pushing distribution + paid pilots
- Got debate but no usage -> change headline/channel, not architecture
- No signal after two cycles -> tighten onboarding path, reposition message

---

## 11. Future Innovations (park until signal)

These are real product ideas but premature to build. Record them, don't act on them yet.

- **Proof Pack Diff** (`assay diff-pack A/ B/`): delta transcript showing what changed between runs
- **Evidence freshness**: explicit staleness language in verify output
- **Quorum witness**: ledger entry trusted only after 2+ independent witnesses
- **Signed claim receipts**: bind claim verdicts to pack root + policy hash
- **Coverage score**: single scalar for management (`assay score .`)
- **Receipt sink pluggability**: file/stdout/http/s3
- **Non-claims as structured data**: `non_claims` field in verify_report.json
- **External verifier test kit**: corpus fixtures + expected outputs for third-party verifier implementations
