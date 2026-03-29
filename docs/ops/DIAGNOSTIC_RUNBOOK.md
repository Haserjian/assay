# Free Comparability Diagnostic — Operator Runbook

Internal. This is how you run the diagnostic when someone says yes.

---

## Required inputs from the buyer

Ask for:
1. Two eval run configs (any format: YAML, JSON, Python dict, Notion doc, Slack message)
   - Which model was used as judge
   - What version (exact, not just "gpt-4o")
   - The scoring prompt / system prompt
   - Rubric / scoring scale
   - Temperature, max tokens, top-p
   - Number of judge passes
   - Dataset name/version
   - Presentation order (fixed, shuffled, etc.)
   - Input format

2. The claimed delta (e.g., "+8% on helpfulness")

3. Permission to share the verdict (not the raw data) as a case reference

## What you do

### Step 1: Convert their config to evidence bundles (15 min)

Map their eval config into the evidence bundle format:

```json
{
  "label": "<their description>",
  "fields": {
    "judge_model": "...",
    "judge_model_version": "...",
    "judge_prompt_template": "...",
    ...all 15 fields
  }
}
```

Save as `baseline.json` and `candidate.json`.

If they can't provide a field, leave it out. The engine will
report it as missing (UNDETERMINED on that dimension).

### Step 2: Run the comparison (2 min)

```bash
assay compare baseline.json candidate.json \
  -c contracts/judge-comparability-v1.yaml \
  --claim "<their claimed delta>" \
  --metric <their metric name> \
  --delta <their delta value>
```

### Step 3: Capture the output

Save the terminal output. If they want JSON:

```bash
assay compare baseline.json candidate.json \
  -c contracts/judge-comparability-v1.yaml \
  --claim "..." --json
```

### Step 4: Interpret for them (10 min)

Walk through the verdict:

**If SATISFIED:** "Your comparison is structurally valid. All 15 parity
fields match. The claimed delta is admissible." This is good news.
Offer: "If you want this check on every PR, the pilot installs that."

**If DENIED:** "The comparison has [N] invalidating mismatches. The
claimed delta cannot be attributed to your system improvement because
[specific fields] changed. Recommendation: rerun the candidate eval
with pinned [field] config." This is the conversion moment.
Offer: "The pilot installs the contract and CI gate so this can't
happen again."

**If DOWNGRADED:** "The comparison has minor mismatches in [fields].
The claim is admissible with caveats. You should disclose [specific
changes] when reporting the delta." Offer: same as DENIED.

**If UNDETERMINED:** "We couldn't evaluate [N] required fields because
they weren't declared. This means the comparison cannot be confirmed
as valid. Recommendation: declare the missing fields and rerun."
Offer: "The pilot includes contract authoring for your eval regime."

### Step 5: Transition to pilot (5 min)

If the diagnostic found something real:

"We can install this as a permanent CI gate in 1-2 weeks. We author
a comparability contract specific to your eval regime, wire it into
your pipeline, and hand off the system. You own everything. Want to
scope that out?"

If the diagnostic was clean:

"Your eval hygiene is good. If you want to lock that in with
continuous verification, the pilot adds a CI gate and evidence trail.
But there's no urgency — your current setup is sound."

---

## What you hand back

1. The comparability verdict (screenshot or formatted text)
2. A one-paragraph summary: "Your [metric] comparison between [baseline] and [candidate] is [SATISFIED/DENIED/DOWNGRADED/UNDETERMINED] because [reason]."
3. If DENIED: specific remediation steps
4. Link to docs/outbound/START_HERE.md for self-serve follow-up

Do NOT hand back:
- Raw evidence bundles (contains their config)
- Internal contract YAML (they can find it publicly if interested)
- Pricing before they ask

---

## Time budget

| Step | Time |
|------|------|
| Receive and review their config | 5 min |
| Convert to evidence bundles | 15 min |
| Run comparison | 2 min |
| Interpret results | 10 min |
| Transition conversation | 5 min |
| **Total** | **~37 min** |

Advertise as "30 minutes" — the extra 7 is buffer for messy input.
