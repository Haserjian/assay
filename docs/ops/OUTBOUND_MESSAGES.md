# Outbound Messages

Internal. Not buyer-facing. Three versions of the same pitch.

Target buyer: eval owner at AI product company (5-50 person eng team,
running structured LLM-as-judge evals, shipping model improvements).

---

## Cold DM / email (4-6 sentences)

Subject: Your last eval improvement might be judge drift

We built a tool that checks whether two LLM-as-judge eval runs are
structurally comparable before anyone makes claims about the delta.

In a recent analysis, what looked like an 11.1% helpfulness improvement
turned out to be 4.7% real gain + 6.4% judge drift (the model version
and prompt had both changed between runs).

We're offering a free 30-minute comparability diagnostic: send us two
recent eval runs and we'll tell you whether the claimed comparison is
structurally valid. If it surfaces real drift risk, we can install the
evidence gate in 1-2 weeks.

Interested?

---

## Warm founder note (for people who know you or your work)

Hey — I've been building an open-source evidence layer for AI evals.
The core insight: most eval "improvements" are never checked for
instrument drift. The judge model quietly updates, someone tweaks the
prompt, and the delta reflects config change, not real progress.

We built a comparability engine that catches that mechanically. I'd
love to run a quick diagnostic on your last two eval runs — takes
30 minutes, free, you keep the results. If there's real risk, we
have a short pilot that installs the evidence gate in CI.

Worth a conversation?

---

## 30-second spoken pitch

"We help teams catch when an AI eval claim is invalid because the
measuring instrument drifted. You run two LLM-as-judge evaluations,
see a score improvement, and ship a blog post. But the judge model
version changed, the prompt changed, and the real improvement is half
what you thought. Assay catches that in seconds — it checks 15 parity
fields between the two runs and denies the comparison if the instrument
broke. We're doing free diagnostics right now: send us two eval runs,
we tell you if the comparison holds. If it doesn't, we install the
gate in a week or two."

---

## Discovery questions (for the diagnostic call)

1. How do you currently track which model/prompt/rubric was used for each eval run?
2. Have you ever had an eval result that looked great but turned out to be noise or config change?
3. When you ship an eval improvement claim, who reviews it? Is there a gate?
4. How many LLM-as-judge evaluations do you run per week/month?
5. Do you pin your judge model version, or does it auto-update?
6. What would happen if your next benchmark claim was wrong by 6%?

---

## Objections and answers

**"We already track our eval config."**
→ Great — then the diagnostic should take 10 minutes. We'll check whether
your last two runs pass the comparability contract. If they do, you're in
good shape and we'll tell you so.

**"We don't use LLM-as-judge evals."**
→ The comparability engine works with any structured evaluation where
conditions need to match. But judge-scored evals are where we see the
most drift. If that's not your pain, this might not be the right fit
right now.

**"What's the catch with the free diagnostic?"**
��� No catch. We run our open-source tool on your eval metadata. You
keep the results. If drift shows up, we can talk about installing
the evidence gate — that's the paid part. If nothing shows up, you've
confirmed your eval hygiene is good.

**"Why would I pay for this when I could just diff my configs?"**
→ Config diff tells you what changed. It doesn't tell you whether that
change invalidates the comparison, or what the consequences are. The
comparability contract encodes severity (invalidating vs degrading vs
informational), instrument continuity, and blocked actions. That's the
difference between "something changed" and "your claim is inadmissible."

**"We're not ready for a full pilot."**
→ Start with the diagnostic. It's 30 minutes. If it surfaces something
real, the pilot is a natural next step. If not, no pressure.
