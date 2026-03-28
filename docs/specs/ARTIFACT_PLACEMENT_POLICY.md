# Artifact Placement Policy

Where milestones, roadmap items, receipts, and session residue should live.

## Rules

1. If a milestone changes subsystem confidence, proof coverage, or
   architecture-relevant friction, record it in an existing navigated
   repo artifact.
2. Prefer updating an existing artifact over creating a new one.
3. Track engineering next steps in-repo only if a real planning surface
   already exists.
4. If no suitable planning surface exists, keep actionable next steps
   outside repo until one does.
5. Keep narrative debriefs, rich conversational context, and temporary
   coordination notes outside repo.
6. Discard redundant or congratulatory summaries.

## Placement hierarchy

| Content class | Destination |
|---------------|-------------|
| Durable engineering state (proof coverage, friction findings, subsystem confidence) | Repo: existing navigated surface |
| Tracked engineering work | Repo: existing planning surface, if one exists |
| Narrative context, session guidance, debriefs | External: memory files, receipt artifacts |
| Redundant recap, congratulatory prose | Discard |

## Decision test

Before writing to the repo, answer these in order:

1. Did subsystem confidence, proof coverage, or architecture-relevant
   friction change? If no, do not write to repo.
2. Is there already a surface people navigate for this content? If yes,
   update it. If no, do not create a new one unless the content has no
   other durable home.
3. Is this planning work with an actual tracked planning destination?
   If yes, track there. If no, keep external.
4. Is this merely narrative residue? If yes, keep outside repo or discard.

## Classification guidance

- Do not classify something as out-of-repo because of its genre.
  Classify by whether a real tracked surface exists for it.
- "Checklists are ephemeral" is not a valid placement rule. Some
  checklists are engineering roadmaps. Route by content, not format.
- Engineering next steps without a tracked destination should be
  explicitly noted as "kept external, no planning surface exists" —
  not silently discarded.
