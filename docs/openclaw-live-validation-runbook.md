# OpenClaw Live Validation Runbook

**Status:** internal operator runbook
**Date:** 2026-04-09
**Purpose:** produce the first real exported OpenClaw session log locally, then run Assay's live-fit harness against it

---

## Goal

Clear the current live-validation blocker honestly.

Today the blocker on this machine is environmental, not importer logic:

- `~/.openclaw` exists
- the current harness reports `blocked`
- the default home has no real `agents/*/sessions/*.jsonl` logs yet

This runbook creates one real OpenClaw session in an isolated profile and then
re-runs Assay's exported-log validation harness against that profile.

---

## Why Use An Isolated Profile

Do not use the default `~/.openclaw` state for the first live-validation turn.

Use a named profile so the experiment is reproducible and does not pollute your
normal OpenClaw runtime state:

```bash
export OPENCLAW_PROFILE=assay-live-validation
export OPENCLAW_HOME="$HOME/.openclaw-$OPENCLAW_PROFILE"
```

All commands below assume that profile.

---

## Preconditions

You need all of the following before the real turn can succeed:

1. `openclaw` is installed and on `PATH`
2. a model provider API key is present in the current shell for the provider you plan to use with `openclaw agent --local`
3. the Assay repo virtualenv exists at `/Users/timmybhaserjian/assay/.venv`

Examples of provider keys, depending on your OpenClaw model/provider setup:

- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`

If the local agent turn fails before tool use starts, treat that as a model/auth
configuration blocker, not an Assay importer failure.

Observed on this machine during the first real-turn attempt:

- the isolated profile defaulted to model `claude-opus-4-5`
- the local turn failed with `No API key found for provider "anthropic"`
- no `auth-profiles.json` existed under the isolated agent state

That is a valid stop point. Do not change Assay importer code in response.

---

## Fastest Path

### 1. Initialize the isolated profile

```bash
openclaw --profile "$OPENCLAW_PROFILE" onboard \
  --non-interactive \
  --accept-risk \
  --mode local \
  --auth-choice skip \
  --workspace "$OPENCLAW_HOME/workspace"
```

Why this exact path:

- the installed CLI currently requires risk acknowledgement for non-interactive setup
- `onboard` is the working non-interactive bootstrap path here
- `--auth-choice skip` lets you create the isolated profile before you spend time on model-provider auth

This should create profile-local config and workspace state under `$OPENCLAW_HOME`.

Filesystem check:

```bash
ls -la "$OPENCLAW_HOME"
```

Do not trust `openclaw status --all` alone as proof that the profile home exists.
The CLI can render the derived config path for a profile even before the backing
files are actually on disk.

### 2. Confirm the profile state

```bash
openclaw --profile "$OPENCLAW_PROFILE" status --all
```

You want to confirm three things:

- the config path resolves under `$OPENCLAW_HOME`
- the profile has an agent, typically `main`
- no sessions exist yet, so the first real turn will be easy to detect

### 3. Run one real local agent turn

Use the embedded local agent path. This is the smallest route to a real session
log because it avoids channel pairing and Gateway delivery.

```bash
openclaw --profile "$OPENCLAW_PROFILE" agent \
  --local \
  --agent main \
  --session-id assay-live-validation-001 \
  --message "Use exactly these tools in order: (1) web_search for 'Python asyncio docs', (2) web_fetch https://docs.python.org/3/library/asyncio.html, (3) browser https://github.com/anthropics/claude-code. Then reply with a three-line summary naming the tool used and the target query or URL for each step." \
  --json
```

Why this prompt:

- it asks for one `web_search` row
- it asks for one `web_fetch` row
- it asks for one `browser` row
- it uses safe public targets
- it produces a known `session_id`

If your isolated profile has no provider auth yet, expect this command to fail
before tool execution with a model/auth error. That still narrows the blocker
honestly.

### 4. Confirm the session exists

```bash
openclaw --profile "$OPENCLAW_PROFILE" sessions --json
find "$OPENCLAW_HOME/agents" -path '*/sessions/*.jsonl' -type f | sort
```

Expected result:

- at least one JSONL path appears under `$OPENCLAW_HOME/agents/*/sessions/`
- ideally one of them is `assay-live-validation-001.jsonl`

Important nuance from the real attempt on this machine:

- OpenClaw may write `sessions.json` metadata for the attempted session even if
  the turn fails before tool execution
- that metadata alone is not the evidence target
- the milestone only advances when a real `*.jsonl` session log exists

### 5. Re-run Assay's live-fit harness against the isolated profile

```bash
cd /Users/timmybhaserjian/assay
/Users/timmybhaserjian/assay/.venv/bin/python \
  scripts/validate_openclaw_session_logs.py \
  --openclaw-home "$OPENCLAW_HOME" \
  --json
```

Expected result:

- `status: "ok"`
- `log_count >= 1`
- imported tool counts visible for the observed real session logs
- `partial` is acceptable at this stage if skipped reasons are explicit

---

## Stop Conditions

Stop and record the blocker if any of these happen.

### A. `openclaw setup` fails

Use `onboard`, not `setup`, for the non-interactive path documented here.

If `onboard --non-interactive --accept-risk` fails, this is a runtime/bootstrap
problem. Do not change Assay importer code.

Capture:

- the full command
- stderr
- `openclaw --profile "$OPENCLAW_PROFILE" status --all`

### B. `openclaw agent --local` fails before tool execution

This is usually missing model provider auth or model configuration.

Treat as:

- local model/auth blocker
- not evidence that the Assay importer is wrong

Observed concrete failure on this machine:

```text
No API key found for provider "anthropic"
```

The CLI referenced an auth store under the isolated agent state. If that file
does not exist yet, configure auth for the isolated profile before retrying the
real turn.

### C. the agent turn succeeds but no JSONL session log appears

This is the most important runtime-storage failure mode.

Capture:

```bash
openclaw --profile "$OPENCLAW_PROFILE" sessions --json
openclaw --profile "$OPENCLAW_PROFILE" status --all
```

If the CLI reports a session but `$OPENCLAW_HOME/agents/*/sessions/*.jsonl` is
still empty, hold the milestone and treat it as an OpenClaw session persistence
or profile-path issue.

Do not confuse this with the auth blocker above. If stderr shows a provider-auth
failure and only `sessions.json` metadata exists, the missing JSONL is a
consequence of pre-tool failure, not proof of a persistence bug.

### D. the Assay harness returns `ok` but the import is `partial`

This is not a blocker by itself.

It means the next work is:

1. preserve the raw real log
2. sanitize it if needed
3. add fixtures and tests for every observed imported row shape and skipped reason

---

## After The First Real Log Lands

Do these before touching the public claim.

### 1. Save the raw source log

Copy the log out of the profile home before you experiment further.

```bash
mkdir -p /Users/timmybhaserjian/assay/artifacts/openclaw-live-validation
cp "$OPENCLAW_HOME/agents/main/sessions/assay-live-validation-001.jsonl" \
  /Users/timmybhaserjian/assay/artifacts/openclaw-live-validation/
```

Adjust the source path if the agent or session id differs.

### 2. Save the harness result

```bash
cd /Users/timmybhaserjian/assay
/Users/timmybhaserjian/assay/.venv/bin/python \
  scripts/validate_openclaw_session_logs.py \
  --openclaw-home "$OPENCLAW_HOME" \
  --json \
  > artifacts/openclaw-live-validation/assay-live-validation-report.json
```

### 3. Convert the observed shapes into durable fixtures

Do not widen the public claim first.

Instead:

- create sanitized fixture logs from the real exported session
- add tests covering every imported row shape that appeared
- add tests for every skipped reason that appeared
- keep the first real JSON report as the baseline

Only after that should you revisit:

- `docs/openclaw-support.md`
- `docs/openclaw-v1-claim-sheet.md`

---

## Current Definition Of Done

This milestone is done when all of the following are true:

1. one real exported OpenClaw session log exists under an isolated profile home
2. `scripts/validate_openclaw_session_logs.py --openclaw-home <profile-home> --json` returns `status: "ok"`
3. the real log and the harness JSON result are saved as artifacts
4. the observed row shapes are promoted into fixture-backed tests before any claim change

Until then, the honest state remains `blocked`.
