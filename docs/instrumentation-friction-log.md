# Instrumentation Friction Log

## 2026-03-19 — CCIO bounded local brainstem proof-pack test

- Repo: `/Users/timmybhaserjian/ccio-main-clean`
- Target path: `brainstem` via existing `drill_brainstem.py` execution shape
- Friction verdict: `strong pass`
- Product-status verdict: `founder-only`

### Objective

Measure the portability/friction envelope for one bounded local, non-credentialed Assay proof-pack path in CCIO without widening the slice into repo cleanup, broad patching, or a mini-specimen.

### Result

The primary `brainstem` path cleared with one explicit code seam and one thin harness.

- Proof pack: `/Users/timmybhaserjian/ccio-main-clean/proof_pack_brainstem_local_20260319/`
- Pack ID: `pack_20260319T071501_71d98626`
- Verify result: `PASS`
- Receipts: `1`
- Attributed path evidence:
  - `provider`: `openai`
  - `model_id`: `gpt-4-turbo-preview`
  - `integration_source`: `assay.integrations.openai`
  - `finish_reason`: `stop`

### Exact command path

```bash
cd /Users/timmybhaserjian/ccio-main-clean
uv venv .venv-assay-portability --python 3.11
uv pip install --python .venv-assay-portability/bin/python -r requirements.txt assay-ai openai
PYTHONPATH=.:src .venv-assay-portability/bin/assay scan .
PYTHONPATH=.:src .venv-assay-portability/bin/assay score .
PYTHONPATH=.:src .venv-assay-portability/bin/python tests/assay_brainstem_local_e2e.py
PYTHONPATH=.:src .venv-assay-portability/bin/assay run -c receipt_completeness \
  -o ./proof_pack_brainstem_local_20260319 \
  -- .venv-assay-portability/bin/python tests/assay_brainstem_local_e2e.py
PYTHONPATH=.:src .venv-assay-portability/bin/assay verify-pack proof_pack_brainstem_local_20260319
```

### Setup tax

- The default machine `python3` was `3.14.3`; this slice required an isolated Python `3.11.15` env.
- Repo imports were not runnable in the default shell env until repo-declared deps were installed.
- `openai` and `assay-ai` were not repo-declared dependencies and had to be added to the isolated env for this slice.

### Hidden assumptions surfaced

- The pack was signed with a pre-existing machine-local Assay signer:
  - `signer_id`: `ci-assay-signer`
  - active signer file: `/Users/timmybhaserjian/.assay/keys/.active_signer`
- The proof tier is `signed-pack` and the time authority is `local_clock`, not an external TSA.
- The bounded run depended on unsetting competing cloud-provider env vars so `brainstem` would fall through `claude` and then succeed on the local-stubbed OpenAI path.
- The default profile behavior remained repo-native; no provider-routing internals were monkeypatched.

### Code and artifact delta

- Modified: `/Users/timmybhaserjian/ccio-main-clean/src/organism/brainstem.py`
  - added explicit `OPENAI_BASE_URL` support in `_call_openai()`
- Added: `/Users/timmybhaserjian/ccio-main-clean/tests/assay_brainstem_local_e2e.py`
  - starts a local OpenAI-compatible stub
  - bounds env vars
  - invokes the existing `drill_brainstem.py` path
- Produced artifact: `/Users/timmybhaserjian/ccio-main-clean/proof_pack_brainstem_local_20260319/`

### Why this is `strong pass`

- The primary target (`brainstem`) worked.
- Only one code seam was needed.
- Only one thin harness was needed.
- No live provider credentials were used.
- The resulting pack verified both in-repo and from a copied temp location.

### Why this is not `public-ready`

- The env bootstrap is still manual and nontrivial.
- The signer came from machine-local Assay state rather than repo-local setup.
- The bounded proof still depends on a purpose-built local stub harness.

### Next implication

Treat this as the first honest portability measurement that clears the primary path but still leaves activation as `founder-only`. The next product-shaping work, if desired, is not another proof demo; it is reducing setup tax:

1. make signer/bootstrap state explicit and repo-local or intentionally bootstrapped
2. make the bounded local stub path a documented, first-party drill
3. reduce environment ambiguity around Python/tooling selection

## 2026-03-19 — Brainstem drill replay on warm vs cold machine state

- Repo under test: `/Users/timmybhaserjian/ccio-main-clean`
- Warm-machine replay worktree: `/Users/timmybhaserjian/ccio-brainstem-replay`
- Cold-machine replay worktree: `/Users/timmybhaserjian/ccio-brainstem-cold-replay`
- Warm-machine verdict: `pass`
- Cold-machine verdict: `fail-fast on signer bootstrap`

### Objective

Measure whether the new drill and preflight convert the bounded `brainstem` proof path into operator memory, and separate documentation sufficiency from machine-bootstrap sufficiency.

### Warm-machine replay result

Using a fresh detached worktree and a stripped shell, the drill was replayable from the documented steps.

- Initial preflight failed on the expected missing venv/packages/CLI state.
- Following the documented bootstrap commands made preflight pass cleanly.
- A fresh `proof_pack_brainstem_local_drill/` was produced.
- `verify-pack` passed in-repo and from a copied temp location.
- Receipt attribution still pointed at `src/organism/brainstem.py` via the local-stubbed OpenAI path.

### Cold-machine replay result

Using a fresh detached worktree plus a clean `HOME` at `/tmp/ccio-cold-home`, the drill separated env bootstrap from signer bootstrap exactly as intended.

- Initial preflight failed on:
  - missing `.venv-assay-portability`
  - missing packages / local `assay` CLI
  - missing `~/.assay/keys/.active_signer`
- After following the documented bootstrap literally, preflight reduced to one remaining blocking issue:
  - `FAIL active-signer: missing /tmp/ccio-cold-home/.assay/keys/.active_signer`

### Interpretation

The drill and preflight are now good enough to make the operator path reproducible on a warm machine without founder narration. Cold-machine bootstrap is still not complete: the remaining hidden dependency is explicit Assay signer setup.

This shifts the next bootstrap question from vague environment folklore to a single concrete gap:

1. define how a fresh operator creates or activates an Assay signer
2. decide whether signer bootstrap should be repo-local, user-local, or deliberately external
3. add that answer to the operator path before claiming cold-machine reproducibility

## 2026-03-19 — Cold-machine replay after explicit local signer bootstrap

- Repo under test: `/Users/timmybhaserjian/ccio-main-clean`
- Clean `HOME`: `/tmp/ccio-cold-home-v2`
- Friction verdict: `strong pass`
- Product-status verdict: `team-runnable under bounded local conditions`

### Objective

Verify that the bounded `brainstem` drill can complete on a clean machine state once signer bootstrap is made explicit operator memory rather than an ambient local assumption.

### Result

The cold-machine path now clears end-to-end with an explicit local signer bootstrap.

- Preflight initially failed only on `active-signer`.
- Running `.venv-assay-portability/bin/assay key generate ccio-brainstem-local` made preflight pass under the clean `HOME`.
- The bounded harness ran successfully.
- `assay run` produced `proof_pack_brainstem_local_drill/` with:
  - Pack ID: `pack_20260319T164031_8c3250c6`
  - Signer: `ccio-brainstem-local`
  - Integrity: `PASS`
  - Claims: `PASS`
  - Receipts: `1`
- `verify-pack` passed in-repo and from a copied temp location.

### Interpretation

This moves the operator path beyond `founder-only`. A fresh operator can now bootstrap the local env, create a local drill signer, produce a signed proof pack, and verify it without founder narration.

What remains unsolved is not local reproducibility. It is trust distribution:

1. how local drill signers map into verifier policy or signer allowlists
2. whether team/shared operators should use user-local keys, imported shared keys, or CI-held keys
3. how public or cross-team verification should treat locally generated signer identities
