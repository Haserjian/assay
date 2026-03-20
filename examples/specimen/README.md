# Assay Specimen

This specimen is the canonical local walkthrough for the current public story:

`scan -> patch -> run -> receipts -> proof pack -> verify -> optional reviewer packet`

It uses a local OpenAI-compatible stub server so you can exercise the full flow without a real API key or external account.

## What this specimen proves

- `assay scan` finds a supported OpenAI call site
- `assay patch` instruments that call site
- `assay run -- <your command>` wraps a real program execution
- an instrumented model call emits a receipt during that run
- Assay packages the receipts into a signed proof pack
- `assay verify-pack` verifies the artifact offline
- `assay vendorq export-reviewer` can wrap that proof pack in a reviewer packet

## Files

- `sample_app.before.py`: the unpatched sample app
- `mock_openai_server.py`: local OpenAI-compatible stub
- `run_demo.sh`: end-to-end specimen runner

## Run it

From the repo root:

```bash
./examples/specimen/run_demo.sh
```

If you are working from the source repo, the script prefers `.venv/bin/python`. If `openai` is missing in that interpreter, install the optional extra first:

```bash
.venv/bin/python -m ensurepip --upgrade
.venv/bin/pip install -e ".[openai]"
```

## What the script does

1. Creates a temporary workspace.
2. Copies in the unpatched sample app.
3. Runs `assay scan` and saves both JSON and HTML outputs.
4. Runs `assay patch` against the sample app.
5. Starts the local OpenAI-compatible stub server.
6. Runs the patched app under `assay run`.
7. Verifies the resulting proof pack with `assay verify-pack`.
8. Compiles and verifies an optional reviewer packet.

## Manual path

If you want to drive it step by step instead of using the script:

```bash
WORKDIR="$(mktemp -d)"
cp examples/specimen/sample_app.before.py "$WORKDIR/sample_app.py"
python -m assay.cli scan "$WORKDIR" --json
python -m assay.cli patch "$WORKDIR" --entrypoint sample_app.py -y
python examples/specimen/mock_openai_server.py --port 8787 &
cd "$WORKDIR"
OPENAI_API_KEY=specimen-local-key SPECIMEN_BASE_URL=http://127.0.0.1:8787/v1 \
  python -m assay.cli run -c receipt_completeness -- python sample_app.py
python -m assay.cli verify-pack ./proof_pack_*/
```

## What to notice

- `run` is not invented theater. It is your normal command, wrapped.
- The receipt appears because the patched runtime actually crossed a supported call site.
- The proof pack is the trust root. The reviewer packet is the readable wrapper.
