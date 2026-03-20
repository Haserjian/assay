# What Assay Does Today

Assay today is a public evidence layer for existing AI workflows. It finds supported AI call sites, instruments them, records receipts during real execution, packages those receipts into signed proof packs, and verifies those packs offline. It can also compile reviewer-facing artifacts from that evidence. That is the primary public story.

## The literal flow

1. `assay scan .`
   Looks through your code and finds supported AI call sites.
2. `assay patch .`
   Adds the integration hooks that let later runtime events emit receipts.
3. `assay run -- <your normal command>`
   Runs your real program or test command and packages any receipts emitted during that run into a signed proof pack.
4. `assay verify-pack ./proof_pack_*`
   Checks integrity and declared claims offline.
5. `assay vendorq export-reviewer ...`
   Optionally compiles a reviewer-ready packet from the proof pack.

## What the important words mean

- `scan`: static inspection only. It does not run your app.
- `patch`: preparation. It does not prove anything by itself.
- `run`: Assay launches your normal command and watches for receipts during that real run.
- `receipt`: a structured event record emitted when an instrumented AI event happens.
- `proof pack`: the signed evidence artifact built from the receipts.
- `verify-pack`: the offline check that the artifact was not tampered with and that declared checks passed or failed honestly.

## Who does what

- The seller or builder integrates Assay into their own workflow.
- Assay emits receipts and builds the signed proof pack.
- Another team can verify the proof pack offline on their own machine.
- Reviewer packets are the readable wrapper around the proof pack, not the trust root itself.

## What Assay is not

- It is not already the full Loom / CCIO organism.
- It is not, today, the whole continuous runtime-native constitutional membrane.
- It does not replace every orchestration framework or agent runtime.
- It does not prove every upstream component was honest.

## Advanced public capability

Assay also exposes episode/checkpoint APIs such as `open_episode`, `seal_checkpoint`, and `verify_checkpoint`. Those are real and important. In this charter they count as advanced public bridge capability, not the first-contact product story.

## One paragraph you should be able to say out loud

Assay is a public evidence compiler for AI execution. It scans for supported call sites, patches the runtime hooks needed for receipts, runs your normal command, packages the receipts from that real run into a signed proof pack, and lets another team verify that pack offline. Reviewer packets sit on top when you need a bounded artifact for security or procurement review. The larger Loom/CCIO membrane exists, but that is not the whole public product today.
