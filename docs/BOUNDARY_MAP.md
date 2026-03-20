# Boundary Map

This is the working boundary for the current charter. If a sentence blurs these rows together, the sentence is probably wrong.

| Component | What it is | Audience | Public / Private | Current / Future | Wedge / Organism role |
|-----------|------------|----------|------------------|------------------|------------------------|
| Assay | Public evidence compiler for AI execution: scan, patch, run, signed proof pack, offline verify | Developers, security reviewers, procurement reviewers | Public | Current | Public trust layer |
| VendorQ | Reviewer workflow and packet compiler built on top of Assay evidence | Teams answering buyer or reviewer questions | Public-facing workflow, but wedge-specific | Current wedge hypothesis | Wedge |
| AgentMesh | Provenance and execution-lineage helper used to support delivery and runtime evidence stories | Builders who need lineage between execution surfaces | Public | Current, but support-layer | Support for the trust story, not the whole product |
| Loom / CCIO | Private constitutional runtime and consequence membrane: episodes, checkpoints, governance, lineage, settlement | Internal builder / operator surface | Private | Current privately, future strategic center | Organism |

## Working rules

- Assay is the first public trust story.
- VendorQ is a wedge hypothesis built on that trust layer.
- AgentMesh is supporting provenance infrastructure.
- Loom / CCIO is where the real load-bearing membrane is allowed to get weird and powerful.

## Anti-blur rules

- Do not describe VendorQ as the whole product.
- Do not describe Assay as if it already is the whole runtime membrane.
- Do not describe Loom / CCIO as public first-contact product surface.
- Do not introduce a second bridge vocabulary when `open_episode`, `seal_checkpoint`, `verify_checkpoint`, `action.settled`, and `action.denied` already name the bridge.
