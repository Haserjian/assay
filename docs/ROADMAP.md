# Assay Roadmap

**As of**: v1.6.0 (Feb 2026)
**Launch**: Feb 18, 2026

---

## What Assay Is

Assay is an evidence compiler for AI systems. It produces tamper-evident,
cryptographically signed audit trails that a third party can verify offline.

Everything in this roadmap ships in the `assay-ai` PyPI package under Apache-2.0.
Some features originate from internal research; they graduate to the public package
when they're stable and don't require private infrastructure.

---

## What's Shipped

### Core (Evidence Compiler)

| Surface | What it does | Status |
|---------|-------------|--------|
| scan, patch | AST call site detection + auto-instrumentation | Shipped |
| run, verify-pack | Receipt collection + signed proof packs | Shipped |
| diff (--gate, --against-previous, --why) | Pack comparison + regression gates + forensics | Shipped |
| analyze (--history) | Cost/latency/error breakdown | Shipped |
| explain | Plain-English pack summaries | Shipped |
| score | Evidence Readiness Score (0-100, A-F) | Shipped |
| lockfile (write, check) | Governance contract freeze + drift detection | Shipped |
| key (list, rotate, set-active) | Ed25519 key lifecycle + active signer | Shipped |
| doctor | Preflight checks (4 profiles) | Shipped |
| schema registry | Receipt version compat + parent_receipt_id | Shipped |
| conformance corpus | 6 deterministic packs + expected outcomes | Shipped |
| flow (try, adopt, ci, mcp, audit) | Guided workflow executor | Shipped |
| audit bundle, verify-signer | Auditor handoff artifacts | Shipped |
| packs (list, show, pin-baseline) | Local pack browsing | Shipped |

### MCP Notary Proxy (Tool-Call Evidence)

Receipting proxy between MCP clients and servers. Zero server changes.

| Surface | Status |
|---------|--------|
| `assay mcp-proxy` (stdio, audit profile) | Shipped (v0) |
| Guard profile + policy enforcement | Phase 2 |
| SSE transport | Phase 3 |
| Decision Escrow (permit/settle) | v2 |

### SDK Integrations

| SDK | Status |
|-----|--------|
| OpenAI (+ any OpenAI-compatible: Ollama, vLLM, LM Studio) | Shipped |
| Anthropic | Shipped |
| Google Gemini | Shipped |
| LiteLLM | Shipped |
| LangChain (callback handler) | Shipped |

---

## Execution Phases

### Phase 0: Launch (Complete)

**Goal**: Get strangers from curiosity to first proof pack in 10 minutes.

All deliverables complete. 1123 tests passing. v1.6.0 on PyPI.

### Phase 1: Temporal Intelligence (Mar 2026)

**Goal**: Assay becomes a weekly ops tool, not just audit tooling.

| Deliverable | Effort | Risk |
|-------------|--------|------|
| Regime detection in `assay analyze` (CUSUM + Bayesian changepoint) | ~1 week | Low |
| Drift detection on claim vectors | ~3 days | Low |
| `assay analyze --history --regime-detect` | ~2 days | Low |
| `assay analyze --drift --baseline <pack>` | ~2 days | Low |

**CLI surface**:
```bash
assay analyze --history --since 14 --regime-detect
# "Cost regime change detected: Tuesday Feb 25 14:12 UTC. Not recovered."

assay analyze --drift --baseline ./baseline_pack/
# "Claim-failure distribution drifted 2.8 sigma vs baseline."
```

**Exit criteria**: 30+ new tests. `regime-detect` identifies synthetic regime
changes with <5% false positive rate. `drift` reports sigma distance from baseline.

### Phase 2: MCP Guard Profile + Policy (Late Mar 2026)

**Goal**: Extend shipped MCP audit proxy with enforceable guard mode.

| Deliverable | Effort | Risk |
|-------------|--------|------|
| `src/assay/mcp_policy.py` (policy engine) | 1 week | Medium: policy semantics |
| Policy evaluation (denylist > constraints > allowlist > default) | 3 days | Low |
| Guard mode in proxy (deny + receipt + error to client) | 3 days | Medium |
| Expanded conformance coverage against protocol MUSTs 1-8 | 3 days | Medium |
| 30+ policy tests with mock MCP server | 3 days | Low |

**Exit criteria**: Denied tool call produces receipt with `outcome: "denied"`,
error returned to client, request never reaches server. Policy governed by
`assay.mcp-policy.yaml`.

### Phase 3: MCP Transport + Escrow Foundations (Apr 2026)

**Goal**: Expand transport support and prepare permit/settle flows.

| Deliverable | Effort |
|-------------|--------|
| SSE transport for proxy | 1 week |
| Permit/settle scaffolding for Decision Escrow | 1 week |
| Cross-transport session trace consistency tests | 3 days |
| Policy + transport integration tests | 3 days |

**Exit criteria**: Stdio + SSE produce equivalent receipt semantics and pass
conformance profile gates in CI.

### Phase 4+: Future (Q2-Q3 2026)

| Item | Prerequisite | Timing |
|------|-------------|--------|
| Compliance report generator | Mapping data in docs/for-compliance.md | Q2 |
| SSE transport for proxy | Phase 2 shipping | Q2 |
| Lever analysis recommendations | Receipt volume from real users | Q2 |
| Decision Escrow (permit/settle) | Proxy adoption + real MCP traffic | Q2-Q3 |
| Observability platform adapters | User demand signal | Q2-Q3 |
| Receipt interop specification | Community interest | H2 |

### Regulatory Deadlines

| Date | Event | Assay relevance |
|------|-------|----------------|
| Aug 2, 2026 | EU AI Act Articles 12 & 19 effective (high-risk, Annex III) | Automatic logging + tamper resistance for high-risk AI |
| Aug 2, 2027 | EU AI Act high-risk obligations for regulated products (Annex I) | Extended scope |
| 2027 | SOC 2 AI-specific controls expected | Evidence artifacts for audits |

See [compliance citations](compliance-citations.md) for exact regulatory references.

---

## Version Strategy

| Version | What ships | When |
|---------|-----------|------|
| v1.5.3 | Schema registry, diff --why, key lifecycle | Live (PyPI) |
| v1.6.0 | Flow commands, audit bundle, verify-signer, Gemini + LiteLLM, key lifecycle UX, pack lifecycle | Live (PyPI) |
| v1.7.0 | Regime detection + drift (`analyze --history --regime-detect`) | Phase 1 (Mar) |
| v1.8.0 | MCP Guard profile + policy enforcement | Phase 2 (late Mar) |
| v2.0.0 | Decision Escrow (breaking: new receipt types) | Q2-Q3 |

---

## Success Metrics

### Launch (Feb 2026)
- PyPI installs
- `quickstart` completions (GitHub star / issue as proxy)
- `scan --report` runs on real repos
- Quality of objections (threat model depth, not "is this real?")

### Phase 1 (Mar 2026)
- Teams with CI gates active
- Regime detection catches real incidents
- Repeat `analyze --history` usage

### Phase 2 (Late Mar 2026)
- MCP proxy deployed by early adopters
- Tool call receipts in proof packs
- First offline verification of an MCP session

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to contribute.
Open an [issue](https://github.com/Haserjian/assay/issues) for feature requests
or bug reports. [Discussions](https://github.com/Haserjian/assay/discussions) for
questions and feedback.
