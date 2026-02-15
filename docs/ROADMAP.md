# Assay Roadmap

**As of**: v1.5.3 (Feb 2026)
**Launch**: Feb 18, 2026

---

## Product Boundary

Three zones. Every PR can be checked against this.

### Public: Assay (Evidence Compiler)

Portable evidence for AI systems. PyPI package, open source.

| Surface | Ships in `assay-ai` | Status |
|---------|---------------------|--------|
| scan, patch | AST call site detection + auto-instrumentation | Shipped |
| run, verify-pack | Receipt collection + signed proof packs | Shipped |
| diff (--gate, --against-previous, --why) | Pack comparison + regression gates + forensics | Shipped |
| analyze (--history) | Cost/latency/error breakdown | Shipped |
| explain | Plain-English pack summaries | Shipped |
| lockfile (write, check) | Governance contract freeze + drift detection | Shipped |
| key (list, rotate, set-active) | Ed25519 key lifecycle + active signer | Shipped |
| doctor | Preflight checks (4 profiles) | Shipped |
| schema registry | Receipt version compat + parent_receipt_id | Shipped |
| conformance corpus | 6 deterministic packs + expected outcomes | Shipped |

### Bridge: MCP Notary Proxy (Tool-Call Evidence)

Receipting proxy between MCP clients and servers. Zero server changes.

| Surface | Status |
|---------|--------|
| `assay mcp-proxy` (stdio, audit profile) | Spec complete, build Phase 1 |
| Guard profile + policy enforcement | Spec complete, build Phase 2 |
| SSE transport | Designed, Phase 3 |
| Decision Escrow (permit/settle) | Reserved, v2 |

### Private: CCIO / Loom / Quintet (Constitutional Cognition)

Not shipped in `assay-ai`. Not open source. The moat.

| System | What it does | Extraction rule |
|--------|-------------|----------------|
| LEM (Large Event Model) | Tri-temporal event spine + causal DAG | Only LEM-lite primitives graduate (regime detection) |
| Coherence Triangulation | 3-estimator drift detection (IT + geometric + predictive) | Simplified single-metric version may graduate as `assay drift` |
| Dignity (5-facet) | Non-compensatory ethics gate | May graduate as open standard (Option F) |
| Semantic Mass / Physics | Knowledge graph inertia + field solve | Stays private |
| Chi-Router | Curvature-driven routing (BLOOM/REFLECT/COMPOST) | Stays private |
| MemoryGraph | Directed graph with temporal attributes | Stays private |
| Organism Model | 12-module AGI architecture | Stays private |
| Quintet Policy Scientist | Offline policy evaluation + debate | May extract lever analysis as `assay recommend` |
| Council / Debate | Multi-agent adversarial consensus | Stays private |

**Boundary rule**: If it affects trust in the verification chain, it must be open.
If it affects cognition, governance internals, or organism architecture, it stays private.
Use private systems to generate better public artifacts, not public complexity.

---

## Execution Phases

### Phase 0: Launch (now -- Feb 18)

**Goal**: Get strangers from curiosity to first proof pack in 10 minutes.

| Deliverable | Status |
|-------------|--------|
| README rewrite (funnel structure) | Done |
| Docs aligned (quickstart, compliance, decision-escrow, repo map) | Done |
| MCP Notary Proxy spec (v0) | Done |
| Bridge de-exported from __init__.py | Done |
| v1.5.3 on PyPI | Done |
| Launch tag (`launch-2026-02-18`) at current main | Done |
| Post drafts (HN, Reddit, Discord, comment replies) | Done |
| Issue templates + CONTRIBUTING + Discussions | Done |

**Exit criteria**: 826 tests pass. PyPI install works. `quickstart` runs clean.
All posts reference `launch-2026-02-18` tag. No stale version numbers in docs.

**Rule**: No new features. Only doc/onboarding fixes.

### Phase 1: Temporal Intelligence (Feb 25 -- Mar 14)

**Goal**: Assay becomes a weekly ops tool, not just audit tooling.

| Deliverable | Source | Effort | Risk |
|-------------|--------|--------|------|
| Regime detection in `assay analyze` | CUSUM (149 LOC) + BOCPD (119 LOC) + RegimeGate (148 LOC) from `ccio/lem/detectors/` | ~1 week | Low: pure signal processing, no governance deps |
| Drift detection on claim vectors | Predictive estimator (CV-RMSE) from coherence.py | ~3 days | Low: single metric, clear semantics |
| `assay analyze --history --regime-detect` | New CLI flag | ~2 days | Low |
| `assay drift` or `assay analyze --drift` | New command or flag | ~2 days | Low |

**CLI surface**:
```bash
assay analyze --history --since 14 --regime-detect
# "Cost regime change detected: Tuesday Feb 25 14:12 UTC. Not recovered."

assay analyze --drift --baseline ./baseline_pack/
# "Claim-failure distribution drifted 2.8 sigma vs baseline."
```

**Exit criteria**: 30+ new tests. `regime-detect` identifies synthetic regime
changes with <5% false positive rate. `drift` reports sigma distance from baseline.

**What does NOT ship**: Full coherence triangulation, dignity system, semantic mass.

### Phase 2: MCP Notary Proxy v0 (Mar 14 -- Mar 28)

**Goal**: `assay mcp-proxy` ships as a working stdio proxy with audit profile.

| Deliverable | Effort | Risk |
|-------------|--------|------|
| `src/assay/mcp_proxy.py` -- stdio forwarding + JSON-RPC parsing | 1 week | Medium: MCP framing edge cases |
| `MCPToolCallReceipt` emission | 2 days | Low |
| Auto-pack on session end | 2 days | Low: reuses existing pack builder |
| Graceful shutdown + partial pack on crash | 2 days | Medium |
| `assay mcp-proxy` CLI command | 1 day | Low |
| 30+ tests with mock MCP server | 3 days | Low |

**Exit criteria**: End-to-end test: mock MCP server, proxy, tool call, receipt,
pack built, `verify-pack` passes. Graceful SIGINT produces valid pack.

**What does NOT ship**: Guard profile, policy enforcement, SSE transport.

### Phase 3: Guard Profile + Policy (Apr)

**Goal**: MCP proxy enforces tool boundaries.

| Deliverable | Source | Effort |
|-------------|--------|--------|
| `src/assay/mcp_policy.py` | Fork from `bridge.py` security invariants | 1 week |
| Policy evaluation (denylist > constraints > allowlist > default) | New | 3 days |
| Guard mode in proxy (deny + receipt + error to client) | Extend mcp_proxy.py | 3 days |
| 30+ policy tests | Fork from test_bridge.py | 3 days |

**Exit criteria**: Denied tool call produces receipt with `outcome: "denied"`,
error returned to client, request never reaches server.

### Phase 4+: Future (Q2-Q3 2026)

| Item | Prerequisite | Timing |
|------|-------------|--------|
| SSE transport for proxy | Phase 2 shipping | Q2 |
| `assay recommend` (lever analysis) | Receipt volume from real users | Q2 |
| Dignity-Lite open standard | Strategic decision on IP exposure | Q2 |
| Decision Escrow (permit/settle) | Proxy adoption + real MCP traffic | Q2-Q3 |
| Invariant Hunter prototype | Rich receipt history from production users | H2 |
| Receipt Internet v0 (local WIPE) | Escrow profile working | H2 |

### Regulatory deadlines

| Date | Event | Assay relevance |
|------|-------|----------------|
| Aug 2, 2026 | EU AI Act Articles 12 & 19 effective | Logging + traceability for high-risk AI |
| 2027 | SOC 2 AI-specific controls expected | Evidence artifacts for audits |

---

## Version Strategy

| Version | What ships | When |
|---------|-----------|------|
| v1.5.3 | Schema registry, diff --why, key lifecycle | Live (PyPI) |
| v1.6.0 | Regime detection + drift | Phase 1 (Mar) |
| v1.7.0 | MCP Notary Proxy (audit) | Phase 2 (late Mar) |
| v1.8.0 | MCP Guard profile + policy | Phase 3 (Apr) |
| v2.0.0 | Decision Escrow (breaking: new receipt types) | Q2-Q3 |

---

## Success Metrics

### Launch week (Feb 18-25)
- PyPI installs
- `quickstart` completions (GitHub star / issue as proxy)
- Number of `scan --report` runs on real repos
- Quality of objections in comments (threat model, not "is this real?")

### Phase 1 (Mar)
- Teams with CI gates active
- Regime detection catches real incidents
- Repeat `analyze --history` usage

### Phase 2 (late Mar)
- MCP proxy deployed by early adopters
- Tool call receipts in proof packs
- First offline verification of an MCP session
