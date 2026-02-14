# MCP Notary Proxy Spec (v0)

**Status**: Implementation spec (v0)
**Product**: `assay mcp-proxy` -- receipting proxy for MCP tool calls
**Alias**: MCP Flight Recorder
**Prerequisite**: Thread-safe store (done: RLock + fcntl.flock in store.py)
**Builds on**: `bridge.py` security invariants, `spec-mcp-receipt-layer.md` receipt schemas
**Target**: Post-launch Phase 1

---

## One-liner

MCP tells agents what to call. Assay proves what they actually did.

## Problem

MCP has 13,000+ servers. No tool produces tamper-evident audit trails for
tool invocations. The existing `spec-mcp-receipt-layer.md` solves this via
server-side wrapping -- but that requires modifying server code. Most MCP
users run third-party servers they don't control.

The proxy sits between client and server. Zero server-side changes. Minimal
client config change. Every tool call gets receipted.

## Boundary claim

The proxy proves what crossed the proxy boundary. It does not prove internal
server truth (what the server did with the arguments, whether the result is
honest, etc.). In guard mode, it additionally proves that denied calls were
blocked before reaching the server.

This is still valuable: it creates a verifiable record of every tool
interaction at the only control point most teams have -- the protocol edge.

## How it works

```
MCP Client (Claude Code, Cursor, etc.)
    |
    | stdio / SSE
    v
assay mcp-proxy (receipting proxy)
    |  - emits MCPToolCallReceipt per invocation
    |  - audit profile: protocol-transparent (observe only)
    |  - guard profile: decision-enforcing (may deny + return error)
    |  - auto-builds proof packs per session
    |
    | stdio / SSE (forwarded)
    v
MCP Server (any -- unmodified)
```

**Transparency model by profile:**
- `audit`: Protocol-transparent. All messages forwarded unchanged. Receipts
  are emitted as side-effects only. The server and client cannot distinguish
  proxied from unproxied connections.
- `guard`: Decision-enforcing. Denied tool calls are intercepted and an MCP
  error response is returned to the client. The server never sees the request.
  Non-denied calls are forwarded unchanged.

---

## CLI UX

### Start the proxy

```bash
# Stdio transport (most common -- wraps a command)
assay mcp-proxy -- python my_server.py

# With explicit audit directory
assay mcp-proxy --audit-dir ./.assay/mcp/ -- python my_server.py

# SSE transport (Phase 2)
assay mcp-proxy --upstream-url http://localhost:8080/mcp
```

The `--` separator splits proxy flags from the upstream server command.
This avoids shell-fragile string quoting of `--upstream "python my_server.py"`.

### Client config (minimal config change)

**Before** (Claude Code `claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "my-server": {
      "command": "python",
      "args": ["my_server.py"]
    }
  }
}
```

**After**:
```json
{
  "mcpServers": {
    "my-server": {
      "command": "assay",
      "args": ["mcp-proxy", "--", "python", "my_server.py"]
    }
  }
}
```

Validated against Claude Code and Cursor MCP config formats. Other clients
may vary -- test before claiming "one line change" for a specific client.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-- <cmd...>` | required (stdio) | Server command, passed after `--` separator |
| `--upstream-url` | none | Server URL (SSE, Phase 2). Mutually exclusive with `--` |
| `--audit-dir` | `./.assay/mcp/` | Where receipts and packs are written |
| `--profile` | `audit` | Security profile: `audit`, `guard` |
| `--policy` | none | Path to `assay.mcp-policy.yaml` (required for `guard`) |
| `--auto-pack` | true | Build proof pack when session ends |
| `--pack-interval` | `session` | Pack interval: `session`, `Nm` (minutes), `Nr` (receipts) |
| `--store-args` | false | Store tool arguments in cleartext (default: hash-only) |
| `--store-results` | false | Store tool results in cleartext (default: hash-only) |
| `--server-id` | auto | Server identifier for receipts |
| `--shutdown-timeout` | `10` | Seconds to wait for graceful shutdown before force-packing |
| `--json` | false | JSON output for status messages |

### Profiles

| Profile | Receipts | Policy | Blocking | Transparency | Use case |
|---------|----------|--------|----------|--------------|----------|
| `audit` | yes | advisory | no | protocol-transparent | Observe without interference |
| `guard` | yes | enforced | yes | decision-enforcing | Enforce tool boundaries |
| `escrow` | reserved | -- | -- | -- | Transaction protocol (v2, not implemented) |

Default is `audit`. `guard` requires `--policy`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Session ended cleanly, pack built and verified |
| 1 | Session ended with policy violations recorded (honest failure) |
| 2 | Self-check failure: pack integrity error, serialization error, or corruption |
| 3 | Bad input (invalid flags, unreachable upstream, missing policy file) |
| 130 | SIGINT (Ctrl+C) -- graceful shutdown, pack built before exit |

---

## Receipt schema: `MCPToolCallReceipt`

One receipt per tool invocation. Not three (requested/denied/executed) as in
the server-side spec -- the proxy sees the full round-trip as one event.

```python
{
    "type": "mcp_tool_call",
    "receipt_id": "mtc_<uuid16>",
    "timestamp": "2026-03-15T11:30:00.000Z",      # Receipt creation time
    "schema_version": "3.0",
    "seq": N,

    # Correlation
    "invocation_id": "inv_<uuid16>",          # Unique per tool call
    "session_id": "mcp_<session_hash>",       # Stable per proxy session
    "parent_receipt_id": null,                 # For causal chains (v2)

    # MCP context
    "server_id": "my-server",                 # From --server-id or auto
    "server_transport": "stdio",              # "stdio" | "sse"
    "tool_name": "web_search",
    "mcp_request_id": "req_123",              # MCP protocol request ID

    # Phase timing (enables causal analysis)
    "request_observed_at": "2026-03-15T11:30:00.000Z",   # When proxy saw tools/call request
    "policy_decided_at": "2026-03-15T11:30:00.001Z",     # When policy verdict was made (null if no_policy)
    "response_observed_at": "2026-03-15T11:30:00.234Z",  # When proxy saw response (null if denied)

    # Arguments (privacy-by-default)
    "arguments_hash": "sha256:<hex>",         # SHA-256 of JCS(arguments)
    "arguments_content": null,                # Set only if --store-args

    # Result (privacy-by-default)
    "result_hash": "sha256:<hex>",            # SHA-256 of JCS(result); null if denied/timeout
    "result_content": null,                   # Set only if --store-results
    "result_is_error": false,                 # MCP isError flag; null if denied/timeout

    # Outcome
    "outcome": "forwarded",                   # "forwarded" | "denied" | "error" | "timeout"
    "duration_ms": 234,                       # Round-trip time; null if denied

    # Policy
    "policy_verdict": "no_policy",            # "allowed" | "denied" | "no_policy"
    "policy_ref": null,                       # Policy rule that matched; null if no_policy
    "policy_hash": null,                      # SHA-256 of active policy file; null if no_policy

    # Integration metadata
    "proxy_version": "1.5.0",
    "integration_source": "assay.mcp_proxy",
}
```

### `policy_verdict` enum (canonical, all profiles)

| Value | Meaning | Profile behavior |
|-------|---------|-----------------|
| `"no_policy"` | No policy file loaded | `audit` without `--policy`, always |
| `"allowed"` | Policy evaluated, tool permitted | `audit`: advisory (still forwarded). `guard`: forwarded |
| `"denied"` | Policy evaluated, tool rejected | `audit`: advisory (still forwarded). `guard`: blocked, error returned |

There is no `"would_allow"` / `"would_deny"` variant. The verdict is always
the real policy evaluation result. What differs by profile is whether the
verdict is *enforced* (guard) or *advisory* (audit). This avoids enum
proliferation and makes receipts comparable across profiles.

### Outcome-to-field nullability matrix

| Outcome | `result_hash` | `result_content` | `result_is_error` | `duration_ms` | `response_observed_at` | `policy_decided_at` |
|---------|--------------|-----------------|-------------------|--------------|----------------------|-------------------|
| `forwarded` | set | set if --store-results | set | set | set | set if policy loaded, else null |
| `denied` | null | null | null | null | null | set |
| `error` | set (error body) | set if --store-results | true | set | set | set if policy loaded, else null |
| `timeout` | null | null | null | set (= timeout duration) | null | set if policy loaded, else null |

"set" means the field is present with a value. "null" means the field is
present with value `null`. Fields are never omitted -- every field in the
schema is always present for stable downstream analytics.

### Why one receipt, not three

The server-side spec uses three receipts (requested -> denied/executed) because
the server can act between request and execution (policy check, async queue).
The proxy sees the tool call as one atomic event: request goes in, response
comes out. One receipt captures the full round-trip.

The phase timing fields (`request_observed_at`, `policy_decided_at`,
`response_observed_at`) preserve causal ordering within the single receipt
for later `--why` / replay analysis.

### Receipt ID prefix

`mtc_` (MCP tool call). Distinct from the server-side `mtr_`/`mtd_`/`mte_`
prefixes so receipts from both integration points are distinguishable.

### Privacy note: low-entropy argument leakage

Hash-only mode prevents cleartext storage but does not prevent brute-force
recovery of low-entropy arguments (e.g., boolean flags, small enum values,
short file paths). For deployments where this matters, consider:
- Using `--store-args` with redaction (future: per-field allowlist)
- Deploying an org-level pepper for hash computation (future: `--hash-pepper`)
- Treating hash-only as "not-in-cleartext" rather than "confidential"

---

## Directory layout

```
.assay/mcp/
  receipts/                       # Raw receipt stream
    session_20260315T113000Z.jsonl # One file per session
  packs/                          # Auto-built proof packs
    proof_pack_20260315T113000Z/
      receipt_pack.jsonl
      pack_manifest.json
      pack_signature.sig
      verify_report.json
      verify_transcript.md
  policy/                         # Policy snapshots (for reproducibility)
    policy_sha256_abc123.yaml     # Content-addressed copy of active policy
```

### Session boundaries

A session starts when the proxy starts and ends when:
- The MCP server process exits (stdio)
- The SSE connection closes
- SIGINT/SIGTERM is received
- `--pack-interval Nm` timer fires (rolling packs)

### Session end behavior (deterministic)

On clean session end (server exits, connection closes):
1. Flush all pending receipts to JSONL
2. Build proof pack from session receipts
3. Sign pack with active signer key
4. Run verify-pack as self-check
5. Print pack path and exit code

On SIGINT/SIGTERM:
1. Set `--shutdown-timeout` timer (default 10s)
2. Forward signal to upstream server process (stdio only)
3. Drain any in-flight tool call responses (wait up to timeout)
4. Flush + pack + sign + verify (same as clean end)
5. If timeout expires before drain completes: pack with receipts collected
   so far, log warning about incomplete session

On crash / unexpected pipe close:
1. Flush receipts collected so far (best-effort)
2. Build pack from whatever receipts exist
3. Mark pack with `"session_complete": false` in manifest metadata
4. Exit code 2 (self-check failure -- incomplete session)

The invariant: **a pack is always attempted**. Even a partial pack from a
crashed session is more useful than no evidence.

---

## Protocol forwarding

### Stdio transport (Phase 1)

The proxy spawns the upstream command as a subprocess and bridges stdio:

```
Client stdin  -> proxy reads -> (inspect + receipt) -> writes to server stdin
Server stdout -> proxy reads -> (inspect + receipt) -> writes to client stdout
Server stderr -> proxy reads -> writes to client stderr (passthrough)
```

The proxy parses JSON-RPC messages on the wire. It only inspects
`tools/call` requests and their responses. All other messages
(initialization, resource reads, prompts) are forwarded unchanged.

**Message detection:**
- Request: `{"method": "tools/call", "params": {"name": "...", "arguments": {...}}}`
- Response: `{"result": {"content": [...], "isError": false}}` (matched by request ID)

**Framing:** Use the `mcp` Python SDK's transport layer for JSON-RPC message
framing. Do NOT implement raw Content-Length or newline-delimited parsing in
v0. The SDK handles both framing styles and edge cases (partial reads,
encoding). Raw parser fallback is deferred to v0.1+ only if SDK transport
proves insufficient for the proxy use case.

### SSE transport (Phase 2)

HTTP proxy that forwards SSE streams. Same receipt logic, different wire
format. Deferred because stdio covers >90% of current MCP server deployments.

---

## Policy enforcement (--profile guard)

Reuses `bridge.py`'s security invariants.

### Policy evaluation precedence (deterministic)

Evaluated in this exact order. First match wins:

```
1. Denylist    -> if tool_name in denylist: DENIED (always, regardless of allowlist)
2. Constraints -> if tool has constraints and they fail: DENIED
3. Allowlist   -> if tool_name in allowlist: ALLOWED
4. Default     -> use policy file's `default:` value (allow | deny)
```

This is fail-closed for `default: deny` and fail-open for `default: allow`.
Guard mode requires an explicit `--policy` file; there is no implicit
default policy.

### Transferred from bridge.py

| Invariant | bridge.py source | Proxy behavior |
|-----------|-----------------|----------------|
| SSRF deny | `_host_is_private()` | Block `web_fetch` to private IPs (constraint) |
| Tool allowlist | `ToolPolicy.safe_tools` | `assay.mcp-policy.yaml` allowlist |
| Tool denylist | `ToolPolicy.dangerous_tools` | `assay.mcp-policy.yaml` denylist |
| Args-never-in-CLI | stdin transport | Already true (MCP uses JSON-RPC) |
| Fail-closed unknown | `POLICY_DEFAULT_DENY_001` | `default: deny` in policy file |
| Sensitive action approval | `sensitive_action_approved` | Deferred to escrow profile |

### Policy file: `assay.mcp-policy.yaml`

```yaml
version: "1"

# Precedence: denylist > constraints > allowlist > default
default: deny

allowlist:
  - web_search
  - web_fetch
  - read_file

denylist:
  - shell_exec
  - file_delete

constraints:
  web_fetch:
    deny_private_hosts: true    # SSRF guard
  read_file:
    allowed_paths:
      - "/workspace/*"
      - "!**/.env"              # Exclude secrets
```

### Policy behavior by profile

**`--profile audit` (with `--policy`):**
- Policy file loaded and evaluated
- `policy_verdict` set to `"allowed"` or `"denied"` (real evaluation)
- All calls forwarded regardless -- verdict is advisory only
- Enables "dry-run policy" before switching to guard mode

**`--profile guard` (requires `--policy`):**
- Policy file loaded and enforced
- Denied tools: receipt emitted with `outcome: "denied"`, MCP error
  returned to client, request never reaches server
- Allowed tools: forwarded unchanged
- Policy file content-addressed and snapshotted in `policy/` dir

---

## Integration with Assay pipeline

### Store integration

Receipts are emitted to the Assay store (via `emit_receipt()`) in addition
to the session JSONL file. This means:

- `assay analyze --history` includes MCP tool call data
- `assay diff` can compare MCP sessions
- `assay explain` works on MCP proof packs

### Claim cards

The existing `receipt_completeness` card works unchanged (checks for receipt
count > 0). A new `mcp_session_completeness` card checks:

- Every `tools/call` request has a matching receipt
- No gaps in sequence numbers
- Session start/end receipts present

### Scanner extension (future)

`assay scan` could detect MCP server configurations that aren't routed
through the proxy. Pattern: find `claude_desktop_config.json` or
`.cursor/mcp.json` and check if commands are wrapped with `assay mcp-proxy`.

---

## Implementation plan

### Phase 1: Stdio proxy + audit profile (target: 2 weeks post-launch)

| File | Work |
|------|------|
| `src/assay/mcp_proxy.py` | Core proxy: stdio forwarding, JSON-RPC parsing, receipt emission |
| `src/assay/commands.py` | `assay mcp-proxy` CLI command |
| `tests/assay/test_mcp_proxy.py` | Mock MCP server (stdin/stdout), receipt verification |

Deliverables:
- [ ] `assay mcp-proxy -- cmd args` works end-to-end
- [ ] MCPToolCallReceipt emitted for every `tools/call`
- [ ] Phase timing fields populated
- [ ] Proof pack auto-built on session end
- [ ] Graceful shutdown with pack on SIGINT
- [ ] Partial pack on crash (best-effort)
- [ ] `assay verify-pack` works on MCP packs
- [ ] 30+ tests (mock MCP server, no real dependency)

### Phase 2: Guard profile + policy (target: 2 weeks after Phase 1)

| File | Work |
|------|------|
| `src/assay/mcp_policy.py` | Policy loading, precedence engine, SSRF guard (fork from bridge.py) |
| `src/assay/mcp_proxy.py` | Policy enforcement in forwarding path |
| `tests/assay/test_mcp_policy.py` | Policy tests (fork from test_bridge.py) |

### Phase 3: SSE transport + pipeline integration (target: 2 weeks after Phase 2)

| File | Work |
|------|------|
| `src/assay/mcp_proxy.py` | SSE transport support |
| `src/assay/run_cards.py` | `mcp_session_completeness` claim card |
| `examples/mcp_proxy_demo/` | Example setup with a real MCP server |

### v2: Decision Escrow profile

Deferred. Requires real-world MCP traffic to discover what permit
constraints mean across different tool types. The `--profile escrow` flag
is reserved but not implemented.

---

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| MCP protocol changes | Pin to `mcp>=1.0.0`, use SDK transport layer |
| Stdio buffering breaks streaming | Use non-blocking I/O, test with streaming tools |
| Large tool outputs (100MB+) | Stream hash computation, don't buffer full output |
| Privacy: args contain secrets | Hash-only by default; `--store-args` is explicit opt-in |
| Privacy: low-entropy brute-force | Document limitation; future `--hash-pepper` for org salt |
| Latency overhead | Target <5ms per tool call (hash + receipt write) |
| Concurrent tool calls | Thread-safe store already done (RLock + flock) |
| Crash before pack | Best-effort partial pack with `session_complete: false` |

## What this does NOT include

- Server-side wrapping (covered by `spec-mcp-receipt-layer.md`)
- Decision Escrow / permit-settle (v2 -- `escrow` profile reserved)
- A2A / Agora / ANP protocol support
- MCP Streamable HTTP transport (Phase 3 at earliest)
- DID-based agent identity
- Real-time alerting on policy violations
- Per-field argument redaction (future: cleartext_fields allowlist)
