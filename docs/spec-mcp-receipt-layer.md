# MCP Receipt Layer Spec

**Status**: Implementation spec
**Feature**: `assay-mcp` -- receipt emission for MCP tool invocations
**Prerequisite**: Thread-safe store (Workstream A)
**Depends on**: `emit_receipt()` from `store.py`, `bridge.py` receipt patterns

---

## Problem

MCP (Model Context Protocol) has 13,000+ servers. 82% have file system
vulnerabilities. 53% use static secrets. No tool produces tamper-evident
audit trails for MCP tool invocations.

Assay's `bridge.py` already emits `BridgeDenial` and `BridgeExecution`
receipts for tool calls. The MCP layer extends this pattern to MCP's
protocol surface.

## What ships

### Package

```bash
pip install assay-ai[mcp]
```

Optional dependency: `mcp>=1.0.0` (the official MCP Python SDK).

**pyproject.toml addition:**
```toml
[project.optional-dependencies]
mcp = ["mcp>=1.0.0"]
```

### New files

```
src/assay/integrations/mcp.py       # MCP middleware (receipt emission)
src/assay/integrations/mcp_policy.py # Tool allowlist / deny policy (optional)
tests/assay/test_mcp_integration.py  # Tests (no MCP server needed)
```

---

## Architecture

### Integration pattern

MCP servers expose tools via `@server.tool()` decorators. The Assay MCP
layer wraps tool handlers to emit receipts before and after execution.

Two integration modes:

**Mode 1: Decorator wrapper (recommended)**

```python
from mcp.server import Server
from assay.integrations.mcp import assay_mcp_wrap

server = Server("my-server")
assay_mcp_wrap(server)  # wraps all registered tools

# That's it. Every tool call now emits receipts.
```

**Mode 2: Manual per-tool wrapping**

```python
from assay.integrations.mcp import mcp_receipt

@server.tool()
@mcp_receipt()
async def web_search(query: str) -> str:
    ...
```

### Receipt lifecycle (per tool call)

```
Client sends tool invocation
    |
    v
[1] Emit "mcp_tool_requested" receipt
    - tool_name, arguments_hash, actor, server_id, timestamp
    |
    v
[2] Policy check (optional)
    - If policy loaded: check allowlist/denylist
    - If denied: emit "mcp_tool_denied" receipt, return error
    |
    v
[3] Execute original handler
    |
    v
[4] Emit "mcp_tool_executed" receipt
    - outcome, result_hash, duration_ms, error (if any)
    |
    v
Return result to client
```

This mirrors bridge.py's BridgeDenial / BridgeExecution pattern but adds
the "requested" receipt to capture intent before execution.

---

## Receipt schemas

### Correlation contract

All three MCP receipts share stable correlation IDs for audit joins:

- **`invocation_id`**: Unique per tool invocation. Generated once in
  `mcp_tool_requested`, carried through to `denied` or `executed`.
  Format: `inv_<uuid16>`. This is the join key for reconstructing
  the full lifecycle of a single tool call.
- **`request_receipt_id`**: Points back to the `mcp_tool_requested`
  receipt. Present in `denied` and `executed` receipts.
- **`decision_receipt_id`**: Present only in `mcp_tool_executed`.
  Points to the `mcp_tool_denied` receipt if the tool was initially
  denied and then retried, or `null` if no denial preceded execution.

These three IDs enable audit joins without scanning all receipts:
```sql
-- Reconstruct a tool call lifecycle
SELECT * FROM receipts WHERE invocation_id = 'inv_abc123'
ORDER BY seq;
```

### Privacy posture (redaction by default)

**Default:** All tool arguments and results are hashed, never stored
in cleartext. This is the same privacy model as the OpenAI/Anthropic
integrations (`input_hash` / `output_hash`).

**Opt-in cleartext** requires explicit field allowlists:

```python
assay_mcp_wrap(
    server,
    store_arguments=False,      # default: hash only
    store_results=False,         # default: hash only
    cleartext_fields={           # NEW: per-field allowlist
        "web_search": ["query"],          # store query but hash everything else
        "read_file": ["path"],            # store path but hash content
    },
)
```

When `cleartext_fields` is set for a tool, only listed argument fields
appear in cleartext. All other fields are replaced with their SHA-256
hash. This prevents accidental PII/secret leakage while allowing
auditors to see operationally relevant metadata.

**Redaction function:**
```python
def _redact_arguments(tool_name: str, arguments: dict, allowlist: dict) -> dict:
    """Return arguments with non-allowlisted fields replaced by hashes."""
    allowed = allowlist.get(tool_name, set())
    redacted = {}
    for key, value in arguments.items():
        if key in allowed:
            redacted[key] = value
        else:
            redacted[key] = f"sha256:{_sha256_json(value)}"
    return redacted
```

### mcp_tool_requested

Emitted when a tool invocation is received, before policy check or execution.

```python
{
    "type": "mcp_tool_requested",
    "receipt_id": "mtr_<uuid16>",
    "timestamp": "2026-03-15T11:30:00.000Z",
    "schema_version": "3.0",
    "seq": N,

    # Correlation
    "invocation_id": "inv_<uuid16>",        # Unique per tool call

    # MCP context
    "server_id": "my-server@1.0.0",
    "server_transport": "stdio|sse|streamable-http",
    "tool_name": "web_search",
    "arguments_hash": "sha256:<hex>",       # SHA-256 of JCS(full arguments)
    "actor": "claude-code|cursor|custom",   # from MCP client info if available
    "session_id": "mcp_session_<id>",       # MCP session identifier

    # Redacted arguments (privacy-by-default)
    "arguments_redacted": {                 # Only allowlisted fields in cleartext
        "query": "climate change effects",  # Allowed field
        "max_results": "sha256:abc123..."   # Non-allowed field, hashed
    },

    # Full cleartext (opt-in only, off by default)
    "arguments_content": null,              # Set if store_arguments=True

    # Integration metadata
    "integration_source": "assay.integrations.mcp",
}
```

### mcp_tool_denied

Emitted when policy denies execution. Terminal receipt for this invocation.

```python
{
    "type": "mcp_tool_denied",
    "receipt_id": "mtd_<uuid16>",
    "timestamp": "2026-03-15T11:30:00.001Z",
    "schema_version": "3.0",
    "seq": N,

    # Correlation
    "invocation_id": "inv_<uuid16>",        # Same as request
    "request_receipt_id": "mtr_<uuid16>",   # Link to request

    # MCP context
    "server_id": "my-server@1.0.0",
    "tool_name": "web_search",
    "arguments_hash": "sha256:<hex>",

    # Denial
    "denied": true,
    "denial_reason": "Tool not in allowlist",
    "policy_ref": "POLICY_MCP_DENY_001",
    "policy_hash": "sha256:<hex>",          # Hash of active policy

    "integration_source": "assay.integrations.mcp",
}
```

### mcp_tool_executed

Emitted after execution completes (success or error).

```python
{
    "type": "mcp_tool_executed",
    "receipt_id": "mte_<uuid16>",
    "timestamp": "2026-03-15T11:30:00.234Z",
    "schema_version": "3.0",
    "seq": N,

    # Correlation
    "invocation_id": "inv_<uuid16>",        # Same as request
    "request_receipt_id": "mtr_<uuid16>",   # Link to request
    "decision_receipt_id": null,            # Link to denial if retried

    # MCP context
    "server_id": "my-server@1.0.0",
    "tool_name": "web_search",
    "arguments_hash": "sha256:<hex>",

    # Execution result
    "outcome": "success|error|timeout",
    "duration_ms": 234,
    "result_hash": "sha256:<hex>",          # SHA-256 of JCS(result)
    "result_is_error": false,               # MCP isError flag
    "error": null,                          # Error message if outcome != success

    # Redacted result (privacy-by-default)
    "result_redacted": null,                # Per-field redaction if configured

    # Full cleartext (opt-in only)
    "result_content": null,                 # Set if store_results=True

    # Policy (if policy was checked)
    "policy_hash": "sha256:<hex>",

    "integration_source": "assay.integrations.mcp",
}
```

### Receipt ID prefixes

| Type | Prefix | Example |
|------|--------|---------|
| model_call | `mcr_` | `mcr_a1b2c3d4e5f6g7h8` |
| mcp_tool_requested | `mtr_` | `mtr_a1b2c3d4e5f6g7h8` |
| mcp_tool_denied | `mtd_` | `mtd_a1b2c3d4e5f6g7h8` |
| mcp_tool_executed | `mte_` | `mte_a1b2c3d4e5f6g7h8` |
| bridge_denial | `bd_` | `bd_a1b2c3d4e5f6g7h8` |
| bridge_execution | `be_` | `be_a1b2c3d4e5f6g7h8` |

---

## Tool policy (optional)

### Policy file: `assay.mcp-policy.yaml`

```yaml
version: "1"

# Default: deny-all (most secure) or allow-all (most permissive)
default: deny

allowlist:
  - web_search
  - web_fetch
  - read_file

denylist:
  - shell_exec
  - file_delete

# Per-tool constraints (future)
constraints:
  web_fetch:
    deny_private_hosts: true    # SSRF guard
  read_file:
    allowed_paths:
      - "/workspace/*"
      - "!**/.env"              # Exclude secrets
```

### Policy loading

```python
from assay.integrations.mcp_policy import MCPToolPolicy

policy = MCPToolPolicy.from_file("assay.mcp-policy.yaml")
assay_mcp_wrap(server, policy=policy)
```

If no policy is provided, all tools are allowed (receipts still emitted).
Policy is optional; receipt emission is always on.

---

## MCP wrapper implementation

### Core: `assay_mcp_wrap()`

```python
def assay_mcp_wrap(
    server: "mcp.server.Server",
    *,
    policy: Optional[MCPToolPolicy] = None,
    store_arguments: bool = False,
    store_results: bool = False,
    trace_id: Optional[str] = None,
    server_id: Optional[str] = None,
) -> None:
    """Wrap all registered MCP tools to emit Assay receipts.

    Args:
        server: MCP Server instance with tools already registered.
        policy: Optional tool policy for allow/deny decisions.
        store_arguments: If True, include raw arguments in receipts.
        store_results: If True, include raw results in receipts.
        trace_id: Optional trace ID (auto-generated if None).
        server_id: Server identifier (defaults to server.name).
    """
```

**Implementation approach:**

1. Iterate over `server._tools` (the registered tool handlers)
2. For each tool, replace handler with a wrapper that:
   a. Emits `mcp_tool_requested` receipt
   b. Checks policy (if provided)
   c. If denied: emits `mcp_tool_denied`, returns MCP error
   d. If allowed: calls original handler
   e. Emits `mcp_tool_executed` receipt in `finally` block
3. Wrapper is async-compatible (MCP handlers are async)

**Key implementation details:**

- Arguments hashed with `_sha256_jcs(arguments)` for privacy-by-default
- Result hashed with `_sha256_jcs(result)` similarly
- Timing captured around handler execution only (not including receipt emission)
- Receipt emission failures are caught and warned, never crash the server
- Server transport detected from server config if available

### Per-tool decorator: `@mcp_receipt()`

```python
def mcp_receipt(
    *,
    policy: Optional[MCPToolPolicy] = None,
    store_arguments: bool = False,
    store_results: bool = False,
):
    """Decorator for individual MCP tool handlers."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Same receipt lifecycle as assay_mcp_wrap
            ...
        return wrapper
    return decorator
```

---

## Session packing

### Session lifecycle

```
MCP session starts
    |
    v
assay_mcp_wrap() starts trace (ASSAY_TRACE_ID)
    |
    v
Tool calls emit receipts to trace
    |
    v
MCP session ends (or pack_session() called)
    |
    v
Build proof pack from trace receipts
```

### Manual session packing

```python
from assay.integrations.mcp import pack_mcp_session

# At session end or on demand:
pack_path = pack_mcp_session(
    trace_id=trace_id,          # From the active session
    output_dir="./proof_packs", # Where to write
    claims=["receipt_completeness"],  # Optional claim cards
)
```

### Automatic session packing (optional)

```python
assay_mcp_wrap(server, auto_pack=True, pack_dir="./proof_packs")
```

When `auto_pack=True`, a proof pack is built when:
- The MCP session closes gracefully
- `SIGTERM` / `SIGINT` is received
- A configurable receipt count threshold is hit (rolling packs)

---

## Coverage metric

### MCP escrow completeness

For every tool invocation, a "complete escrow chain" means:
1. `mcp_tool_requested` receipt exists
2. Either `mcp_tool_denied` OR `mcp_tool_executed` receipt exists
3. Receipts are linked by `request_receipt_id`

**Coverage = (complete chains) / (total requested receipts)**

This maps to the `receipt_completeness` claim card. The existing card
checks that receipts exist; the MCP extension checks that receipt *pairs*
are complete.

### New claim: `mcp_escrow_completeness`

```python
# Run card definition
{
    "card_id": "mcp_escrow_completeness",
    "description": "Every MCP tool request has a matching execution or denial receipt",
    "checks": [
        {
            "check_id": "escrow_chain_complete",
            "description": "All mcp_tool_requested have matching outcome receipt",
            "threshold": 1.0,  # 100% by default
        }
    ]
}
```

Usage:
```bash
assay run -c receipt_completeness -c mcp_escrow_completeness -- python my_mcp_server.py
```

---

## CI integration

### Example workflow

```yaml
name: MCP Server Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install
        run: pip install assay-ai[mcp] -e .

      - name: Run MCP server with test client
        run: |
          assay run \
            -c receipt_completeness \
            -c mcp_escrow_completeness \
            -- python test_mcp_client.py

      - name: Verify proof pack
        run: assay verify-pack ./proof_pack_*/

      - name: Diff against baseline
        run: |
          assay diff ./baseline_pack/ ./proof_pack_*/ \
            --gates assay.gates.yaml \
            --report gate_report.html

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: mcp-audit-pack
          path: |
            proof_pack_*/
            gate_report.html
```

### Reference MCP server (for testing/demos)

Ship a minimal example MCP server with Assay receipts:

```
examples/
  mcp_demo_server/
    server.py           # 3-tool MCP server (web_search, read_file, echo)
    assay.gates.yaml    # Sample gate policy
    assay.mcp-policy.yaml  # Sample tool policy
    test_client.py      # Test harness that exercises all tools
    README.md           # "Add receipts to your MCP server in 15 minutes"
```

---

## Implementation plan

### Phase 1: Core receipt emission (1 week)

| File | Work |
|------|------|
| `src/assay/integrations/mcp.py` | `assay_mcp_wrap()`, `@mcp_receipt()`, receipt emission for all 3 types |
| `tests/assay/test_mcp_integration.py` | Unit tests with mock MCP server (no real MCP dependency needed for core tests) |

**Test strategy:** Mock the MCP server tool registration interface.
Verify receipt fields, linking, hashing, timing. No actual MCP transport.

### Phase 2: Policy + session packing (1 week)

| File | Work |
|------|------|
| `src/assay/integrations/mcp_policy.py` | `MCPToolPolicy`, YAML loading, allow/deny/constraints |
| `src/assay/integrations/mcp.py` | `pack_mcp_session()`, auto-pack on session close |
| `tests/assay/test_mcp_policy.py` | Policy file loading, allow/deny, SSRF guard |

### Phase 3: Claim card + example server (3-5 days)

| File | Work |
|------|------|
| `src/assay/run_cards.py` | Add `mcp_escrow_completeness` card |
| `examples/mcp_demo_server/` | Reference server, test client, README |
| `pyproject.toml` | Add `mcp` optional dependency |

### Phase 4: CI integration + docs (2-3 days)

| File | Work |
|------|------|
| `docs/mcp-integration.md` | Integration guide |
| Template CI workflow | GitHub Actions example |

---

## Thread safety prerequisite

The current `AssayStore` is NOT thread-safe:
- No locks on file writes
- Global `_seq_counter` is unprotected
- Global `_default_store` is unprotected

MCP servers handle concurrent requests. Receipt emission MUST be
thread-safe before shipping.

**Minimum fix:**
```python
import threading

class AssayStore:
    def __init__(self, base_dir=None):
        ...
        self._lock = threading.Lock()

    def append_dict(self, data):
        with self._lock:
            # existing write logic
            ...
```

Also protect `_seq_counter` and `_default_store` with module-level locks.

This is Workstream A item 1. Must ship before MCP layer.

---

## Exit criteria

- [ ] `assay_mcp_wrap(server)` instruments all tools with zero config
- [ ] Three receipt types emitted per tool call lifecycle
- [ ] Receipts linked by `request_receipt_id`
- [ ] Policy allow/deny works with YAML file
- [ ] Denied tools emit denial receipt, not just error
- [ ] `pack_mcp_session()` builds valid proof pack from session
- [ ] `mcp_escrow_completeness` claim card verifies chain completeness
- [ ] Coverage metric: % of tool calls with complete escrow chain
- [ ] Example server works end-to-end: start -> tool calls -> pack -> verify
- [ ] Thread-safe store (prerequisite, separate PR)
- [ ] No MCP dependency required for core assay-ai install
- [ ] All existing tests pass (745+)
- [ ] 30+ new tests for MCP layer

---

## What this does NOT include (deferred)

- MCP client-side instrumentation (only server-side for v0)
- A2A / Agora / ANP protocol support
- Per-tool cost estimation (MCP tools don't have standard pricing)
- Real-time streaming receipt emission (batch at tool completion)
- Policy composition / hierarchical policies (MAPL-style)
- DID-based agent identity (future trust tier)
