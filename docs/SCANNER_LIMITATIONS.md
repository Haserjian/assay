# Scanner Limitations

`assay scan` uses Python AST (Abstract Syntax Tree) analysis to detect
LLM API calls in source files. This approach is deterministic and fast
but has inherent blind spots.

---

## What the scanner detects

The scanner recognizes direct SDK calls at three confidence levels:

- **HIGH**: `openai.chat.completions.create()`, `anthropic.messages.create()`,
  `generate_content()`, `generate_content_async()`
- **MEDIUM**: LangChain `.invoke()` / `.ainvoke()`, LiteLLM `completion()`,
  constructor calls (`ChatOpenAI()`, `ChatAnthropic()`)
- **LOW**: Heuristic function name matches (`call_llm`, `query_model`, etc.)

All detection is based on static AST node matching against known call patterns.

---

## Known evasion patterns

The following patterns are **not detectable** by AST-based scanning.
A codebase using any of these idioms will produce a false-clean scan report.

### 1. Dynamic dispatch via `getattr`

```python
method_name = "create"
getattr(client.chat.completions, method_name)(messages=[...])
```

The call target is resolved at runtime. The AST sees `getattr(...)()`,
not `client.chat.completions.create()`.

### 2. String execution via `eval` / `exec`

```python
eval(f"client.chat.completions.create(messages={msgs!r})")
```

The call is constructed as a string and executed dynamically.
The AST sees `eval(...)`, not the underlying API call.

### 3. Subprocess delegation

```python
subprocess.run(["python", "-c", "import openai; openai.chat.completions.create(...)"])
```

The LLM call happens in a child process. The parent's AST contains
only `subprocess.run(...)`.

### 4. Raw HTTP calls to API endpoints

```python
requests.post(
    "https://api.openai.com/v1/chat/completions",
    headers={"Authorization": f"Bearer {api_key}"},
    json={"model": "gpt-4o", "messages": [...]},
)
```

The scanner detects SDK method calls, not HTTP requests. A raw
`requests.post()` or `httpx.post()` to an LLM API endpoint is
invisible to pattern-based AST scanning.

---

## Why these are fundamental limits

These patterns are not bugs in the scanner — they are inherent limits
of static analysis on a dynamic language. Python's runtime dispatch
(`getattr`, `eval`, `exec`) and process-boundary calls (`subprocess`)
are opaque to any tool that operates on the AST alone.

---

## Mitigations

- **Runtime instrumentation** (e.g., `assay patch` with monkey-patching)
  can intercept SDK calls at runtime regardless of how they are dispatched.
  This covers patterns 1 and 2 but not 3 or 4.
- **HTTP-layer interception** (proxy or network monitor) could detect
  pattern 4 by matching outbound requests to known LLM API domains.
  This is not currently implemented.
- **Subprocess delegation** (pattern 3) is not reliably detectable
  without process-tree instrumentation.

These mitigations are future work. The current scanner makes no claim
to detect them.

---

## Recommendations

When `assay scan` reports a clean result, interpret it as:

> "No LLM calls were found via static AST pattern matching.
> Dynamic dispatch, eval, subprocess, and raw HTTP calls are not covered."

If your codebase uses any of the above patterns, supplement `assay scan`
with runtime instrumentation (`assay patch`) for coverage.
