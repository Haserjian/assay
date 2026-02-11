# I scanned 30 popular AI projects for tamper-evident audit trails. None had one.

*2026-02-08 | assay-ai v1.2.2*

## TL;DR

- Scanned **30** open-source AI/LLM projects on GitHub
- Found **202** high-confidence LLM SDK call sites (direct `openai`/`anthropic` calls) across 21 projects
- **None** had tamper-evident evidence emission at any call site
- Including heuristic matches: **903** total detected call sites, **0** with Assay-compatible instrumentation
- These projects may have logging or observability elsewhere -- this scan specifically measures cryptographic receipt coverage

## Method limits

> **Read this before interpreting the numbers.**
>
> This is a static AST scan, not runtime tracing. It detects LLM SDK call patterns
> (`client.chat.completions.create`, `anthropic.messages.create`, etc.) and checks for
> [Assay](https://github.com/Haserjian/assay) receipt emission at each call site.
>
> It does **not** detect custom logging, OpenTelemetry, LangSmith callbacks, Datadog integrations,
> or other observability mechanisms. Many of these projects have extensive logging.
> What they don't have is *tamper-evident, cryptographically signed evidence* of what went
> into and came out of each LLM call -- which is what regulators and auditors increasingly need.
>
> Instrumentation detection is file-scoped: a signal in one file does not cover call sites in other files.
>
> Medium/low confidence findings are heuristic. High-confidence findings are direct SDK pattern matches.

## Why this matters

Logging tells you what happened. Tamper-evident evidence *proves* what happened.

The difference matters when someone asks: "Can you prove your AI system did what you said it did?"
With logs, you can show them. With signed receipts, you can *prove* the logs weren't modified after the fact.

This is the gap between observability ("we can see what happened") and
verifiability ("we can prove what happened, cryptographically").

## Method

I used [`assay scan`](https://github.com/Haserjian/assay) -- an AST-based static scanner.

```bash
pip install assay-ai
assay scan .  # run it on your own project
```

Confidence levels:
- **High**: Direct SDK calls (`client.chat.completions.create`, `anthropic.messages.create`)
- **Medium**: Framework calls with import evidence (`ChatOpenAI`, `litellm.completion`, `.invoke` in LangChain files)
- **Low**: Heuristic name matches (`call_llm`, `generate_response`, etc.)

## Results

### High-confidence SDK calls (primary metric)

| Metric | Value |
|--------|-------|
| Repos scanned | 30 |
| Repos with high-confidence LLM calls | 21 |
| High-confidence call sites | 202 |
| With tamper-evident instrumentation | 0 |
| **Coverage** | **0%** |

### All confidence levels (including heuristics)

| Confidence | Call Sites | Description |
|-----------|-----------|-------------|
| High | 202 | Direct SDK calls (OpenAI, Anthropic) |
| Medium | 628 | Framework calls with import context (LangChain, LiteLLM) |
| Low | 73 | Heuristic name matches |
| **Total** | **903** | |

### Per-repo breakdown

| Repo | Stars | High | Medium | Low | Total |
|------|-------|------|--------|-----|-------|
| [run-llama/llama_index](https://github.com/run-llama/llama_index) | 46870 | 38 | 119 | 4 | 161 |
| [agno-agi/agno](https://github.com/agno-agi/agno) | 37673 | 27 | 2 | 0 | 29 |
| [mem0ai/mem0](https://github.com/mem0ai/mem0) | 46901 | 22 | 25 | 18 | 65 |
| [browser-use/browser-use](https://github.com/browser-use/browser-use) | 78027 | 20 | 11 | 0 | 31 |
| [crewAIInc/crewAI](https://github.com/crewAIInc/crewAI) | 43808 | 14 | 4 | 0 | 18 |
| [comet-ml/opik](https://github.com/comet-ml/opik) | 17696 | 13 | 23 | 31 | 67 |
| [langchain-ai/langchain](https://github.com/langchain-ai/langchain) | 126246 | 12 | 195 | 4 | 211 |
| [BerriAI/litellm](https://github.com/BerriAI/litellm) | 35519 | 9 | 52 | 0 | 61 |
| [Doriandarko/claude-engineer](https://github.com/Doriandarko/claude-engineer) | 11166 | 8 | 0 | 0 | 8 |
| [AgentOps-AI/agentops](https://github.com/AgentOps-AI/agentops) | 5274 | 7 | 0 | 0 | 7 |
| [awslabs/agent-squad](https://github.com/awslabs/agent-squad) | 7357 | 5 | 0 | 0 | 5 |
| [griptape-ai/griptape](https://github.com/griptape-ai/griptape) | 2464 | 5 | 0 | 0 | 5 |
| [pydantic/pydantic-ai](https://github.com/pydantic/pydantic-ai) | 14746 | 4 | 0 | 0 | 4 |
| [567-labs/instructor](https://github.com/567-labs/instructor) | 12340 | 4 | 0 | 0 | 4 |
| [gptme/gptme](https://github.com/gptme/gptme) | 4186 | 4 | 1 | 0 | 5 |
| [chatchat-space/Langchain-Chatchat](https://github.com/chatchat-space/Langchain-Chatchat) | 37270 | 3 | 21 | 0 | 24 |
| [stanfordnlp/dspy](https://github.com/stanfordnlp/dspy) | 32084 | 2 | 4 | 0 | 6 |
| [anthropics/anthropic-sdk-python](https://github.com/anthropics/anthropic-sdk-python) | 2735 | 2 | 0 | 0 | 2 |
| [openai/openai-agents-python](https://github.com/openai/openai-agents-python) | 18842 | 1 | 1 | 0 | 2 |
| [kyegomez/swarms](https://github.com/kyegomez/swarms) | 5724 | 1 | 0 | 5 | 6 |
| [Storia-AI/sage](https://github.com/Storia-AI/sage) | 1264 | 1 | 2 | 0 | 3 |
| [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | 24446 | 0 | 56 | 0 | 56 |
| [Aider-AI/aider](https://github.com/Aider-AI/aider) | 40431 | 0 | 3 | 0 | 3 |
| [docker/genai-stack](https://github.com/docker/genai-stack) | 5198 | 0 | 7 | 0 | 7 |
| [shroominic/codeinterpreter-api](https://github.com/shroominic/codeinterpreter-api) | 3865 | 0 | 12 | 1 | 13 |
| [explosion/spacy-llm](https://github.com/explosion/spacy-llm) | 1362 | 0 | 1 | 0 | 1 |
| [TaskingAI/TaskingAI](https://github.com/TaskingAI/TaskingAI) | 5367 | 0 | 0 | 10 | 10 |
| [LearningCircuit/local-deep-research](https://github.com/LearningCircuit/local-deep-research) | 3978 | 0 | 89 | 0 | 89 |

### Top findings (high-confidence only)

**[run-llama/llama_index](https://github.com/run-llama/llama_index)** -- 38 high-confidence call sites

- `llama-index-integrations/agent/llama-index-agent-azure/llama_index/agent/azure_foundry_agent/base.py:175` `self._client.agents.messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `llama-index-integrations/agent/llama-index-agent-azure/llama_index/agent/azure_foundry_agent/base.py:356` `self._client.agents.messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `llama-index-integrations/llms/llama-index-llms-ai21/llama_index/llms/ai21/base.py:245` `self._client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- `llama-index-integrations/llms/llama-index-llms-ai21/llama_index/llms/ai21/base.py:270` `self._async_client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- `llama-index-integrations/llms/llama-index-llms-ai21/llama_index/llms/ai21/base.py:294` `self._async_client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- ... and 33 more high-confidence sites

**[agno-agi/agno](https://github.com/agno-agi/agno)** -- 27 high-confidence call sites

- `libs/agno/agno/models/anthropic/claude.py:604` `beta.messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `libs/agno/agno/models/anthropic/claude.py:611` `messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `libs/agno/agno/models/anthropic/claude.py:730` `beta.messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `libs/agno/agno/models/anthropic/claude.py:737` `messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `libs/agno/agno/models/cerebras/cerebras.py:262` `chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- ... and 22 more high-confidence sites

**[mem0ai/mem0](https://github.com/mem0ai/mem0)** -- 22 high-confidence call sites

- `embedchain/embedchain/evaluation/metrics/answer_relevancy.py:43` `self.client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- `embedchain/embedchain/evaluation/metrics/context_relevancy.py:42` `self.client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- `embedchain/embedchain/evaluation/metrics/groundedness.py:42` `self.client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- `embedchain/embedchain/evaluation/metrics/groundedness.py:63` `self.client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- `embedchain/embedchain/loaders/image.py:29` `self.client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- ... and 17 more high-confidence sites

**[browser-use/browser-use](https://github.com/browser-use/browser-use)** -- 20 high-confidence call sites

- `browser_use/llm/anthropic/chat.py:145` `messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `browser_use/llm/anthropic/chat.py:196` `messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `browser_use/llm/aws/chat_anthropic.py:165` `messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `browser_use/llm/aws/chat_anthropic.py:207` `messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `browser_use/llm/cerebras/chat.py:118` `client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- ... and 15 more high-confidence sites

**[crewAIInc/crewAI](https://github.com/crewAIInc/crewAI)** -- 14 high-confidence call sites

- `lib/crewai-tools/src/crewai_tools/tools/ai_mind_tool/ai_mind_tool.py:94` `openai_client.chat.completions.create` -- fix: `from assay.integrations.openai import patch; patch()`
- `lib/crewai/src/crewai/llms/providers/anthropic/completion.py:676` `self.client.beta.messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `lib/crewai/src/crewai/llms/providers/anthropic/completion.py:680` `self.client.messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `lib/crewai/src/crewai/llms/providers/anthropic/completion.py:1102` `self.client.messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- `lib/crewai/src/crewai/llms/providers/anthropic/completion.py:1197` `self.async_client.beta.messages.create` -- fix: `from assay.integrations.anthropic import patch; patch()`
- ... and 9 more high-confidence sites

## How to add tamper-evident evidence (5 minutes)

### Option 1: One-line patch (OpenAI)

```python
# Add to your entrypoint, before any OpenAI calls:
from assay.integrations.openai import patch; patch()
```

### Option 2: One-line patch (Anthropic)

```python
from assay.integrations.anthropic import patch; patch()
```

### Option 3: One-line patch (LangChain)

```python
from assay.integrations.langchain import patch; patch()
```

### Then verify

```bash
# Run your code through assay -- captures receipts and builds a signed proof pack
assay run -c receipt_completeness -- python your_app.py

# Verify the proof pack (integrity + claims)
assay verify-pack ./proof_pack_*/
```

Every LLM call now produces a cryptographically signed receipt.
The proof pack is a 5-file evidence bundle: receipts, manifest, signature, verification report, and transcript.

## Try it yourself

```bash
pip install assay-ai
assay scan .          # find uninstrumented call sites
assay doctor          # check your setup
assay demo-pack       # see a complete proof pack (no API key needed)
```

## How to challenge this

If you think your project has tamper-evident evidence emission and this scan missed it,
[open an issue](https://github.com/Haserjian/assay/issues) with:

- A commit link to the instrumentation code
- The evidence emission pattern (signed receipts, hash chains, etc.)

I'll verify it and update the dataset. The goal is accuracy, not a gotcha.

If you think a finding is a false positive (e.g., `.invoke()` on a non-LLM object),
same process -- open an issue with the file and line.

## Reproduce this study

```bash
git clone https://github.com/Haserjian/assay.git
cd assay
pip install -e .
cd scripts/scan_study
./run_study.sh                 # clone 30 repos, scan each, aggregate
python generate_report.py      # generate report.md from results.csv
```

Artifacts:
- `results/results.csv` -- per-repo metrics with commit SHAs
- `results/summary.json` -- aggregate stats with tool version
- `results/*.json` -- per-repo scan detail (30 files)
- `results/report.md` -- this report

Full source and docs: [github.com/Haserjian/assay](https://github.com/Haserjian/assay)
