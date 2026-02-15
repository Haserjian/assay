# Contributing to Assay

Thanks for your interest. Here's how to help.

## Quick Setup

```bash
git clone https://github.com/Haserjian/assay.git
cd assay
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest tests/assay/ -q
```

## What We Need

- **New RunCards**: Custom claim verifiers for specific use cases
- **Scanner patterns**: Detect more LLM SDK patterns beyond OpenAI/Anthropic/LangChain
- **Integration patches**: More framework integrations (LiteLLM, vLLM, etc.)
- **Bug reports**: Especially edge cases in `verify-pack` and `scan`
- **Documentation**: Tutorials, examples, translations

## How to Contribute

1. Check [Issues](https://github.com/Haserjian/assay/issues) for `good first issue` labels
2. Fork the repo and create a branch
3. Make your changes
4. Run `pytest tests/assay/ -q` (all tests must pass)
5. Open a PR with a clear description of what changed and why

## Code Style

- Python 3.9+ (3.11+ preferred for development)
- Type hints on public functions
- Tests for non-trivial logic
- `ruff` for formatting

## Questions?

Open a [Discussion](https://github.com/Haserjian/assay/discussions).
