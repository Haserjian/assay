"""
Assay integrations for common AI frameworks.

Drop-in wrappers that make every AI call emit a receipt automatically.

Usage:
    from assay.integrations.openai import patch
    patch()  # Now every OpenAI call emits a receipt

    from assay.integrations.anthropic import patch
    patch()  # Now every Anthropic call emits a receipt

    from assay.integrations.langchain import AssayCallbackHandler
    llm = ChatOpenAI(callbacks=[AssayCallbackHandler()])
"""

__all__ = []
