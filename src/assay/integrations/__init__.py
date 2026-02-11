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
from __future__ import annotations

import inspect
import os
from typing import Optional, Tuple


def find_caller_frame() -> Tuple[Optional[str], Optional[int]]:
    """Find the first call frame outside ``assay.*``.

    Walks ``inspect.stack(0)`` (context=0 to avoid reading source files)
    and returns ``(relative_path, line_number)`` for the first frame whose
    module is NOT in the ``assay`` package.

    Returns ``(None, None)`` if no suitable frame is found (graceful
    degradation -- callsite fields simply won't be added to the receipt).
    """
    try:
        frames = inspect.stack(0)
    except Exception:
        return None, None

    try:
        for frame_info in frames:
            module = frame_info.frame.f_globals.get("__name__", "")
            if module.startswith("assay.") or module == "assay":
                continue
            filename = frame_info.filename
            if not filename or filename == "<string>":
                continue
            # Convert to relative path from CWD
            try:
                rel = os.path.relpath(filename)
            except ValueError:
                rel = filename
            return rel, frame_info.lineno
    finally:
        del frames  # avoid reference cycles

    return None, None


__all__ = ["find_caller_frame"]
