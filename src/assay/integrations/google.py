"""
Google Gemini integration for Assay.

Drop-in wrapper that emits ModelCallReceipt for every Gemini API call.
Patches google.generativeai.GenerativeModel.generate_content (sync)
and generate_content_async (async).

Usage:
    from assay.integrations.google import patch
    patch()

    import google.generativeai as genai
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content("Hello!")
    # Receipt automatically emitted

Configuration:
    patch(
        store_prompts=False,   # Default: hash prompts, don't store content
        store_responses=False, # Default: hash responses, don't store content
        trace_id=None,         # Optional: use existing trace
    )
"""
from __future__ import annotations

import hashlib
import time
import uuid
from functools import wraps
from typing import Any, Callable, Dict, Optional

# Global state
_original_generate: Optional[Callable] = None
_original_generate_async: Optional[Callable] = None
_patch_config: Dict[str, Any] = {}
_patched = False


def _hash_content(content: str) -> str:
    """Hash content for privacy-preserving logging."""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _extract_input_hash(contents: Any) -> str:
    """Extract a privacy-preserving hash from Gemini input contents."""
    if isinstance(contents, str):
        return _hash_content(contents)
    if isinstance(contents, (list, tuple)):
        parts = []
        for item in contents:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("text", "") or item.get("parts", "")))
            else:
                # Pydantic or proto object
                parts.append(str(getattr(item, "text", "") or getattr(item, "parts", "")))
        return _hash_content("".join(parts))
    return _hash_content(str(contents))


def _extract_output_text(response: Any) -> Optional[str]:
    """Extract text from a Gemini GenerateContentResponse."""
    if response is None:
        return None
    try:
        return response.text
    except (AttributeError, ValueError):
        pass
    # Fallback: iterate candidates
    try:
        candidates = getattr(response, "candidates", None)
        if candidates:
            parts = getattr(candidates[0].content, "parts", [])
            texts = [getattr(p, "text", "") for p in parts if hasattr(p, "text")]
            return "".join(texts) if texts else None
    except Exception:
        pass
    return None


def _infer_message_count(contents: Any) -> int:
    """Best-effort message count for Gemini input."""
    if contents is None:
        return 0
    if isinstance(contents, str):
        return 1
    if isinstance(contents, (list, tuple)):
        return len(contents)
    return 1


def _create_model_call_receipt(
    model: str,
    contents: Any,
    response: Any,
    latency_ms: int,
    error: Optional[str] = None,
    callsite_file: Optional[str] = None,
    callsite_line: Optional[int] = None,
    callsite_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a model_call receipt from a Gemini call."""
    from assay.store import emit_receipt

    input_tokens = 0
    output_tokens = 0
    finish_reason = "error" if error else "stop"
    response_hash = None

    if response and hasattr(response, "usage_metadata") and response.usage_metadata:
        meta = response.usage_metadata
        input_tokens = getattr(meta, "prompt_token_count", 0) or 0
        output_tokens = getattr(meta, "candidates_token_count", 0) or 0

    # Extract finish reason from candidates
    if response and hasattr(response, "candidates") and response.candidates:
        candidate = response.candidates[0]
        fr = getattr(candidate, "finish_reason", None)
        if fr is not None:
            # Gemini uses enum integers or strings
            fr_str = str(fr)
            if "STOP" in fr_str:
                finish_reason = "stop"
            elif "MAX_TOKENS" in fr_str:
                finish_reason = "length"
            elif "SAFETY" in fr_str:
                finish_reason = "safety"
            else:
                finish_reason = fr_str.lower()

    response_text = _extract_output_text(response)
    if response_text is not None:
        response_hash = _hash_content(response_text)

    data: Dict[str, Any] = {
        "provider": "google",
        "model_id": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "latency_ms": latency_ms,
        "finish_reason": finish_reason,
        "error": error,
        "input_hash": _extract_input_hash(contents),
        "output_hash": response_hash,
        "message_count": _infer_message_count(contents),
        "integration_source": "assay.integrations.google",
    }

    if _patch_config.get("store_prompts"):
        if isinstance(contents, str):
            data["input_content"] = [{"role": "user", "content": contents}]
        else:
            data["input_content"] = contents
    if _patch_config.get("store_responses") and response_text is not None:
        data["output_content"] = response_text

    if callsite_file is not None:
        data["callsite_file"] = callsite_file
    if callsite_line is not None:
        data["callsite_line"] = callsite_line
    if callsite_id is not None:
        data["callsite_id"] = callsite_id

    return emit_receipt(
        "model_call",
        data,
        receipt_id=f"mcr_{uuid.uuid4().hex[:16]}",
    )


def _wrapped_generate(original: Callable) -> Callable:
    """Wrap GenerativeModel.generate_content to emit receipts."""

    @wraps(original)
    def wrapper(*args, **kwargs):
        from assay.integrations import find_caller_frame
        caller_file, caller_line = find_caller_frame()
        caller_id = None
        if caller_file is not None and caller_line is not None:
            from assay.coverage import compute_callsite_id
            caller_id = compute_callsite_id(caller_file, caller_line)

        start_time = time.time()
        error = None
        response = None

        # args[0] is self (GenerativeModel instance)
        model_name = "unknown"
        if args:
            model_name = getattr(args[0], "model_name", None) or getattr(args[0], "_model_name", "unknown")
        contents = args[1] if len(args) > 1 else kwargs.get("contents", "")

        try:
            response = original(*args, **kwargs)
            return response
        except Exception as e:
            error = str(e)
            raise
        finally:
            latency_ms = int((time.time() - start_time) * 1000)
            try:
                _create_model_call_receipt(
                    model=model_name,
                    contents=contents,
                    response=response,
                    latency_ms=latency_ms,
                    error=error,
                    callsite_file=caller_file,
                    callsite_line=caller_line,
                    callsite_id=caller_id,
                )
            except Exception as exc:
                import warnings
                warnings.warn(
                    f"assay: receipt emission failed: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    return wrapper


def _wrapped_generate_async(original: Callable) -> Callable:
    """Wrap GenerativeModel.generate_content_async to emit receipts."""

    @wraps(original)
    async def wrapper(*args, **kwargs):
        from assay.integrations import find_caller_frame
        caller_file, caller_line = find_caller_frame()
        caller_id = None
        if caller_file is not None and caller_line is not None:
            from assay.coverage import compute_callsite_id
            caller_id = compute_callsite_id(caller_file, caller_line)

        start_time = time.time()
        error = None
        response = None

        model_name = "unknown"
        if args:
            model_name = getattr(args[0], "model_name", None) or getattr(args[0], "_model_name", "unknown")
        contents = args[1] if len(args) > 1 else kwargs.get("contents", "")

        try:
            response = await original(*args, **kwargs)
            return response
        except Exception as e:
            error = str(e)
            raise
        finally:
            latency_ms = int((time.time() - start_time) * 1000)
            try:
                _create_model_call_receipt(
                    model=model_name,
                    contents=contents,
                    response=response,
                    latency_ms=latency_ms,
                    error=error,
                    callsite_file=caller_file,
                    callsite_line=caller_line,
                    callsite_id=caller_id,
                )
            except Exception as exc:
                import warnings
                warnings.warn(
                    f"assay: receipt emission failed: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    return wrapper


def patch(
    store_prompts: bool = False,
    store_responses: bool = False,
    trace_id: Optional[str] = None,
) -> None:
    """
    Patch Google Gemini client to emit receipts for every call.

    Args:
        store_prompts: If True, store full prompt content. Default False (hash only).
        store_responses: If True, store full response content. Default False (hash only).
        trace_id: Optional trace ID to append to. Default: create new trace.

    Example:
        from assay.integrations.google import patch
        patch()

        import google.generativeai as genai
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content("Hello!")
        # Receipt automatically emitted
    """
    global _original_generate, _original_generate_async
    global _patch_config, _patched

    if _patched:
        return

    try:
        import google.generativeai as genai  # noqa: F401
        from google.generativeai import GenerativeModel
    except ImportError:
        raise ImportError(
            "google-generativeai package not installed. "
            "Install with: pip install google-generativeai"
        )

    _patch_config = {
        "store_prompts": store_prompts,
        "store_responses": store_responses,
        "trace_id": trace_id,
    }

    from assay.store import get_default_store
    store = get_default_store()
    if trace_id:
        store.start_trace(trace_id)
    else:
        store.start_trace()

    _original_generate = GenerativeModel.generate_content
    GenerativeModel.generate_content = _wrapped_generate(_original_generate)

    if hasattr(GenerativeModel, "generate_content_async"):
        _original_generate_async = GenerativeModel.generate_content_async
        GenerativeModel.generate_content_async = _wrapped_generate_async(_original_generate_async)

    _patched = True


def unpatch() -> None:
    """Remove the Google Gemini patch."""
    global _original_generate, _original_generate_async, _patched

    if not _patched:
        return

    try:
        from google.generativeai import GenerativeModel

        if _original_generate:
            GenerativeModel.generate_content = _original_generate
        if _original_generate_async and hasattr(GenerativeModel, "generate_content_async"):
            GenerativeModel.generate_content_async = _original_generate_async
    except ImportError:
        pass

    _patched = False
    _original_generate = None
    _original_generate_async = None


def get_trace_id() -> Optional[str]:
    """Get the current trace ID being used for receipts."""
    from assay.store import get_default_store
    store = get_default_store()
    return store.current_trace_id if hasattr(store, "current_trace_id") else None


__all__ = ["patch", "unpatch", "get_trace_id"]
