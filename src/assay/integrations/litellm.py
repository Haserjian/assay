"""
LiteLLM integration for Assay.

Drop-in wrapper that emits ModelCallReceipt for every LiteLLM call.
Patches litellm.completion (sync) and litellm.acompletion (async).

LiteLLM returns OpenAI-compatible ModelResponse objects, so token
extraction follows the OpenAI pattern.

Usage:
    from assay.integrations.litellm import patch
    patch()

    import litellm
    response = litellm.completion(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello!"}],
    )
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
_original_completion: Optional[Callable] = None
_original_acompletion: Optional[Callable] = None
_patch_config: Dict[str, Any] = {}
_patched = False


def _hash_content(content: str) -> str:
    """Hash content for privacy-preserving logging."""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _extract_messages_hash(messages: list) -> str:
    """Extract a privacy-preserving hash of messages."""
    content = ""
    for msg in messages:
        if isinstance(msg, dict):
            content += msg.get("role", "") + msg.get("content", "")
        else:
            content += getattr(msg, "role", "") + getattr(msg, "content", "")
    return _hash_content(content)


def _create_model_call_receipt(
    model: str,
    messages: list,
    response: Any,
    latency_ms: int,
    error: Optional[str] = None,
    callsite_file: Optional[str] = None,
    callsite_line: Optional[int] = None,
    callsite_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a model_call receipt from a LiteLLM call.

    LiteLLM returns OpenAI-compatible ModelResponse objects.
    """
    from assay.store import emit_receipt

    input_tokens = 0
    output_tokens = 0
    finish_reason = "error" if error else "stop"
    response_hash = None

    if response and hasattr(response, "usage") and response.usage:
        usage = response.usage
        input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        output_tokens = getattr(usage, "completion_tokens", 0) or 0

    response_text = None
    if response and hasattr(response, "choices") and response.choices:
        choice = response.choices[0]
        finish_reason = getattr(choice, "finish_reason", None) or "stop"
        if hasattr(choice, "message") and choice.message:
            response_text = getattr(choice.message, "content", "") or ""
            response_hash = _hash_content(response_text)

    data: Dict[str, Any] = {
        "provider": "litellm",
        "model_id": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "latency_ms": latency_ms,
        "finish_reason": finish_reason,
        "error": error,
        "input_hash": _extract_messages_hash(messages),
        "output_hash": response_hash,
        "message_count": len(messages),
        "integration_source": "assay.integrations.litellm",
    }

    if _patch_config.get("store_prompts"):
        data["input_content"] = [
            {"role": m.get("role", ""), "content": m.get("content", "")}
            if isinstance(m, dict)
            else {"role": getattr(m, "role", ""), "content": getattr(m, "content", "")}
            for m in messages
        ]
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


def _wrapped_completion(original: Callable) -> Callable:
    """Wrap litellm.completion to emit receipts."""

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

        model = kwargs.get("model") or (args[0] if args else "unknown")
        messages = kwargs.get("messages", [])

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
                    model=model,
                    messages=messages,
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


def _wrapped_acompletion(original: Callable) -> Callable:
    """Wrap litellm.acompletion to emit receipts."""

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

        model = kwargs.get("model") or (args[0] if args else "unknown")
        messages = kwargs.get("messages", [])

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
                    model=model,
                    messages=messages,
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
    Patch LiteLLM to emit receipts for every call.

    Args:
        store_prompts: If True, store full prompt content. Default False (hash only).
        store_responses: If True, store full response content. Default False (hash only).
        trace_id: Optional trace ID to append to. Default: create new trace.

    Example:
        from assay.integrations.litellm import patch
        patch()

        import litellm
        response = litellm.completion(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello!"}],
        )
        # Receipt automatically emitted
    """
    global _original_completion, _original_acompletion
    global _patch_config, _patched

    if _patched:
        return

    try:
        import litellm  # noqa: F401
    except ImportError:
        raise ImportError(
            "litellm package not installed. Install with: pip install litellm"
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

    _original_completion = litellm.completion
    litellm.completion = _wrapped_completion(_original_completion)

    if hasattr(litellm, "acompletion"):
        _original_acompletion = litellm.acompletion
        litellm.acompletion = _wrapped_acompletion(_original_acompletion)

    _patched = True


def unpatch() -> None:
    """Remove the LiteLLM patch."""
    global _original_completion, _original_acompletion, _patched

    if not _patched:
        return

    try:
        import litellm

        if _original_completion:
            litellm.completion = _original_completion
        if _original_acompletion and hasattr(litellm, "acompletion"):
            litellm.acompletion = _original_acompletion
    except ImportError:
        pass

    _patched = False
    _original_completion = None
    _original_acompletion = None


def get_trace_id() -> Optional[str]:
    """Get the current trace ID being used for receipts."""
    from assay.store import get_default_store
    store = get_default_store()
    return store.current_trace_id if hasattr(store, "current_trace_id") else None


__all__ = ["patch", "unpatch", "get_trace_id"]
