"""
OpenAI integration for Assay.

Drop-in wrapper that emits ModelCallReceipt for every OpenAI API call.
Covers both Chat Completions (client.chat.completions.create) and the
Responses API (client.responses.create, openai >= 1.66).

Usage:
    from assay.integrations.openai import patch
    patch()

    # Chat Completions -- receipt emitted
    client = OpenAI()
    response = client.chat.completions.create(...)

    # Responses API -- receipt emitted (api="responses" in receipt)
    response = client.responses.create(model="gpt-4o", input="Hello!")

Configuration:
    patch(
        store_prompts=False,  # Default: hash prompts, don't store content
        store_responses=False,  # Default: hash responses, don't store content
        trace_id=None,  # Optional: use existing trace
    )
"""
from __future__ import annotations

import hashlib
import time
import uuid
from functools import wraps
from typing import Any, Callable, Dict, Optional

# Global state
_original_create: Optional[Callable] = None
_original_responses_create: Optional[Callable] = None
_patch_config: Dict[str, Any] = {}
_patched = False


def _hash_content(content: str) -> str:
    """Hash content for privacy-preserving logging."""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _extract_messages_hash(messages: list) -> str:
    """Extract a privacy-preserving hash of messages."""
    # Concatenate all message content and hash
    content = ""
    for msg in messages:
        if isinstance(msg, dict):
            content += msg.get("role", "") + msg.get("content", "")
        else:
            # Pydantic model
            content += getattr(msg, "role", "") + getattr(msg, "content", "")
    return _hash_content(content)


def _extract_endpoint_hint(instance: Any) -> Optional[str]:
    """Extract hostname from a non-default base_url on the OpenAI client."""
    try:
        client = getattr(instance, "_client", None)
        if client is None:
            return None
        base_url = str(getattr(client, "base_url", ""))
        if not base_url:
            return None
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        host = parsed.hostname
        if host and host != "api.openai.com":
            return host
    except Exception:
        pass
    return None


def _create_model_call_receipt(
    model: str,
    messages: list,
    response: Any,
    latency_ms: int,
    error: Optional[str] = None,
    callsite_file: Optional[str] = None,
    callsite_line: Optional[int] = None,
    callsite_id: Optional[str] = None,
    endpoint_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a model_call receipt from an OpenAI call.

    Uses emit_receipt() to write canonical Assay receipts (type + timestamp)
    that pass integrity verification.
    """
    from assay.store import emit_receipt

    # Extract response data
    input_tokens = 0
    output_tokens = 0
    finish_reason = "error" if error else "stop"
    response_hash = None

    if response and hasattr(response, "usage"):
        usage = response.usage
        if usage:
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
        "provider": "openai",
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
        "integration_source": "assay.integrations.openai",
    }

    # Store cleartext content when opted in
    if _patch_config.get("store_prompts"):
        data["input_content"] = [
            {"role": m.get("role", ""), "content": m.get("content", "")}
            if isinstance(m, dict)
            else {"role": getattr(m, "role", ""), "content": getattr(m, "content", "")}
            for m in messages
        ]
    if _patch_config.get("store_responses") and response_text is not None:
        data["output_content"] = response_text

    if endpoint_hint is not None:
        data["endpoint_hint"] = endpoint_hint
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


def _wrapped_create(original_create: Callable) -> Callable:
    """Wrap OpenAI's chat.completions.create to emit receipts."""

    @wraps(original_create)
    def wrapper(*args, **kwargs):
        # Capture caller frame BEFORE the API call (stack is correct here)
        from assay.integrations import find_caller_frame
        caller_file, caller_line = find_caller_frame()
        caller_id = None
        if caller_file is not None and caller_line is not None:
            from assay.coverage import compute_callsite_id
            caller_id = compute_callsite_id(caller_file, caller_line)

        # Extract endpoint hint from Completions instance (args[0] is self)
        hint = _extract_endpoint_hint(args[0]) if args else None

        start_time = time.time()
        error = None
        response = None

        # Extract model and messages
        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])

        try:
            response = original_create(*args, **kwargs)
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
                    endpoint_hint=hint,
                )
            except Exception as exc:
                import warnings
                warnings.warn(
                    f"assay: receipt emission failed: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    return wrapper


def _wrapped_create_async(original_create: Callable) -> Callable:
    """Wrap OpenAI's async chat.completions.create to emit receipts."""

    @wraps(original_create)
    async def wrapper(*args, **kwargs):
        from assay.integrations import find_caller_frame
        caller_file, caller_line = find_caller_frame()
        caller_id = None
        if caller_file is not None and caller_line is not None:
            from assay.coverage import compute_callsite_id
            caller_id = compute_callsite_id(caller_file, caller_line)

        hint = _extract_endpoint_hint(args[0]) if args else None

        start_time = time.time()
        error = None
        response = None

        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])

        try:
            response = await original_create(*args, **kwargs)
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
                    endpoint_hint=hint,
                )
            except Exception as exc:
                import warnings
                warnings.warn(
                    f"assay: receipt emission failed: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    return wrapper


# ---------------------------------------------------------------------------
# Responses API (client.responses.create)
# ---------------------------------------------------------------------------

def _extract_responses_input_hash(input_data: Any) -> str:
    """Extract a privacy-preserving hash from Responses API input."""
    if isinstance(input_data, str):
        return _hash_content(input_data)
    import json
    try:
        content = json.dumps(input_data, default=str, sort_keys=True)
    except (TypeError, ValueError):
        content = str(input_data)
    return _hash_content(content)


def _extract_responses_output_text(response: Any) -> Optional[str]:
    """Extract text content from Responses API output items."""
    if not response or not hasattr(response, "output"):
        return None
    texts = []
    for item in response.output:
        if getattr(item, "type", None) == "message" and hasattr(item, "content"):
            for part in item.content:
                if getattr(part, "type", None) == "output_text" and hasattr(part, "text"):
                    texts.append(part.text)
    return "".join(texts) if texts else None


def _create_responses_receipt(
    model: str,
    input_data: Any,
    response: Any,
    latency_ms: int,
    error: Optional[str] = None,
    callsite_file: Optional[str] = None,
    callsite_line: Optional[int] = None,
    callsite_id: Optional[str] = None,
    endpoint_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a model_call receipt from an OpenAI Responses API call."""
    from assay.store import emit_receipt

    input_tokens = 0
    output_tokens = 0
    finish_reason = "error" if error else "stop"
    response_hash = None

    if response and hasattr(response, "usage") and response.usage:
        input_tokens = getattr(response.usage, "input_tokens", 0) or 0
        output_tokens = getattr(response.usage, "output_tokens", 0) or 0

    if response and hasattr(response, "status") and response.status:
        status = response.status
        if status == "completed":
            finish_reason = "stop"
        elif status == "incomplete":
            finish_reason = "length"
        elif status in ("failed", "cancelled"):
            finish_reason = status

    response_text = _extract_responses_output_text(response) if response else None
    if response_text is not None:
        response_hash = _hash_content(response_text)

    message_count = 1 if isinstance(input_data, str) else len(input_data) if input_data else 0

    data: Dict[str, Any] = {
        "provider": "openai",
        "model_id": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "latency_ms": latency_ms,
        "finish_reason": finish_reason,
        "error": error,
        "input_hash": _extract_responses_input_hash(input_data),
        "output_hash": response_hash,
        "message_count": message_count,
        "api": "responses",
        "integration_source": "assay.integrations.openai",
    }

    if _patch_config.get("store_prompts"):
        if isinstance(input_data, str):
            data["input_content"] = [{"role": "user", "content": input_data}]
        else:
            data["input_content"] = input_data
    if _patch_config.get("store_responses") and response_text is not None:
        data["output_content"] = response_text

    if endpoint_hint is not None:
        data["endpoint_hint"] = endpoint_hint
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


def _wrapped_responses_create(original_create: Callable) -> Callable:
    """Wrap OpenAI's responses.create to emit receipts."""

    @wraps(original_create)
    def wrapper(*args, **kwargs):
        from assay.integrations import find_caller_frame
        caller_file, caller_line = find_caller_frame()
        caller_id = None
        if caller_file is not None and caller_line is not None:
            from assay.coverage import compute_callsite_id
            caller_id = compute_callsite_id(caller_file, caller_line)

        hint = _extract_endpoint_hint(args[0]) if args else None

        start_time = time.time()
        error = None
        response = None

        model = kwargs.get("model", "unknown")
        input_data = kwargs.get("input", "")

        try:
            response = original_create(*args, **kwargs)
            return response
        except Exception as e:
            error = str(e)
            raise
        finally:
            latency_ms = int((time.time() - start_time) * 1000)
            try:
                _create_responses_receipt(
                    model=model,
                    input_data=input_data,
                    response=response,
                    latency_ms=latency_ms,
                    error=error,
                    callsite_file=caller_file,
                    callsite_line=caller_line,
                    callsite_id=caller_id,
                    endpoint_hint=hint,
                )
            except Exception as exc:
                import warnings
                warnings.warn(
                    f"assay: receipt emission failed: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    return wrapper


def _wrapped_responses_create_async(original_create: Callable) -> Callable:
    """Wrap OpenAI's async responses.create to emit receipts."""

    @wraps(original_create)
    async def wrapper(*args, **kwargs):
        from assay.integrations import find_caller_frame
        caller_file, caller_line = find_caller_frame()
        caller_id = None
        if caller_file is not None and caller_line is not None:
            from assay.coverage import compute_callsite_id
            caller_id = compute_callsite_id(caller_file, caller_line)

        hint = _extract_endpoint_hint(args[0]) if args else None

        start_time = time.time()
        error = None
        response = None

        model = kwargs.get("model", "unknown")
        input_data = kwargs.get("input", "")

        try:
            response = await original_create(*args, **kwargs)
            return response
        except Exception as e:
            error = str(e)
            raise
        finally:
            latency_ms = int((time.time() - start_time) * 1000)
            try:
                _create_responses_receipt(
                    model=model,
                    input_data=input_data,
                    response=response,
                    latency_ms=latency_ms,
                    error=error,
                    callsite_file=caller_file,
                    callsite_line=caller_line,
                    callsite_id=caller_id,
                    endpoint_hint=hint,
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
    Patch OpenAI client to emit receipts for every call.

    Args:
        store_prompts: If True, store full prompt content. Default False (hash only).
        store_responses: If True, store full response content. Default False (hash only).
        trace_id: Optional trace ID to append to. Default: create new trace.

    Example:
        from assay.integrations.openai import patch
        patch()

        from openai import OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello!"}]
        )
        # Receipt automatically emitted
    """
    global _original_create, _original_responses_create, _patch_config, _patched

    if _patched:
        return  # Already patched

    try:
        import openai  # noqa: F401
        from openai.resources.chat import completions
    except ImportError:
        raise ImportError(
            "OpenAI package not installed. Install with: pip install openai"
        )

    _patch_config = {
        "store_prompts": store_prompts,
        "store_responses": store_responses,
        "trace_id": trace_id,
    }

    # Start trace if not provided
    if trace_id:
        from assay.store import get_default_store
        store = get_default_store()
        store.start_trace(trace_id)
    else:
        from assay.store import get_default_store
        store = get_default_store()
        store.start_trace()

    # Patch synchronous create
    _original_create = completions.Completions.create
    completions.Completions.create = _wrapped_create(_original_create)

    # Patch async create if available
    if hasattr(completions, "AsyncCompletions"):
        original_async = completions.AsyncCompletions.create
        completions.AsyncCompletions.create = _wrapped_create_async(original_async)

    # Patch Responses API if available (openai >= 1.66)
    try:
        from openai.resources import responses as _responses_mod
        _original_responses_create = _responses_mod.Responses.create
        _responses_mod.Responses.create = _wrapped_responses_create(_original_responses_create)
        if hasattr(_responses_mod, "AsyncResponses"):
            original_async_resp = _responses_mod.AsyncResponses.create
            _responses_mod.AsyncResponses.create = _wrapped_responses_create_async(original_async_resp)
    except (ImportError, AttributeError):
        pass  # Older SDK without Responses API

    _patched = True


def unpatch() -> None:
    """Remove the OpenAI patch."""
    global _original_create, _original_responses_create, _patched

    if not _patched:
        return

    try:
        from openai.resources.chat import completions

        if _original_create:
            completions.Completions.create = _original_create

    except ImportError:
        pass

    try:
        from openai.resources import responses as _responses_mod
        if _original_responses_create:
            _responses_mod.Responses.create = _original_responses_create
    except (ImportError, AttributeError):
        pass

    _patched = False
    _original_create = None
    _original_responses_create = None


def get_trace_id() -> Optional[str]:
    """Get the current trace ID being used for receipts."""
    from assay.store import get_default_store
    store = get_default_store()
    return store.current_trace_id if hasattr(store, "current_trace_id") else None


__all__ = ["patch", "unpatch", "get_trace_id"]
