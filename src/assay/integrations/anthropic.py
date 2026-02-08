"""
Anthropic integration for Assay.

Drop-in wrapper that emits ModelCallReceipt for every Anthropic API call.

Usage:
    from assay.integrations.anthropic import patch
    patch()

    # Now every Anthropic call emits a receipt
    client = Anthropic()
    response = client.messages.create(...)
    # Receipt automatically emitted to ~/.loom/assay/

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
            role = msg.get("role", "")
            msg_content = msg.get("content", "")
            if isinstance(msg_content, list):
                # Handle content blocks
                for block in msg_content:
                    if isinstance(block, dict):
                        content += block.get("text", "")
                    else:
                        content += str(block)
            else:
                content += str(msg_content)
            content += role
        else:
            content += getattr(msg, "role", "") + str(getattr(msg, "content", ""))
    return _hash_content(content)


def _create_model_call_receipt(
    model: str,
    messages: list,
    system: Optional[str],
    response: Any,
    latency_ms: int,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a model_call receipt from an Anthropic call.

    Uses emit_receipt() to write canonical Assay receipts (type + timestamp)
    that pass integrity verification.
    """
    from assay.store import emit_receipt

    # Extract response data
    input_tokens = 0
    output_tokens = 0
    stop_reason = "error" if error else "end_turn"
    response_hash = None

    if response:
        if hasattr(response, "usage"):
            usage = response.usage
            input_tokens = getattr(usage, "input_tokens", 0) or 0
            output_tokens = getattr(usage, "output_tokens", 0) or 0

        stop_reason = getattr(response, "stop_reason", None) or "end_turn"

        if hasattr(response, "content") and response.content:
            text_parts = []
            for block in response.content:
                if hasattr(block, "text"):
                    text_parts.append(block.text)
            if text_parts:
                response_hash = _hash_content("".join(text_parts))

    # Include system prompt in hash if present
    input_hash = _extract_messages_hash(messages)
    if system:
        input_hash = _hash_content(system + input_hash)

    return emit_receipt(
        "model_call",
        {
            "provider": "anthropic",
            "model_id": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "latency_ms": latency_ms,
            "finish_reason": stop_reason,
            "error": error,
            "input_hash": input_hash,
            "output_hash": response_hash,
            "message_count": len(messages),
            "integration_source": "assay.integrations.anthropic",
        },
        receipt_id=f"mcr_{uuid.uuid4().hex[:16]}",
    )


def _wrapped_create(original_create: Callable) -> Callable:
    """Wrap Anthropic's messages.create to emit receipts."""

    @wraps(original_create)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        error = None
        response = None

        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])
        system = kwargs.get("system", None)

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
                    system=system,
                    response=response,
                    latency_ms=latency_ms,
                    error=error,
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
    """Wrap Anthropic's async messages.create to emit receipts."""

    @wraps(original_create)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        error = None
        response = None

        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])
        system = kwargs.get("system", None)

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
                    system=system,
                    response=response,
                    latency_ms=latency_ms,
                    error=error,
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
    Patch Anthropic client to emit receipts for every call.

    Args:
        store_prompts: If True, store full prompt content. Default False (hash only).
        store_responses: If True, store full response content. Default False (hash only).
        trace_id: Optional trace ID to append to. Default: create new trace.

    Example:
        from assay.integrations.anthropic import patch
        patch()

        from anthropic import Anthropic
        client = Anthropic()
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello!"}]
        )
        # Receipt automatically emitted
    """
    global _original_create, _patch_config, _patched

    if _patched:
        return

    try:
        import anthropic  # noqa: F401
        from anthropic.resources import messages
    except ImportError:
        raise ImportError(
            "Anthropic package not installed. Install with: pip install anthropic"
        )

    _patch_config = {
        "store_prompts": store_prompts,
        "store_responses": store_responses,
        "trace_id": trace_id,
    }

    # Start trace
    from assay.store import get_default_store
    store = get_default_store()
    if trace_id:
        store.start_trace(trace_id)
    else:
        store.start_trace()

    # Patch synchronous create
    _original_create = messages.Messages.create
    messages.Messages.create = _wrapped_create(_original_create)

    # Patch async create
    if hasattr(messages, "AsyncMessages"):
        original_async = messages.AsyncMessages.create
        messages.AsyncMessages.create = _wrapped_create_async(original_async)

    _patched = True


def unpatch() -> None:
    """Remove the Anthropic patch."""
    global _original_create, _patched

    if not _patched:
        return

    try:
        from anthropic.resources import messages

        if _original_create:
            messages.Messages.create = _original_create

        _patched = False
        _original_create = None
    except ImportError:
        pass


def get_trace_id() -> Optional[str]:
    """Get the current trace ID being used for receipts."""
    from assay.store import get_default_store
    store = get_default_store()
    return store.current_trace_id if hasattr(store, "current_trace_id") else None


__all__ = ["patch", "unpatch", "get_trace_id"]
