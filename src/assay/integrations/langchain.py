"""
LangChain integration for Assay.

Callback handler that emits ModelCallReceipt for every LLM call in LangChain.

Usage:
    from assay.integrations.langchain import AssayCallbackHandler
    from langchain_openai import ChatOpenAI

    handler = AssayCallbackHandler()
    llm = ChatOpenAI(callbacks=[handler])

    response = llm.invoke("Hello!")
    # Receipt automatically emitted to ~/.loom/assay/

Configuration:
    handler = AssayCallbackHandler(
        store_prompts=False,  # Default: hash prompts, don't store content
        store_responses=False,  # Default: hash responses, don't store content
        trace_id=None,  # Optional: use existing trace
    )
"""
from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional

# Defer import of langchain to avoid hard dependency
_LANGCHAIN_AVAILABLE = None


def _check_langchain():
    """Check if langchain is available."""
    global _LANGCHAIN_AVAILABLE
    if _LANGCHAIN_AVAILABLE is None:
        try:
            from langchain_core.callbacks.base import BaseCallbackHandler  # noqa: F401
            _LANGCHAIN_AVAILABLE = True
        except ImportError:
            _LANGCHAIN_AVAILABLE = False
    return _LANGCHAIN_AVAILABLE


def _hash_content(content: str) -> str:
    """Hash content for privacy-preserving logging."""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _serialize_messages(messages: List[Any]) -> str:
    """Serialize messages list to string for hashing."""
    parts = []
    for msg in messages:
        if hasattr(msg, "content"):
            parts.append(str(msg.content))
        elif isinstance(msg, dict):
            parts.append(str(msg.get("content", "")))
        else:
            parts.append(str(msg))
    return "".join(parts)


class AssayCallbackHandler:
    """
    LangChain callback handler that emits Assay receipts.

    Every LLM call emits a ModelCallReceipt. Optionally, tool calls
    emit CapabilityUseReceipt.

    Example:
        from assay.integrations.langchain import AssayCallbackHandler
        from langchain_openai import ChatOpenAI

        handler = AssayCallbackHandler()
        llm = ChatOpenAI(callbacks=[handler])

        # All LLM calls now emit receipts
        response = llm.invoke("Hello!")
    """

    def __init__(
        self,
        store_prompts: bool = False,
        store_responses: bool = False,
        trace_id: Optional[str] = None,
    ):
        """
        Initialize the callback handler.

        Args:
            store_prompts: If True, store full prompt content. Default False (hash only).
            store_responses: If True, store full response content. Default False (hash only).
            trace_id: Optional trace ID to append to. Default: create new trace.
        """
        if not _check_langchain():
            raise ImportError(
                "LangChain not installed. Install with: pip install langchain-core"
            )

        self.store_prompts = store_prompts
        self.store_responses = store_responses

        # Get or start trace
        from assay.store import get_default_store
        self._store = get_default_store()
        if trace_id:
            self._store.start_trace(trace_id)
        else:
            self._store.start_trace()

        # Track in-flight calls
        self._call_starts: Dict[str, Dict[str, Any]] = {}

    # Required callback interface properties
    @property
    def raise_error(self) -> bool:
        """Don't raise errors - let the LLM call continue."""
        return False

    # LLM callbacks
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: Optional[uuid.UUID] = None,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts running."""
        run_key = str(run_id) if run_id else uuid.uuid4().hex
        self._call_starts[run_key] = {
            "start_time": time.time(),
            "serialized": serialized,
            "prompts": prompts,
            "model": serialized.get("kwargs", {}).get("model_name")
                    or serialized.get("id", ["unknown"])[-1],
            "provider": self._extract_provider(serialized),
        }

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: Optional[uuid.UUID] = None,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when chat model starts running."""
        run_key = str(run_id) if run_id else uuid.uuid4().hex
        # Flatten messages for hashing
        flat_messages = []
        for msg_list in messages:
            flat_messages.extend(msg_list)

        self._call_starts[run_key] = {
            "start_time": time.time(),
            "serialized": serialized,
            "messages": flat_messages,
            "model": serialized.get("kwargs", {}).get("model_name")
                    or serialized.get("kwargs", {}).get("model")
                    or serialized.get("id", ["unknown"])[-1],
            "provider": self._extract_provider(serialized),
        }

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Optional[uuid.UUID] = None,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM ends running."""
        run_key = str(run_id) if run_id else None
        if not run_key or run_key not in self._call_starts:
            return

        call_data = self._call_starts.pop(run_key)
        latency_ms = int((time.time() - call_data["start_time"]) * 1000)

        self._emit_model_call_receipt(
            call_data=call_data,
            response=response,
            latency_ms=latency_ms,
            error=None,
        )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: Optional[uuid.UUID] = None,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM errors."""
        run_key = str(run_id) if run_id else None
        if not run_key or run_key not in self._call_starts:
            return

        call_data = self._call_starts.pop(run_key)
        latency_ms = int((time.time() - call_data["start_time"]) * 1000)

        self._emit_model_call_receipt(
            call_data=call_data,
            response=None,
            latency_ms=latency_ms,
            error=str(error),
        )

    # Internal helpers
    def _extract_provider(self, serialized: Dict[str, Any]) -> str:
        """Extract provider from serialized LLM."""
        id_parts = serialized.get("id", [])
        if not id_parts:
            return "unknown"

        # LangChain ID format: ['langchain', 'chat_models', 'openai', 'ChatOpenAI']
        # or ['langchain_openai', 'chat_models', 'ChatOpenAI']
        for part in id_parts:
            part_lower = part.lower()
            if "openai" in part_lower:
                return "openai"
            elif "anthropic" in part_lower:
                return "anthropic"
            elif "google" in part_lower or "gemini" in part_lower:
                return "google"
            elif "cohere" in part_lower:
                return "cohere"
            elif "huggingface" in part_lower:
                return "huggingface"
            elif "ollama" in part_lower:
                return "ollama"

        return "unknown"

    def _emit_model_call_receipt(
        self,
        call_data: Dict[str, Any],
        response: Any,
        latency_ms: int,
        error: Optional[str],
    ) -> None:
        """Emit a model_call receipt for the LLM call.

        Uses emit_receipt() to write canonical Assay receipts (type + timestamp)
        that pass integrity verification.
        """
        from assay.store import emit_receipt

        # Extract token counts from response
        input_tokens = 0
        output_tokens = 0
        finish_reason = "error" if error else "stop"
        output_hash = None
        response_text = None

        if response:
            # LangChain LLMResult has llm_output with token counts
            llm_output = getattr(response, "llm_output", {}) or {}
            token_usage = llm_output.get("token_usage", {})
            input_tokens = token_usage.get("prompt_tokens", 0) or 0
            output_tokens = token_usage.get("completion_tokens", 0) or 0

            # Also check for usage_metadata on generations
            generations = getattr(response, "generations", [])
            if generations and generations[0]:
                gen = generations[0][0] if isinstance(generations[0], list) else generations[0]
                gen_info = getattr(gen, "generation_info", {}) or {}
                if "finish_reason" in gen_info:
                    finish_reason = gen_info["finish_reason"]

                # Get response text for hashing
                text = getattr(gen, "text", "") or ""
                if not text and hasattr(gen, "message"):
                    text = str(getattr(gen.message, "content", ""))
                if text:
                    response_text = text
                    output_hash = _hash_content(text)

        # Calculate input hash
        if "messages" in call_data:
            input_content = _serialize_messages(call_data["messages"])
            input_hash = _hash_content(input_content)
            message_count = len(call_data["messages"])
        else:
            prompts = call_data.get("prompts", [])
            input_hash = _hash_content("".join(prompts))
            message_count = len(prompts)

        data: Dict[str, Any] = {
            "provider": call_data.get("provider", "unknown"),
            "model_id": call_data.get("model", "unknown"),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "latency_ms": latency_ms,
            "finish_reason": finish_reason,
            "error": error,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "message_count": message_count,
            "integration_source": "assay.integrations.langchain",
        }

        # Store cleartext content when opted in
        if self.store_prompts:
            if "messages" in call_data:
                data["input_content"] = [str(getattr(m, "content", m)) for m in call_data["messages"]]
            else:
                data["input_content"] = call_data.get("prompts", [])
        if self.store_responses and response_text is not None:
            data["output_content"] = response_text

        emit_receipt(
            "model_call",
            data,
            receipt_id=f"mcr_{uuid.uuid4().hex[:16]}",
        )


def get_trace_id() -> Optional[str]:
    """Get the current trace ID being used for receipts."""
    from assay.store import get_default_store
    store = get_default_store()
    return store.current_trace_id if hasattr(store, "current_trace_id") else None


__all__ = ["AssayCallbackHandler", "get_trace_id"]
