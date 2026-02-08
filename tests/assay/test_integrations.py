"""
Tests for Assay integrations (OpenAI, Anthropic, LangChain).

These tests mock the actual API calls - for real API tests, see test_integrations_live.py
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch as mock_patch

import assay.store as store_mod
import pytest


class TestOpenAIIntegration:
    """Tests for OpenAI integration."""

    def test_patch_without_openai_raises(self):
        """Patch raises ImportError if openai not installed."""
        from assay.integrations import openai as openai_integration

        # Reset state
        openai_integration._patched = False
        openai_integration._original_create = None

        with mock_patch.dict("sys.modules", {"openai": None}):
            # Force reimport to trigger ImportError
            with pytest.raises(ImportError, match="OpenAI package not installed"):
                # Manually trigger the import check
                try:
                    import openai  # noqa: F401
                    from openai.resources.chat import completions  # noqa: F401
                except (ImportError, TypeError):
                    raise ImportError("OpenAI package not installed. Install with: pip install openai")

    def test_hash_content(self):
        """Hash content produces consistent output."""
        from assay.integrations.openai import _hash_content

        result1 = _hash_content("test content")
        result2 = _hash_content("test content")
        result3 = _hash_content("different content")

        assert result1 == result2  # Same input, same hash
        assert result1 != result3  # Different input, different hash
        assert len(result1) == 16  # Truncated to 16 chars

    def test_extract_messages_hash_dict(self):
        """Extract hash from dict-style messages."""
        from assay.integrations.openai import _extract_messages_hash

        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]

        result = _extract_messages_hash(messages)
        assert len(result) == 16

    def test_create_model_call_receipt(self):
        """Can create receipt from mock response with canonical Assay fields."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                # Mock response
                mock_response = MagicMock()
                mock_response.usage.prompt_tokens = 10
                mock_response.usage.completion_tokens = 20
                mock_response.choices = [MagicMock()]
                mock_response.choices[0].finish_reason = "stop"
                mock_response.choices[0].message.content = "Hello!"

                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=mock_response,
                    latency_ms=100,
                )

                # Canonical Assay fields (type, not receipt_type)
                assert receipt["type"] == "model_call"
                assert receipt["provider"] == "openai"
                assert receipt["model_id"] == "gpt-4"
                assert receipt["input_tokens"] == 10
                assert receipt["output_tokens"] == 20
                assert receipt["total_tokens"] == 30
                assert receipt["finish_reason"] == "stop"
                assert receipt["latency_ms"] == 100
                assert receipt["error"] is None
                assert receipt["integration_source"] == "assay.integrations.openai"
                assert "timestamp" in receipt
                assert "seq" in receipt

    def test_create_model_call_receipt_with_error(self):
        """Receipt captures error."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=None,
                    latency_ms=50,
                    error="Rate limit exceeded",
                )

                assert receipt["error"] == "Rate limit exceeded"
                assert receipt["input_tokens"] == 0
                assert receipt["output_tokens"] == 0


class TestAnthropicIntegration:
    """Tests for Anthropic integration."""

    def test_hash_content(self):
        """Hash content produces consistent output."""
        from assay.integrations.anthropic import _hash_content

        result1 = _hash_content("test content")
        result2 = _hash_content("test content")

        assert result1 == result2
        assert len(result1) == 16

    def test_extract_messages_hash(self):
        """Extract hash from Anthropic-style messages."""
        from assay.integrations.anthropic import _extract_messages_hash

        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]

        result = _extract_messages_hash(messages)
        assert len(result) == 16

    def test_extract_messages_hash_with_content_blocks(self):
        """Handle content block format."""
        from assay.integrations.anthropic import _extract_messages_hash

        messages = [
            {"role": "user", "content": [{"type": "text", "text": "Hello"}]},
        ]

        result = _extract_messages_hash(messages)
        assert len(result) == 16

    def test_create_model_call_receipt(self):
        """Can create receipt from mock Anthropic response with canonical fields."""
        from assay.integrations.anthropic import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                # Mock response
                mock_response = MagicMock()
                mock_response.usage.input_tokens = 15
                mock_response.usage.output_tokens = 25
                mock_response.stop_reason = "end_turn"
                mock_content_block = MagicMock()
                mock_content_block.text = "Hello there!"
                mock_response.content = [mock_content_block]

                receipt = _create_model_call_receipt(
                    model="claude-sonnet-4-20250514",
                    messages=[{"role": "user", "content": "Hi"}],
                    system="You are helpful.",
                    response=mock_response,
                    latency_ms=200,
                )

                # Canonical Assay fields (type, not receipt_type)
                assert receipt["type"] == "model_call"
                assert receipt["provider"] == "anthropic"
                assert receipt["model_id"] == "claude-sonnet-4-20250514"
                assert receipt["input_tokens"] == 15
                assert receipt["output_tokens"] == 25
                assert receipt["total_tokens"] == 40
                assert receipt["finish_reason"] == "end_turn"
                assert receipt["latency_ms"] == 200
                assert receipt["integration_source"] == "assay.integrations.anthropic"
                assert "timestamp" in receipt
                assert "seq" in receipt


class TestIntegrationPrivacy:
    """Tests for privacy-preserving behavior."""

    def test_openai_default_no_content_stored(self):
        """By default, prompts/responses are hashed, not stored."""
        from assay.integrations.openai import _create_model_call_receipt, _patch_config
        from assay.store import AssayStore

        # Ensure default config
        _patch_config.clear()
        _patch_config["store_prompts"] = False
        _patch_config["store_responses"] = False

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                mock_response = MagicMock()
                mock_response.usage.prompt_tokens = 10
                mock_response.usage.completion_tokens = 20
                mock_response.choices = [MagicMock()]
                mock_response.choices[0].finish_reason = "stop"
                mock_response.choices[0].message.content = "Secret response"

                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Secret prompt"}],
                    response=mock_response,
                    latency_ms=100,
                )

                # Should have hashes, not content
                assert "input_hash" in receipt
                assert "output_hash" in receipt
                assert "messages" not in receipt
                assert "response_content" not in receipt
                assert "Secret" not in json.dumps(receipt)

    def test_receipts_use_canonical_assay_fields(self):
        """Receipts use canonical Assay fields compatible with integrity verification."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                mock_response = MagicMock()
                mock_response.usage.prompt_tokens = 10
                mock_response.usage.completion_tokens = 20
                mock_response.choices = [MagicMock()]
                mock_response.choices[0].finish_reason = "stop"
                mock_response.choices[0].message.content = "The response"

                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "The prompt"}],
                    response=mock_response,
                    latency_ms=100,
                )

                # Canonical Assay fields (integrity.py requires these)
                assert receipt["type"] == "model_call"
                assert receipt["receipt_id"].startswith("mcr_")
                assert "timestamp" in receipt
                assert receipt["schema_version"] == "3.0"
                assert "seq" in receipt

    def test_integration_receipts_build_and_verify_proof_pack(self):
        """Regression: integration receipts must pass Proof Pack integrity verification."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.integrity import verify_pack_manifest
        from assay.keystore import AssayKeyStore
        from assay.proof_pack import ProofPack
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            store = AssayStore(base_dir=base / "store")
            trace_id = store.start_trace("trace_integration_proof_pack")

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                mock_response = MagicMock()
                mock_response.usage.prompt_tokens = 7
                mock_response.usage.completion_tokens = 11
                mock_response.choices = [MagicMock()]
                mock_response.choices[0].finish_reason = "stop"
                mock_response.choices[0].message.content = "Integration response"

                _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Integration prompt"}],
                    response=mock_response,
                    latency_ms=123,
                )

            entries = store.read_trace(trace_id)
            assert len(entries) == 1
            assert entries[0]["type"] == "model_call"
            assert "timestamp" in entries[0]

            ks = AssayKeyStore(keys_dir=base / "keys")
            ks.generate_key("test-signer")

            out_dir = base / "pack"
            pack = ProofPack(
                run_id=trace_id,
                entries=entries,
                signer_id="test-signer",
            )
            pack.build(out_dir, keystore=ks)

            manifest = json.loads((out_dir / "pack_manifest.json").read_text())
            verify = verify_pack_manifest(manifest, out_dir, ks)

            assert manifest["attestation"]["receipt_integrity"] == "PASS"
            assert verify.passed
            assert verify.errors == []


class TestIntegrationTraceId:
    """Tests for trace ID handling."""

    def test_get_trace_id_openai(self):
        """Can get trace ID from OpenAI integration."""
        from assay.integrations.openai import get_trace_id
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            trace_id = store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store):
                result = get_trace_id()
                assert result == trace_id

    def test_get_trace_id_anthropic(self):
        """Can get trace ID from Anthropic integration."""
        from assay.integrations.anthropic import get_trace_id
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            trace_id = store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store):
                result = get_trace_id()
                assert result == trace_id


class TestLangChainIntegration:
    """Tests for LangChain integration."""

    def test_hash_content(self):
        """Hash content produces consistent output."""
        from assay.integrations.langchain import _hash_content

        result1 = _hash_content("test content")
        result2 = _hash_content("test content")
        result3 = _hash_content("different content")

        assert result1 == result2
        assert result1 != result3
        assert len(result1) == 16

    def test_serialize_messages(self):
        """Serialize messages for hashing."""
        from assay.integrations.langchain import _serialize_messages

        # Dict messages
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi"},
        ]
        result = _serialize_messages(messages)
        assert "Hello" in result
        assert "Hi" in result

    def test_extract_provider_openai(self):
        """Extract OpenAI provider from serialized LLM."""
        from assay.integrations.langchain import AssayCallbackHandler
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))

            with mock_patch("assay.store.get_default_store", return_value=store):
                # Mock langchain being available
                with mock_patch("assay.integrations.langchain._check_langchain", return_value=True):
                    handler = AssayCallbackHandler()

                    # OpenAI-style serialized
                    serialized = {"id": ["langchain", "chat_models", "openai", "ChatOpenAI"]}
                    assert handler._extract_provider(serialized) == "openai"

                    # Anthropic-style
                    serialized = {"id": ["langchain_anthropic", "chat_models", "ChatAnthropic"]}
                    assert handler._extract_provider(serialized) == "anthropic"

                    # Unknown
                    serialized = {"id": ["something", "else"]}
                    assert handler._extract_provider(serialized) == "unknown"

    def test_callback_handler_creates_trace(self):
        """Handler creates a trace on init."""
        from assay.integrations.langchain import AssayCallbackHandler
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))

            with mock_patch("assay.store.get_default_store", return_value=store):
                with mock_patch("assay.integrations.langchain._check_langchain", return_value=True):
                    AssayCallbackHandler()
                    assert store.trace_id is not None
                    assert store.trace_id.startswith("trace_")

    def test_callback_handler_uses_existing_trace(self):
        """Handler can use an existing trace ID."""
        from assay.integrations.langchain import AssayCallbackHandler
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace("trace_existing_123")

            with mock_patch("assay.store.get_default_store", return_value=store):
                with mock_patch("assay.integrations.langchain._check_langchain", return_value=True):
                    AssayCallbackHandler(trace_id="trace_existing_123")
                    assert store.trace_id == "trace_existing_123"

    def test_callback_handler_emits_receipt_on_llm_end(self):
        """Handler emits ModelCallReceipt when LLM completes."""
        import uuid as uuid_module
        from assay.integrations.langchain import AssayCallbackHandler
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))

            with mock_patch("assay.store.get_default_store", return_value=store):
                with mock_patch("assay.integrations.langchain._check_langchain", return_value=True):
                    handler = AssayCallbackHandler()

                    # Simulate LLM start
                    run_id = uuid_module.uuid4()
                    serialized = {
                        "id": ["langchain", "chat_models", "openai", "ChatOpenAI"],
                        "kwargs": {"model_name": "gpt-4"},
                    }
                    messages = [[MagicMock(content="Hello")]]

                    handler.on_chat_model_start(
                        serialized=serialized,
                        messages=messages,
                        run_id=run_id,
                    )

                    # Simulate LLM end
                    mock_response = MagicMock()
                    mock_response.llm_output = {"token_usage": {"prompt_tokens": 5, "completion_tokens": 10}}
                    mock_gen = MagicMock()
                    mock_gen.text = "Hi there!"
                    mock_gen.generation_info = {"finish_reason": "stop"}
                    mock_response.generations = [[mock_gen]]

                    handler.on_llm_end(response=mock_response, run_id=run_id)

                    # Verify receipt was stored with canonical fields
                    entries = store.read_trace(store.trace_id)
                    assert len(entries) == 1
                    receipt = entries[0]
                    assert receipt["type"] == "model_call"
                    assert receipt["provider"] == "openai"
                    assert receipt["model_id"] == "gpt-4"
                    assert receipt["integration_source"] == "assay.integrations.langchain"
                    assert "timestamp" in receipt

    def test_callback_handler_emits_receipt_on_error(self):
        """Handler emits ModelCallReceipt with error when LLM fails."""
        import uuid as uuid_module
        from assay.integrations.langchain import AssayCallbackHandler
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))

            with mock_patch("assay.store.get_default_store", return_value=store):
                with mock_patch("assay.integrations.langchain._check_langchain", return_value=True):
                    handler = AssayCallbackHandler()

                    # Simulate LLM start
                    run_id = uuid_module.uuid4()
                    handler.on_llm_start(
                        serialized={"id": ["openai"], "kwargs": {}},
                        prompts=["Hello"],
                        run_id=run_id,
                    )

                    # Simulate error
                    handler.on_llm_error(
                        error=Exception("Rate limit exceeded"),
                        run_id=run_id,
                    )

                    # Verify receipt was stored with error
                    entries = store.read_trace(store.trace_id)
                    assert len(entries) == 1
                    receipt = entries[0]
                    assert receipt["error"] == "Rate limit exceeded"
                    assert receipt["finish_reason"] == "error"

    def test_get_trace_id_langchain(self):
        """Can get trace ID from LangChain integration."""
        from assay.integrations.langchain import get_trace_id
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            trace_id = store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store):
                result = get_trace_id()
                assert result == trace_id
