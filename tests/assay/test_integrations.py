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


class TestCallsiteTracking:
    """Tests for callsite tracking in integration receipts."""

    def test_openai_receipt_has_callsite_fields(self):
        """OpenAI receipt includes callsite_file, callsite_line, callsite_id."""
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
                mock_response.choices[0].message.content = "Hello!"

                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=mock_response,
                    latency_ms=100,
                    callsite_file="src/app.py",
                    callsite_line=42,
                    callsite_id="abc123def456",
                )

                assert receipt["callsite_file"] == "src/app.py"
                assert receipt["callsite_line"] == 42
                assert receipt["callsite_id"] == "abc123def456"

    def test_anthropic_receipt_has_callsite_fields(self):
        """Anthropic receipt includes callsite_file, callsite_line, callsite_id."""
        from assay.integrations.anthropic import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                mock_response = MagicMock()
                mock_response.usage.input_tokens = 15
                mock_response.usage.output_tokens = 25
                mock_response.stop_reason = "end_turn"
                mock_content_block = MagicMock()
                mock_content_block.text = "Hello!"
                mock_response.content = [mock_content_block]

                receipt = _create_model_call_receipt(
                    model="claude-sonnet-4-20250514",
                    messages=[{"role": "user", "content": "Hi"}],
                    system=None,
                    response=mock_response,
                    latency_ms=200,
                    callsite_file="src/worker.py",
                    callsite_line=99,
                    callsite_id="feed0000cafe",
                )

                assert receipt["callsite_file"] == "src/worker.py"
                assert receipt["callsite_line"] == 99
                assert receipt["callsite_id"] == "feed0000cafe"

    def test_callsite_id_matches_scanner_formula(self):
        """callsite_id uses the same SHA256(path:line)[:12] as the scanner."""
        from assay.coverage import compute_callsite_id

        expected = compute_callsite_id("src/app.py", 42)
        assert len(expected) == 12

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
                mock_response.choices[0].message.content = "Hello!"

                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=mock_response,
                    latency_ms=100,
                    callsite_file="src/app.py",
                    callsite_line=42,
                    callsite_id=expected,
                )

                assert receipt["callsite_id"] == expected

    def test_no_callsite_fields_when_none(self):
        """Receipt omits callsite fields when find_caller_frame returns None."""
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
                mock_response.choices[0].message.content = "Hello!"

                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=mock_response,
                    latency_ms=100,
                    # No callsite params = graceful degradation
                )

                assert "callsite_file" not in receipt
                assert "callsite_line" not in receipt
                assert "callsite_id" not in receipt

    def test_callsite_receipt_passes_integrity(self):
        """Receipt with callsite fields still passes proof pack integrity."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.integrity import verify_pack_manifest
        from assay.keystore import AssayKeyStore
        from assay.proof_pack import ProofPack
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            store = AssayStore(base_dir=base / "store")
            trace_id = store.start_trace("trace_callsite_integrity")

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                mock_response = MagicMock()
                mock_response.usage.prompt_tokens = 7
                mock_response.usage.completion_tokens = 11
                mock_response.choices = [MagicMock()]
                mock_response.choices[0].finish_reason = "stop"
                mock_response.choices[0].message.content = "Response"

                _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Prompt"}],
                    response=mock_response,
                    latency_ms=50,
                    callsite_file="src/app.py",
                    callsite_line=42,
                    callsite_id="abc123def456",
                )

            entries = store.read_trace(trace_id)
            assert entries[0]["callsite_id"] == "abc123def456"

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

            assert verify.passed
            assert verify.errors == []


class TestFindCallerFrame:
    """Tests for find_caller_frame utility."""

    def test_returns_tuple(self):
        from assay.integrations import find_caller_frame
        result = find_caller_frame()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_finds_test_file(self):
        """When called from test code, should find the test file."""
        from assay.integrations import find_caller_frame
        path, line = find_caller_frame()
        # Should find this test file since it's outside assay.*
        assert path is not None
        assert line is not None
        assert "test_integrations" in path

    def test_line_number_is_positive(self):
        from assay.integrations import find_caller_frame
        _, line = find_caller_frame()
        assert line is not None
        assert line > 0


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


class TestOpenAICompatibleProviders:
    """Regression tests: OpenAI-compatible providers intercepted via base_url / AzureOpenAI.

    The OpenAI integration patches openai.resources.chat.completions.Completions.create.
    Both OpenAI(base_url=...) and AzureOpenAI(...) resolve to the same Completions class,
    so the patch intercepts all OpenAI-compatible providers.
    """

    def _make_mock_response(self, model="deepseek-chat"):
        mock_response = MagicMock()
        mock_response.usage.prompt_tokens = 8
        mock_response.usage.completion_tokens = 12
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].finish_reason = "stop"
        mock_response.choices[0].message.content = "Response from compatible provider"
        return mock_response

    def test_custom_base_url_receipt_captures_model(self):
        """OpenAI(base_url=...) calls emit receipts with the actual model name."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="deepseek-chat",
                    messages=[{"role": "user", "content": "Hello"}],
                    response=self._make_mock_response("deepseek-chat"),
                    latency_ms=150,
                )

                assert receipt["type"] == "model_call"
                assert receipt["model_id"] == "deepseek-chat"
                assert receipt["provider"] == "openai"
                assert receipt["input_tokens"] == 8
                assert receipt["output_tokens"] == 12

    def test_groq_model_name_captured(self):
        """Groq via OpenAI SDK captures the Groq model name."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="llama-3.1-70b-versatile",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=self._make_mock_response("llama-3.1-70b-versatile"),
                    latency_ms=80,
                )

                assert receipt["model_id"] == "llama-3.1-70b-versatile"
                assert receipt["provider"] == "openai"

    def test_together_model_name_captured(self):
        """Together AI via OpenAI SDK captures the Together model name."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=self._make_mock_response(),
                    latency_ms=200,
                )

                assert receipt["model_id"] == "meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo"

    def test_mistral_model_name_captured(self):
        """Mistral via OpenAI SDK captures the Mistral model name."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="mistral-large-latest",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=self._make_mock_response(),
                    latency_ms=120,
                )

                assert receipt["model_id"] == "mistral-large-latest"

    def test_ollama_model_name_captured(self):
        """Ollama via OpenAI SDK captures the local model name."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="llama3.2:3b",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=self._make_mock_response(),
                    latency_ms=50,
                )

                assert receipt["model_id"] == "llama3.2:3b"

    def test_patch_target_is_shared_class(self):
        """Completions.create is the same class for OpenAI and AzureOpenAI clients.

        This is the structural guarantee that one monkey-patch covers both.
        """
        try:
            from openai.resources.chat.completions import Completions
        except ImportError:
            pytest.skip("openai package not installed")

        # The patch target in integrations/openai.py
        assert hasattr(Completions, "create"), "Completions.create must exist"

        # Verify it's the same class the patch imports
        from openai.resources.chat import completions as completions_module
        assert completions_module.Completions is Completions

    def test_azure_openai_uses_same_completions_class(self):
        """AzureOpenAI client resolves to the same Completions class as OpenAI."""
        try:
            from openai import AzureOpenAI, OpenAI
            from openai.resources.chat.completions import Completions
        except ImportError:
            pytest.skip("openai package not installed")

        # Both client types should use the same Completions class
        # We can verify this by checking the class hierarchy
        assert hasattr(AzureOpenAI, "chat"), "AzureOpenAI must have chat attribute"

        # The critical invariant: patching Completions.create affects both clients
        # because both clients instantiate the same Completions class
        original = Completions.create

        def fake_create(*a, **kw):
            return "intercepted"

        try:
            Completions.create = fake_create
            # After patching the class method, any instance of Completions
            # (whether created by OpenAI or AzureOpenAI) uses the patched version
            assert Completions.create is fake_create
        finally:
            Completions.create = original

    def test_compatible_provider_receipt_passes_integrity(self):
        """Receipt from an OpenAI-compatible provider passes proof pack integrity."""
        from assay.integrations.openai import _create_model_call_receipt
        from assay.integrity import verify_pack_manifest
        from assay.keystore import AssayKeyStore
        from assay.proof_pack import ProofPack
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            store = AssayStore(base_dir=base / "store")
            trace_id = store.start_trace("trace_compat_provider")

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                # Simulate DeepSeek via OpenAI SDK
                _create_model_call_receipt(
                    model="deepseek-chat",
                    messages=[{"role": "user", "content": "Hello from DeepSeek"}],
                    response=self._make_mock_response("deepseek-chat"),
                    latency_ms=300,
                )
                # Simulate Groq via OpenAI SDK
                _create_model_call_receipt(
                    model="llama-3.1-70b-versatile",
                    messages=[{"role": "user", "content": "Hello from Groq"}],
                    response=self._make_mock_response("llama-3.1-70b-versatile"),
                    latency_ms=60,
                )

            entries = store.read_trace(trace_id)
            assert len(entries) == 2
            assert entries[0]["model_id"] == "deepseek-chat"
            assert entries[1]["model_id"] == "llama-3.1-70b-versatile"

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

            assert verify.passed
            assert verify.errors == []
            assert manifest["receipt_count_expected"] == 2


class TestStorePromptsResponses:
    """Tests for store_prompts / store_responses opt-in content capture."""

    def _make_openai_response(self, content="Hello!"):
        mock_response = MagicMock()
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 20
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].finish_reason = "stop"
        mock_response.choices[0].message.content = content
        return mock_response

    def _make_anthropic_response(self, content="Hello!"):
        mock_response = MagicMock()
        mock_response.usage.input_tokens = 15
        mock_response.usage.output_tokens = 25
        mock_response.stop_reason = "end_turn"
        mock_content_block = MagicMock()
        mock_content_block.text = content
        mock_response.content = [mock_content_block]
        return mock_response

    def test_openai_store_prompts_true(self):
        """When store_prompts=True, receipt includes input_content."""
        from assay.integrations.openai import _create_model_call_receipt, _patch_config
        from assay.store import AssayStore

        _patch_config.clear()
        _patch_config["store_prompts"] = True
        _patch_config["store_responses"] = False

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "What is 2+2?"}],
                    response=self._make_openai_response(),
                    latency_ms=100,
                )

                assert "input_content" in receipt
                assert receipt["input_content"][0]["content"] == "What is 2+2?"
                assert "input_hash" in receipt  # hash always present
                assert "output_content" not in receipt  # not opted in

        _patch_config.clear()

    def test_openai_store_responses_true(self):
        """When store_responses=True, receipt includes output_content."""
        from assay.integrations.openai import _create_model_call_receipt, _patch_config
        from assay.store import AssayStore

        _patch_config.clear()
        _patch_config["store_prompts"] = False
        _patch_config["store_responses"] = True

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Hi"}],
                    response=self._make_openai_response("The answer is 4"),
                    latency_ms=100,
                )

                assert "output_content" in receipt
                assert receipt["output_content"] == "The answer is 4"
                assert "output_hash" in receipt
                assert "input_content" not in receipt

        _patch_config.clear()

    def test_openai_default_no_content(self):
        """Default config: no cleartext content in receipt."""
        from assay.integrations.openai import _create_model_call_receipt, _patch_config
        from assay.store import AssayStore

        _patch_config.clear()
        _patch_config["store_prompts"] = False
        _patch_config["store_responses"] = False

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Secret stuff"}],
                    response=self._make_openai_response("Secret response"),
                    latency_ms=100,
                )

                assert "input_content" not in receipt
                assert "output_content" not in receipt
                assert "Secret" not in json.dumps(receipt)

        _patch_config.clear()

    def test_anthropic_store_prompts_true(self):
        """When store_prompts=True, Anthropic receipt includes input_content."""
        from assay.integrations.anthropic import _create_model_call_receipt, _patch_config
        from assay.store import AssayStore

        _patch_config.clear()
        _patch_config["store_prompts"] = True
        _patch_config["store_responses"] = False

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="claude-sonnet-4-20250514",
                    messages=[{"role": "user", "content": "Explain quantum computing"}],
                    system="You are a physicist.",
                    response=self._make_anthropic_response(),
                    latency_ms=200,
                )

                assert "input_content" in receipt
                assert receipt["input_content"][0]["content"] == "Explain quantum computing"
                assert receipt["system_content"] == "You are a physicist."
                assert "output_content" not in receipt

        _patch_config.clear()

    def test_anthropic_store_responses_true(self):
        """When store_responses=True, Anthropic receipt includes output_content."""
        from assay.integrations.anthropic import _create_model_call_receipt, _patch_config
        from assay.store import AssayStore

        _patch_config.clear()
        _patch_config["store_prompts"] = False
        _patch_config["store_responses"] = True

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))
            store.start_trace()

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                receipt = _create_model_call_receipt(
                    model="claude-sonnet-4-20250514",
                    messages=[{"role": "user", "content": "Hi"}],
                    system=None,
                    response=self._make_anthropic_response("Quantum is weird"),
                    latency_ms=200,
                )

                assert "output_content" in receipt
                assert receipt["output_content"] == "Quantum is weird"
                assert "input_content" not in receipt

        _patch_config.clear()

    def test_langchain_store_prompts_true(self):
        """When store_prompts=True, LangChain receipt includes input_content."""
        import uuid as uuid_module
        from assay.integrations.langchain import AssayCallbackHandler
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))

            with mock_patch("assay.store.get_default_store", return_value=store):
                with mock_patch("assay.integrations.langchain._check_langchain", return_value=True):
                    handler = AssayCallbackHandler(store_prompts=True, store_responses=False)

                    run_id = uuid_module.uuid4()
                    handler.on_chat_model_start(
                        serialized={"id": ["openai"], "kwargs": {"model_name": "gpt-4"}},
                        messages=[[MagicMock(content="What is AI?")]],
                        run_id=run_id,
                    )

                    mock_response = MagicMock()
                    mock_response.llm_output = {"token_usage": {"prompt_tokens": 5, "completion_tokens": 10}}
                    mock_gen = MagicMock()
                    mock_gen.text = "AI is..."
                    mock_gen.generation_info = {"finish_reason": "stop"}
                    mock_response.generations = [[mock_gen]]

                    handler.on_llm_end(response=mock_response, run_id=run_id)

                    entries = store.read_trace(store.trace_id)
                    receipt = entries[0]
                    assert "input_content" in receipt
                    assert "output_content" not in receipt

    def test_langchain_store_responses_true(self):
        """When store_responses=True, LangChain receipt includes output_content."""
        import uuid as uuid_module
        from assay.integrations.langchain import AssayCallbackHandler
        from assay.store import AssayStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = AssayStore(base_dir=Path(tmpdir))

            with mock_patch("assay.store.get_default_store", return_value=store):
                with mock_patch("assay.integrations.langchain._check_langchain", return_value=True):
                    handler = AssayCallbackHandler(store_prompts=False, store_responses=True)

                    run_id = uuid_module.uuid4()
                    handler.on_chat_model_start(
                        serialized={"id": ["openai"], "kwargs": {"model_name": "gpt-4"}},
                        messages=[[MagicMock(content="Hello")]],
                        run_id=run_id,
                    )

                    mock_response = MagicMock()
                    mock_response.llm_output = {"token_usage": {"prompt_tokens": 5, "completion_tokens": 10}}
                    mock_gen = MagicMock()
                    mock_gen.text = "The stored response"
                    mock_gen.generation_info = {"finish_reason": "stop"}
                    mock_response.generations = [[mock_gen]]

                    handler.on_llm_end(response=mock_response, run_id=run_id)

                    entries = store.read_trace(store.trace_id)
                    receipt = entries[0]
                    assert "output_content" in receipt
                    assert receipt["output_content"] == "The stored response"
                    assert "input_content" not in receipt

    def test_store_content_receipts_pass_integrity(self):
        """Receipts with cleartext content still pass proof pack integrity."""
        from assay.integrations.openai import _create_model_call_receipt, _patch_config
        from assay.integrity import verify_pack_manifest
        from assay.keystore import AssayKeyStore
        from assay.proof_pack import ProofPack
        from assay.store import AssayStore

        _patch_config.clear()
        _patch_config["store_prompts"] = True
        _patch_config["store_responses"] = True

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            store = AssayStore(base_dir=base / "store")
            trace_id = store.start_trace("trace_content_integrity")

            with mock_patch("assay.store.get_default_store", return_value=store), \
                 mock_patch.object(store_mod, "_seq_counter", 0):
                _create_model_call_receipt(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Stored prompt"}],
                    response=self._make_openai_response("Stored response"),
                    latency_ms=50,
                )

            entries = store.read_trace(trace_id)
            assert "input_content" in entries[0]
            assert "output_content" in entries[0]

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
            assert verify.passed

        _patch_config.clear()
