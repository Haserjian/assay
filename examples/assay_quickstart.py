#!/usr/bin/env python3
"""
Assay Quickstart Example

Demonstrates the complete flow:
1. Emit receipts from your code
2. Build and verify a signed Proof Pack
3. Use integrations for automatic receipt emission

Run mock demo (no API key needed):
    pip install assay-ai
    python examples/assay_quickstart.py

Run with real OpenAI calls (requires OPENAI_API_KEY):
    pip install assay-ai[openai]
    python examples/assay_quickstart.py --live

Or just run the built-in demo:
    assay demo-pack
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def run_mock_demo():
    """Run demo with mocked API calls (no API key needed)."""
    from assay.store import emit_receipt, get_default_store

    print("=" * 60)
    print("ASSAY QUICKSTART DEMO (Mock Mode)")
    print("=" * 60)

    # Start a trace
    store = get_default_store()
    trace_id = store.start_trace()
    print(f"\n1. Started trace: {trace_id}")

    # Emit some receipts
    print("\n2. Emitting receipts...")

    r1 = emit_receipt("model_call", {
        "provider": "openai",
        "model_id": "gpt-4",
        "input_tokens": 15,
        "output_tokens": 42,
        "total_tokens": 57,
        "latency_ms": 234,
        "finish_reason": "stop",
    })
    print(f"   - model_call: gpt-4, 57 tokens, 234ms -> {r1['receipt_id']}")

    r2 = emit_receipt("model_call", {
        "provider": "openai",
        "model_id": "gpt-4",
        "input_tokens": 128,
        "output_tokens": 89,
        "total_tokens": 217,
        "latency_ms": 456,
        "finish_reason": "stop",
    })
    print(f"   - model_call: gpt-4, 217 tokens, 456ms -> {r2['receipt_id']}")

    r3 = emit_receipt("guardian_verdict", {
        "verdict": "allow",
        "tool": "web_search",
        "policy": "guardian_enforcement",
    })
    print(f"   - guardian_verdict: allow -> {r3['receipt_id']}")

    r4 = emit_receipt("model_call", {
        "provider": "openai",
        "model_id": "gpt-4",
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "latency_ms": 50,
        "finish_reason": "error",
        "error": "Rate limit exceeded",
    })
    print(f"   - model_call: ERROR (rate limit) -> {r4['receipt_id']}")

    # Show the trace
    print(f"\n3. Trace contents ({store.trace_file}):")
    entries = store.read_trace(trace_id)
    for i, entry in enumerate(entries, 1):
        t = entry.get("type", "unknown")
        model = entry.get("model_id", "")
        extra = f" - {model}" if model else ""
        print(f"   {i}. {t}{extra} (seq={entry.get('seq', '?')})")

    print(f"\n4. Receipts emitted: {len(entries)}")
    print(f"   Trace ID: {trace_id}")

    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("  # Run the built-in 60-second demo:")
    print("  assay demo-pack")
    print()
    print("  # Wrap a command and build a Proof Pack:")
    print("  assay run -- python my_agent.py")
    print()
    print("  # Verify a Proof Pack:")
    print("  assay verify-pack ./proof_pack_*/")
    print()
    print("  # CI gate (fail if claims don't pass):")
    print("  assay verify-pack ./proof_pack_*/ --require-claim-pass")


def run_live_demo():
    """Run demo with real OpenAI API calls."""
    try:
        from openai import OpenAI  # noqa: F401
    except ImportError:
        print("ERROR: openai package not installed")
        print("Install with: pip install assay-ai[openai]")
        sys.exit(1)

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set")
        print("Set with: export OPENAI_API_KEY=sk-...")
        sys.exit(1)

    print("=" * 60)
    print("ASSAY QUICKSTART DEMO (Live Mode)")
    print("=" * 60)

    # Patch OpenAI to auto-emit receipts
    from assay.integrations.openai import patch
    patch()
    print("\n1. Patched OpenAI client to emit receipts")

    from assay.store import get_default_store
    store = get_default_store()
    trace_id = store.trace_id
    print(f"   Trace: {trace_id}")

    # Make real API calls
    print("\n2. Making real OpenAI API calls...")
    client = OpenAI()

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Say 'Hello from Assay!' in exactly 5 words."}],
            max_tokens=20,
        )
        print(f"   Response: {response.choices[0].message.content}")
        print(f"   Tokens: {response.usage.total_tokens}, Finish: {response.choices[0].finish_reason}")
    except Exception as e:
        print(f"   Call failed: {e}")

    # Show trace
    print("\n3. Trace contents:")
    entries = store.read_trace(trace_id)
    for i, entry in enumerate(entries, 1):
        t = entry.get("type", "unknown")
        model = entry.get("model_id", "N/A")
        tokens = entry.get("total_tokens", "N/A")
        print(f"   {i}. {t} - {model} - {tokens} tokens")

    print(f"\n4. Receipts emitted: {len(entries)}")

    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print(f"\nTrace ID: {trace_id}")
    print("\nYour AI calls are now leaving cryptographic receipts!")
    print("\nNext: assay run -- python my_agent.py")


def main():
    parser = argparse.ArgumentParser(description="Assay Quickstart Demo")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use real OpenAI API calls (requires OPENAI_API_KEY)",
    )
    args = parser.parse_args()

    if args.live:
        run_live_demo()
    else:
        run_mock_demo()


if __name__ == "__main__":
    main()
