#!/usr/bin/env python3
"""Minimal LLM-as-judge eval runner for Assay organic precedent.

Scores 5 hardcoded items on helpfulness (1-5) using an OpenAI model,
then emits an evidence bundle JSON suitable for `assay gate compare`.

Usage:
    python eval_runner.py --run-id run_a --output-dir organic/run_a
    python eval_runner.py --run-id run_b --output-dir organic/run_b --max-tokens 256
    python eval_runner.py --run-id run_c --output-dir organic/run_c --prompt-variant v2
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Dataset (hardcoded, 5 items)
# ---------------------------------------------------------------------------
DATASET = [
    {"id": "q1", "question": "What is photosynthesis?", "response": "Photosynthesis is how plants convert sunlight into energy using chlorophyll."},
    {"id": "q2", "question": "Explain gravity.", "response": "Gravity is the force that attracts objects with mass toward each other."},
    {"id": "q3", "question": "What causes rain?", "response": "Water evaporates, condenses into clouds, and falls as precipitation."},
    {"id": "q4", "question": "How do vaccines work?", "response": "Vaccines train your immune system to recognize pathogens by exposing it to weakened or inactive forms."},
    {"id": "q5", "question": "Why is the sky blue?", "response": "Sunlight scatters off air molecules, and blue wavelengths scatter more than others."},
]

SYSTEM_PROMPT = "You are an expert evaluator. Score the response on helpfulness.\n"

PROMPT_TEMPLATES = {
    "v1": (
        "Rate the following response on helpfulness from 1 to 5.\n"
        "Consider clarity, completeness, and accuracy.\n"
        "Reply with ONLY a single integer (1-5).\n\n"
        "Question: {question}\n"
        "Response: {response}\n"
    ),
    "v2": (
        "Rate the following response on helpfulness from 1 to 5.\n"
        "Consider clarity, completeness, accuracy, and relevance.\n"
        "Reply with ONLY a single integer (1-5).\n\n"
        "Question: {question}\n"
        "Response: {response}\n"
    ),
}

RUBRIC = "1=unhelpful, 2=slightly helpful, 3=moderately helpful, 4=helpful, 5=very helpful\n"


def content_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def run_eval(model: str, temperature: float, max_tokens: int, prompt_template: str) -> list[dict]:
    from openai import OpenAI

    client = OpenAI()  # uses OPENAI_API_KEY from env
    results = []
    for item in DATASET:
        prompt = prompt_template.format(**item)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        raw = resp.choices[0].message.content.strip()
        try:
            score = int(raw)
        except ValueError:
            score = -1  # parse failure recorded honestly
        results.append({
            "id": item["id"],
            "score": score,
            "raw_output": raw,
            "model": resp.model,
            "usage": {"prompt_tokens": resp.usage.prompt_tokens, "completion_tokens": resp.usage.completion_tokens},
        })
    return results


def build_bundle(
    results: list[dict],
    *,
    run_id: str,
    model: str,
    temperature: float,
    max_tokens: int,
    prompt_template: str,
) -> dict:
    """Build an evidence bundle matching judge-comparability-v1 contract."""
    dataset_str = json.dumps(DATASET, sort_keys=True)
    actual_model = results[0]["model"] if results else model
    return {
        "label": f"{actual_model} @ {run_id}",
        "ref": f"examples/llm_judge/organic/{run_id}",
        "fields": {
            "judge_model": model,
            "judge_model_version": actual_model,
            "judge_prompt_template": prompt_template,
            "judge_system_prompt": SYSTEM_PROMPT,
            "scoring_rubric": RUBRIC,
            "score_type": "likert",
            "score_range": "1-5",
            "judge_temperature": temperature,
            "judge_max_tokens": max_tokens,
            "judge_top_p": 1.0,
            "judge_passes": 1,
            "eval_dataset": content_hash(dataset_str),
            "eval_dataset_version": "v1-hardcoded",
            "presentation_order": "fixed",
            "input_format": content_hash(prompt_template),
        },
        "requested_config": {
            "judge_model": model,
            "judge_temperature": temperature,
            "judge_max_tokens": max_tokens,
        },
        "executed_config": {
            "judge_model": actual_model,
            "judge_temperature": temperature,
            "judge_max_tokens": max_tokens,
        },
        "field_sources": {
            "judge_model": "arg:--model (CLI)",
            "judge_prompt_template": "inline:eval_runner.py:PROMPT_TEMPLATE",
            "judge_temperature": "arg:--temperature (CLI)",
            "eval_dataset": "inline:eval_runner.py:DATASET",
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Minimal LLM-as-judge eval")
    parser.add_argument("--run-id", required=True, help="Run identifier (e.g. run_a)")
    parser.add_argument("--output-dir", required=True, help="Output directory for results + bundle")
    parser.add_argument("--model", default="gpt-4o-mini", help="Judge model")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument("--prompt-variant", choices=list(PROMPT_TEMPLATES), default="v1", help="Prompt template variant")
    args = parser.parse_args()

    prompt_template = PROMPT_TEMPLATES[args.prompt_variant]
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    print(f"Running eval: {args.run_id} (model={args.model}, temp={args.temperature}, max_tokens={args.max_tokens}, prompt={args.prompt_variant})")
    results = run_eval(args.model, args.temperature, args.max_tokens, prompt_template)

    scores = [r["score"] for r in results]
    mean_score = sum(scores) / len(scores) if scores else 0
    print(f"  Scores: {scores}  Mean: {mean_score:.2f}")

    # Write results
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")

    # Write evidence bundle
    bundle = build_bundle(
        results,
        run_id=args.run_id,
        model=args.model,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        prompt_template=prompt_template,
    )
    (out / "evidence_bundle.json").write_text(json.dumps(bundle, indent=2) + "\n")

    print(f"  Results: {out / 'results.json'}")
    print(f"  Bundle:  {out / 'evidence_bundle.json'}")


if __name__ == "__main__":
    main()
