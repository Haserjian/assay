#!/usr/bin/env python3
from __future__ import annotations

import os

from openai import OpenAI


def main() -> None:
    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY", "specimen-local-key"),
        base_url=os.environ.get("SPECIMEN_BASE_URL", "http://127.0.0.1:8787/v1"),
    )
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "user",
                "content": "Reply with exactly five words about evidence.",
            }
        ],
        max_tokens=24,
    )
    print(response.choices[0].message.content)


if __name__ == "__main__":
    main()
