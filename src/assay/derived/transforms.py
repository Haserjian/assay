"""Deterministic transforms for receipted derived context."""

from __future__ import annotations

import inspect
import platform
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from assay.derived.hashing import canonical_hash, stable_id
from assay.derived.models import TransformSpec


DEFAULT_CHUNKER_VERSION = "0.1.0"
DEFAULT_MAX_LINES = 80


@dataclass(frozen=True)
class TextChunk:
    chunk_index: int
    start_line: int
    end_line: int
    text: str
    output_hash: str

    def output_payload(self) -> Dict[str, Any]:
        return {
            "artifact_type": "source_chunk",
            "chunk_index": self.chunk_index,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "text": self.text,
        }


def chunk_lines(text: str, max_lines: int = DEFAULT_MAX_LINES) -> List[TextChunk]:
    if max_lines < 1:
        raise ValueError("max_lines must be >= 1")
    lines = text.splitlines()
    if text and text.endswith("\n"):
        # splitlines() drops the final empty line. That is fine for line chunks:
        # the text payload below preserves joined line content deterministically.
        pass
    if not lines:
        return []

    chunks: List[TextChunk] = []
    for offset in range(0, len(lines), max_lines):
        selected = lines[offset : offset + max_lines]
        start_line = offset + 1
        end_line = offset + len(selected)
        chunk_text = "\n".join(selected)
        payload = {
            "artifact_type": "source_chunk",
            "chunk_index": len(chunks),
            "start_line": start_line,
            "end_line": end_line,
            "text": chunk_text,
        }
        chunks.append(
            TextChunk(
                chunk_index=len(chunks),
                start_line=start_line,
                end_line=end_line,
                text=chunk_text,
                output_hash=canonical_hash(payload),
            )
        )
    return chunks


def line_chunk_transform_spec(
    *,
    version: str = DEFAULT_CHUNKER_VERSION,
    max_lines: int = DEFAULT_MAX_LINES,
    code_hash_override: Optional[str] = None,
    runtime_hash_override: Optional[str] = None,
) -> TransformSpec:
    config_hash = canonical_hash({"max_lines": max_lines})
    if code_hash_override is None:
        try:
            source = inspect.getsource(chunk_lines)
        except OSError:
            source = "chunk_lines"
        code_hash = canonical_hash({"function": "chunk_lines", "source": source})
    else:
        code_hash = code_hash_override

    runtime_hash = runtime_hash_override
    if runtime_hash is None:
        runtime_hash = canonical_hash(
            {
                "python_implementation": platform.python_implementation(),
                "python_version": platform.python_version(),
            }
        )

    transform_id = stable_id(
        "xfm",
        {
            "name": "line_chunker",
            "version": version,
            "code_hash": code_hash,
            "config_hash": config_hash,
            "runtime_hash": runtime_hash,
        },
    )
    return TransformSpec(
        transform_id=transform_id,
        name="line_chunker",
        version=version,
        code_hash=code_hash,
        config_hash=config_hash,
        runtime_hash=runtime_hash,
    )
