"""Auto-insert SDK integration patches into entrypoint files."""
from __future__ import annotations

import difflib
import re
import shutil
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from assay.scanner import ScanResult, _detect_frameworks


# ---------------------------------------------------------------------------
# Import line templates
# ---------------------------------------------------------------------------

_PATCH_LINES: Dict[str, str] = {
    "openai": "from assay.integrations.openai import patch; patch()",
    "anthropic": "from assay.integrations.anthropic import patch; patch()",
    "google": "from assay.integrations.google import patch; patch()",
    "litellm": "from assay.integrations.litellm import patch; patch()",
}

_PATCH_LINES_ALIASED: Dict[str, str] = {
    "openai": "from assay.integrations.openai import patch as patch_openai; patch_openai()",
    "anthropic": "from assay.integrations.anthropic import patch as patch_anthropic; patch_anthropic()",
    "google": "from assay.integrations.google import patch as patch_google; patch_google()",
    "litellm": "from assay.integrations.litellm import patch as patch_litellm; patch_litellm()",
}

_LANGCHAIN_NOTE = (
    "LangChain detected. LangChain uses callbacks, not global patching.\n"
    "Add manually:\n"
    "  from assay.integrations.langchain import AssayCallbackHandler\n"
    "  handler = AssayCallbackHandler()\n"
    "Then pass handler to your LLM's callbacks parameter."
)

# Frameworks that support auto-patching (global monkey-patch)
_PATCHABLE = {"openai", "anthropic", "google", "litellm"}

# Marker comment appended to auto-inserted lines
_PATCH_MARKER = "  # assay:patched"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PatchPlan:
    """Plan for patching an entrypoint file."""
    entrypoint: str
    frameworks: List[str]
    lines_to_insert: List[str]
    insertion_line: int
    already_patched: List[str] = field(default_factory=list)
    langchain_note: Optional[str] = None

    @property
    def has_work(self) -> bool:
        return len(self.lines_to_insert) > 0

    def to_dict(self) -> dict:
        return {
            "entrypoint": self.entrypoint,
            "frameworks": self.frameworks,
            "lines_to_insert": self.lines_to_insert,
            "insertion_line": self.insertion_line,
            "already_patched": self.already_patched,
            "langchain_note": self.langchain_note,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_insertion_point(lines: List[str]) -> int:
    """Find the line index where patch imports should be inserted.

    Skips: shebang, module docstring, __future__ imports, blank lines
    between them. Returns the index of the first "real" import or code line.
    """
    idx = 0
    n = len(lines)

    # Skip shebang
    if idx < n and lines[idx].startswith("#!"):
        idx += 1

    # Skip blank lines after shebang
    while idx < n and lines[idx].strip() == "":
        idx += 1

    # Skip module docstring (triple-quoted)
    if idx < n:
        stripped = lines[idx].strip()
        for quote in ('"""', "'''"):
            if stripped.startswith(quote):
                # Check if docstring closes on same line
                rest = stripped[3:]
                if quote in rest:
                    idx += 1
                    break
                # Multi-line docstring: find closing quote
                idx += 1
                while idx < n and quote not in lines[idx]:
                    idx += 1
                if idx < n:
                    idx += 1  # skip the closing line
                break

    # Skip blank lines after docstring
    while idx < n and lines[idx].strip() == "":
        idx += 1

    # Skip __future__ imports
    while idx < n and re.match(r"^from\s+__future__\s+import\s+", lines[idx]):
        idx += 1

    # Skip blank lines after __future__
    while idx < n and lines[idx].strip() == "":
        idx += 1

    return idx


def _check_already_patched(lines: List[str]) -> Set[str]:
    """Check which frameworks already have assay patch lines in the file."""
    patched: Set[str] = set()
    for line in lines:
        if "from assay.integrations.openai import patch" in line:
            patched.add("openai")
        if "from assay.integrations.anthropic import patch" in line:
            patched.add("anthropic")
    return patched


def _pick_entrypoint(scan_result: ScanResult) -> Optional[str]:
    """Pick the best entrypoint file from scan results.

    Returns the file with the most uninstrumented call sites.
    """
    uninstrumented = [f for f in scan_result.findings if not f.instrumented]
    if not uninstrumented:
        return None
    counts = Counter(f.path for f in uninstrumented)
    return counts.most_common(1)[0][0]


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

def plan_patch(
    scan_result: ScanResult,
    root: Path,
    entrypoint: Optional[str] = None,
) -> PatchPlan:
    """Analyze scan results and produce a patch plan."""
    uninstrumented = [f for f in scan_result.findings if not f.instrumented]
    frameworks_detected = _detect_frameworks(uninstrumented)
    patchable = sorted(frameworks_detected & _PATCHABLE)

    # Pick entrypoint
    ep = entrypoint or _pick_entrypoint(scan_result)
    if ep is None:
        return PatchPlan(
            entrypoint="",
            frameworks=sorted(frameworks_detected),
            lines_to_insert=[],
            insertion_line=0,
            langchain_note=_LANGCHAIN_NOTE if "langchain" in frameworks_detected else None,
        )

    # Read the entrypoint file
    ep_path = root / ep
    if not ep_path.is_file():
        raise FileNotFoundError(f"Entrypoint not found: {ep}")

    content = ep_path.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)
    lines_stripped = [l.rstrip("\n\r") for l in lines]

    # Check what's already patched
    already = _check_already_patched(lines_stripped)
    needed = [fw for fw in patchable if fw not in already]

    # Build import lines
    if len(needed) == 1:
        import_lines = [_PATCH_LINES[needed[0]]]
    elif len(needed) > 1:
        import_lines = [_PATCH_LINES_ALIASED[fw] for fw in needed]
    else:
        import_lines = []

    insertion_line = _find_insertion_point(lines_stripped)

    return PatchPlan(
        entrypoint=ep,
        frameworks=sorted(frameworks_detected),
        lines_to_insert=import_lines,
        insertion_line=insertion_line,
        already_patched=sorted(already),
        langchain_note=_LANGCHAIN_NOTE if "langchain" in frameworks_detected else None,
    )


def _build_modified(original: List[str], plan: PatchPlan) -> List[str]:
    """Build the modified file content from a patch plan."""
    modified = list(original)
    for i, line in enumerate(plan.lines_to_insert):
        modified.insert(plan.insertion_line + i, line + _PATCH_MARKER + "\n")
    return modified


def generate_diff(plan: PatchPlan, root: Path) -> str:
    """Generate a unified diff showing what would change."""
    if not plan.has_work:
        return ""

    ep_path = root / plan.entrypoint
    original = ep_path.read_text(encoding="utf-8").splitlines(keepends=True)
    modified = _build_modified(original, plan)

    diff = difflib.unified_diff(
        original,
        modified,
        fromfile=f"a/{plan.entrypoint}",
        tofile=f"b/{plan.entrypoint}",
        lineterm="",
    )
    return "\n".join(l.rstrip() for l in diff)


def backup_file(path: Path) -> Path:
    """Copy file to .assay.bak before patching. Returns path to backup."""
    bak = path.with_suffix(path.suffix + ".assay.bak")
    shutil.copy2(path, bak)
    return bak


def undo_patch(root: Path, entrypoint: str) -> bool:
    """Restore entrypoint from .assay.bak. Returns True if restored."""
    ep_path = root / entrypoint
    bak = ep_path.with_suffix(ep_path.suffix + ".assay.bak")
    if not bak.exists():
        return False
    shutil.copy2(bak, ep_path)
    bak.unlink()
    return True


def apply_patch(plan: PatchPlan, root: Path, *, backup: bool = True) -> str:
    """Apply the patch plan. Returns the unified diff string."""
    if not plan.has_work:
        return ""

    diff = generate_diff(plan, root)

    ep_path = root / plan.entrypoint
    if backup:
        backup_file(ep_path)

    original = ep_path.read_text(encoding="utf-8").splitlines(keepends=True)
    modified = _build_modified(original, plan)

    ep_path.write_text("".join(modified), encoding="utf-8")
    return diff
