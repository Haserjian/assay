"""
Assay Scanner: find uninstrumented LLM call sites.

AST-based detection of LLM SDK calls and whether evidence emission
exists nearby. Designed for conversion, not static analysis purity.

Confidence levels:
  high   - direct SDK call detected (openai, anthropic)
  medium - likely wrapper call (langchain invoke, known patterns)
  low    - heuristic name match (llm/model/chat/completion in function name)
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CallSite:
    """A detected LLM call site."""
    path: str
    line: int
    call: str
    confidence: Confidence
    instrumented: bool
    fix: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "path": self.path,
            "line": self.line,
            "call": self.call,
            "confidence": self.confidence.value,
            "instrumented": self.instrumented,
        }
        if self.fix:
            d["fix"] = self.fix
        return d


@dataclass
class ScanResult:
    """Result of scanning a project."""
    findings: List[CallSite] = field(default_factory=list)

    @property
    def summary(self) -> Dict[str, int]:
        total = len(self.findings)
        instrumented = sum(1 for f in self.findings if f.instrumented)
        uninstrumented = total - instrumented
        high = sum(1 for f in self.findings if not f.instrumented and f.confidence == Confidence.HIGH)
        medium = sum(1 for f in self.findings if not f.instrumented and f.confidence == Confidence.MEDIUM)
        low = sum(1 for f in self.findings if not f.instrumented and f.confidence == Confidence.LOW)
        return {
            "sites_total": total,
            "instrumented": instrumented,
            "uninstrumented": uninstrumented,
            "high": high,
            "medium": medium,
            "low": low,
        }

    @property
    def status(self) -> str:
        s = self.summary
        if s["high"] > 0:
            return "fail"
        if s["medium"] > 0 or s["low"] > 0:
            return "warn"
        return "pass"

    @property
    def next_command(self) -> Optional[str]:
        if not self.findings:
            return None

        patch_line = _recommended_patch_line(self.findings)
        if patch_line:
            return (
                "1) Add instrumentation in your entrypoint:\n"
                f"   {patch_line}\n"
                "\n"
                "2) Generate a proof pack:\n"
                "   assay run -c receipt_completeness -- python your_app.py\n"
                "\n"
                "3) Verify and lock your baseline:\n"
                "   assay verify-pack ./proof_pack_*/\n"
                "   assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock"
            )

        return (
            "1) Add receipt emission near your LLM wrapper:\n"
            "   from assay import emit_receipt\n"
            "   emit_receipt('model_call', {'provider': '...', 'model_id': '...'})\n"
            "\n"
            "2) Generate a proof pack:\n"
            "   assay run -c receipt_completeness -- python your_app.py\n"
            "\n"
            "3) Verify and lock your baseline:\n"
            "   assay verify-pack ./proof_pack_*/\n"
            "   assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "assay-scan",
            "status": self.status,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "next_command": self.next_command,
        }


def _detect_frameworks(findings: List[CallSite]) -> Set[str]:
    """Detect which frameworks are present from call signatures."""
    frameworks: Set[str] = set()
    for f in findings:
        call_lower = f.call.lower()
        if "openai" in call_lower or "chat.completions" in call_lower:
            frameworks.add("openai")
        elif "anthropic" in call_lower or "messages.create" in call_lower:
            frameworks.add("anthropic")
        elif "langchain" in call_lower or "invoke" in call_lower:
            frameworks.add("langchain")
    return frameworks


def _recommended_patch_line(findings: List[CallSite]) -> Optional[str]:
    frameworks = _detect_frameworks(findings)
    if "openai" in frameworks:
        return "from assay.integrations.openai import patch; patch()"
    if "anthropic" in frameworks:
        return "from assay.integrations.anthropic import patch; patch()"
    if "langchain" in frameworks:
        return "from assay.integrations.langchain import patch; patch()"
    return None


# ---------------------------------------------------------------------------
# AST patterns
# ---------------------------------------------------------------------------

# High confidence: direct SDK calls
_HIGH_PATTERNS = [
    # OpenAI
    ("chat.completions.create", "openai"),
    ("completions.create", "openai"),
    # Anthropic
    ("messages.create", "anthropic"),
    # Azure OpenAI
    ("chat_completions.create", "openai"),
]

# Medium confidence: framework calls (always match)
_MEDIUM_PATTERNS = [
    # LangChain wrapper constructors (unambiguous)
    ("ChatOpenAI(", "langchain"),
    ("ChatAnthropic(", "langchain"),
    # LiteLLM (unambiguous namespace)
    ("litellm.completion(", "litellm"),
    ("litellm.acompletion(", "litellm"),
]

# Medium confidence: generic patterns that need framework import evidence
# These match too broadly without import context (e.g., ctx.invoke, db.invoke)
_MEDIUM_GUARDED_PATTERNS = [
    (".invoke(", "langchain"),
    (".ainvoke(", "langchain"),
    ("llm.predict(", "langchain"),
    ("llm.apredict(", "langchain"),
]

# Imports that qualify a file as "framework-adjacent" for guarded patterns
_FRAMEWORK_IMPORT_PREFIXES = {
    "langchain", "langgraph", "llama_index", "litellm",
    "langchain_core", "langchain_community", "langchain_openai",
    "langchain_anthropic", "llama_index.core",
}

# Low confidence: heuristic name patterns in function/method calls
_LOW_HEURISTIC_NAMES = {
    "llm_call", "call_llm", "query_model", "call_model",
    "generate_response", "chat_completion", "model_inference",
    "run_model", "ask_llm", "prompt_model",
}

# Instrumentation evidence patterns
_INSTRUMENTATION_IMPORTS = {
    "emit_receipt",
    "assay.integrations.openai",
    "assay.integrations.anthropic",
    "assay.integrations.langchain",
}

_INSTRUMENTATION_CALLS = {
    "emit_receipt",
    "patch",
    "_assay_emit",
}


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _LLMCallVisitor(ast.NodeVisitor):
    """AST visitor that finds LLM call sites and instrumentation evidence."""

    def __init__(self) -> None:
        self.call_sites: List[tuple[int, str, Confidence]] = []
        self.has_instrumentation = False
        self.has_framework_imports = False
        self._imports: Set[str] = set()
        self._calls: Set[str] = set()
        self._deferred_medium: List[tuple[int, str]] = []

    def resolve_deferred(self) -> None:
        """Promote deferred guarded patterns based on collected import evidence."""
        if self.has_framework_imports:
            for line, call in self._deferred_medium:
                self.call_sites.append((line, call, Confidence.MEDIUM))
        # If no framework imports, guarded patterns are silently dropped

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._imports.add(alias.name)
            if any(pat in alias.name for pat in _INSTRUMENTATION_IMPORTS):
                self.has_instrumentation = True
            if any(alias.name == pfx or alias.name.startswith(pfx + ".") for pfx in _FRAMEWORK_IMPORT_PREFIXES):
                self.has_framework_imports = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self._imports.add(full)
            self._imports.add(alias.name)
            if alias.name in _INSTRUMENTATION_IMPORTS or module in _INSTRUMENTATION_IMPORTS:
                self.has_instrumentation = True
            if any(pat in full for pat in _INSTRUMENTATION_IMPORTS):
                self.has_instrumentation = True
        if any(module == pfx or module.startswith(pfx + ".") for pfx in _FRAMEWORK_IMPORT_PREFIXES):
            self.has_framework_imports = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_str = _call_to_string(node.func)
        if call_str:
            # Check for instrumentation calls
            name_parts = call_str.split(".")
            if name_parts[-1] in _INSTRUMENTATION_CALLS:
                self.has_instrumentation = True
                self._calls.add(call_str)

            # Check high-confidence patterns
            for pattern, _framework in _HIGH_PATTERNS:
                if pattern in call_str:
                    self.call_sites.append((node.lineno, call_str, Confidence.HIGH))
                    break
            else:
                # Check medium-confidence patterns (always match)
                for pattern, _framework in _MEDIUM_PATTERNS:
                    pat = pattern.rstrip("(")
                    if pat in call_str:
                        self.call_sites.append((node.lineno, call_str, Confidence.MEDIUM))
                        break
                else:
                    # Check guarded medium patterns (need framework imports)
                    # Store as deferred -- resolved after full tree walk
                    for pattern, _framework in _MEDIUM_GUARDED_PATTERNS:
                        pat = pattern.rstrip("(")
                        if pat in call_str:
                            self._deferred_medium.append((node.lineno, call_str))
                            break
                    else:
                        # Check low-confidence heuristics
                        func_name = name_parts[-1].lower()
                        if func_name in _LOW_HEURISTIC_NAMES:
                            self.call_sites.append((node.lineno, call_str, Confidence.LOW))

        self.generic_visit(node)


def _call_to_string(node: ast.expr) -> Optional[str]:
    """Convert an AST call target to a readable string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value = _call_to_string(node.value)
        if value:
            return f"{value}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Subscript):
        value = _call_to_string(node.value)
        return value
    return None


# ---------------------------------------------------------------------------
# Fix suggestions
# ---------------------------------------------------------------------------

def _suggest_fix(call: str) -> str:
    """Suggest a fix based on the detected call pattern."""
    call_lower = call.lower()
    # LangChain wrappers first (ChatOpenAI contains "openai", ChatAnthropic contains "anthropic")
    if "langchain" in call_lower or call_lower.startswith("chatopen") or call_lower.startswith("chatanthropic"):
        return "from assay.integrations.langchain import patch; patch()"
    if "openai" in call_lower or "chat.completions" in call_lower or "completions.create" in call_lower:
        return "from assay.integrations.openai import patch; patch()"
    if "anthropic" in call_lower or "messages.create" in call_lower:
        return "from assay.integrations.anthropic import patch; patch()"
    return "from assay import emit_receipt  # add emit_receipt() after this call"


# ---------------------------------------------------------------------------
# File scanner
# ---------------------------------------------------------------------------

def _should_scan(path: Path, include: Optional[List[str]], exclude: Optional[List[str]]) -> bool:
    """Check if a file should be scanned based on include/exclude patterns."""
    rel = str(path)

    if exclude:
        for pat in exclude:
            if fnmatch(rel, pat):
                return False

    if include:
        return any(fnmatch(rel, pat) for pat in include)

    return True


def scan_file(filepath: Path) -> tuple[List[CallSite], bool]:
    """Scan a single Python file for LLM call sites.

    Returns (call_sites, has_instrumentation).
    """
    try:
        source = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], False

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return [], False

    visitor = _LLMCallVisitor()
    visitor.visit(tree)
    visitor.resolve_deferred()

    rel_path = str(filepath)
    sites = []
    for line, call, confidence in visitor.call_sites:
        sites.append(CallSite(
            path=rel_path,
            line=line,
            call=call,
            confidence=confidence,
            instrumented=visitor.has_instrumentation,
            fix=None if visitor.has_instrumentation else _suggest_fix(call),
        ))

    return sites, visitor.has_instrumentation


def scan_directory(
    root: Path,
    *,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
) -> ScanResult:
    """Scan a directory tree for LLM call sites.

    Args:
        root: Directory to scan.
        include: Glob patterns to include (default: all .py files).
        exclude: Glob patterns to exclude (default: common non-source dirs).

    Returns:
        ScanResult with all findings.
    """
    root = Path(root).resolve()
    result = ScanResult()

    # Default excludes
    default_exclude = {
        ".venv", "venv", "node_modules", ".git", "__pycache__",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
        ".eggs", "*.egg-info",
        "challenge_pack",
    }

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip excluded directories (including assay-generated proof_pack_* dirs)
        dirnames[:] = [
            d for d in dirnames
            if d not in default_exclude
            and not d.startswith(".")
            and not d.startswith("proof_pack_")
        ]

        for filename in filenames:
            if not filename.endswith(".py"):
                continue

            filepath = Path(dirpath) / filename
            try:
                rel_path = filepath.relative_to(root)
            except ValueError:
                rel_path = filepath

            if not _should_scan(rel_path, include, exclude):
                continue

            sites, _has_instrumentation = scan_file(filepath)
            # Update paths to relative
            for site in sites:
                site.path = str(rel_path)
            result.findings.extend(sites)

    # Sort by path and line
    result.findings.sort(key=lambda f: (f.path, f.line))
    return result
