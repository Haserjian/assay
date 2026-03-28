"""Evidence bundle: declared metadata from an evaluation run.

For v0, evidence bundles are explicit declarations — a sidecar JSON or
YAML file alongside the proof pack. Auto-extraction is a later feature.

The bundle contains:
  - requested_config: what the operator intended
  - executed_config: what actually ran
  - field_sources: provenance for each field value

Bundle completeness is computed against a contract's required fields.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay.comparability.types import BundleCompleteness, FieldSource


# ---------------------------------------------------------------------------
# Evidence bundle
# ---------------------------------------------------------------------------

class EvidenceBundle:
    """Declared evidence metadata for one evaluation run.

    Fields are stored flat for contract evaluation. The requested/executed
    distinction and provenance are preserved as separate surfaces.
    """

    def __init__(
        self,
        *,
        fields: Dict[str, Any],
        label: str = "",
        ref: str = "",
        requested_config: Optional[Dict[str, Any]] = None,
        executed_config: Optional[Dict[str, Any]] = None,
        field_sources: Optional[Dict[str, str]] = None,
    ):
        self.fields = fields
        self.label = label
        self.ref = ref
        self.requested_config = requested_config or {}
        self.executed_config = executed_config or {}
        self.field_sources = field_sources or {}

    def get(self, field_name: str) -> Any:
        """Get a field value. Returns None if not present."""
        return self.fields.get(field_name)

    def has(self, field_name: str) -> bool:
        """Whether a field has usable evidence.

        Returns False if the key is absent OR the value is None.
        For comparability, null on a required parity field is missing
        evidence, not present evidence.
        """
        return field_name in self.fields and self.fields[field_name] is not None

    def config_diverged(self, field_name: str) -> bool:
        """Whether requested and executed config differ for a field.

        Returns False if either config doesn't declare the field.
        """
        if field_name not in self.requested_config:
            return False
        if field_name not in self.executed_config:
            return False
        return self.requested_config[field_name] != self.executed_config[field_name]

    def diverged_fields(self) -> List[str]:
        """Fields where requested != executed config."""
        return [
            f for f in self.requested_config
            if f in self.executed_config
            and self.requested_config[f] != self.executed_config[f]
        ]

    def get_source(self, field_name: str) -> Optional[FieldSource]:
        """Get provenance for a field."""
        source = self.field_sources.get(field_name)
        if source is None:
            return None
        return FieldSource(
            field=field_name,
            source=source,
            method="declared",
        )

    def completeness(self, required_fields: List[str]) -> BundleCompleteness:
        """Compute completeness against a list of required field names."""
        missing = [f for f in required_fields if not self.has(f)]
        present = [f for f in required_fields if self.has(f)]
        return BundleCompleteness(
            status="INCOMPLETE" if missing else "COMPLETE",
            missing_fields=missing,
            present_fields=present,
        )

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "fields": self.fields,
        }
        if self.label:
            d["label"] = self.label
        if self.ref:
            d["ref"] = self.ref
        if self.requested_config:
            d["requested_config"] = self.requested_config
        if self.executed_config:
            d["executed_config"] = self.executed_config
        if self.field_sources:
            d["field_sources"] = self.field_sources
        return d


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

BUNDLE_FILENAMES = [
    "evidence_bundle.json",
    "evidence_bundle.yaml",
    "evidence_bundle.yml",
    "judge_evidence.json",
    "judge_evidence.yaml",
]


def load_bundle(path: str | Path) -> EvidenceBundle:
    """Load an evidence bundle from a JSON or YAML file.

    The file should have this structure:
    {
      "label": "gpt-4o-mini @ v2.3 prompt",
      "ref": "path/to/proof_pack",
      "fields": {
        "judge_model": "gpt-4o",
        "judge_temperature": 0.0,
        ...
      },
      "requested_config": { ... },    // optional
      "executed_config": { ... },      // optional
      "field_sources": {               // optional
        "judge_model": "env:OPENAI_MODEL",
        "judge_prompt_template": "file:prompts/v2.3.txt"
      }
    }
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Evidence bundle not found: {path}")

    text = path.read_text(encoding="utf-8")

    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            raise ImportError(
                "PyYAML is required to load YAML bundles. "
                "Install with: pip install pyyaml"
            )
    else:
        data = json.loads(text)

    if not isinstance(data, dict):
        raise ValueError(f"Evidence bundle must be a JSON/YAML object, got {type(data).__name__}")

    fields = data.get("fields", {})
    if not isinstance(fields, dict):
        raise ValueError("Evidence bundle 'fields' must be a mapping")

    return EvidenceBundle(
        fields=fields,
        label=data.get("label", ""),
        ref=data.get("ref", ""),
        requested_config=data.get("requested_config"),
        executed_config=data.get("executed_config"),
        field_sources=data.get("field_sources"),
    )


def find_bundle(pack_dir: str | Path) -> Optional[Path]:
    """Find an evidence bundle sidecar in or alongside a proof pack directory."""
    pack_dir = Path(pack_dir)
    for name in BUNDLE_FILENAMES:
        # Check inside the pack directory
        candidate = pack_dir / name
        if candidate.exists():
            return candidate
        # Check alongside the pack directory
        candidate = pack_dir.parent / name
        if candidate.exists():
            return candidate
    return None
