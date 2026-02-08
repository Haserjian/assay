"""
Runtime schema enforcement for Proof Pack manifests and attestations.

Validates pack_manifest.json against schemas/pack_manifest.schema.json
and attestation against schemas/attestation.schema.json.

Schemas are bundled inside the assay package (src/assay/schemas/) so they
are always available in installed wheels.  Validation FAILS CLOSED: if
schemas cannot be loaded, errors are reported rather than silently skipped.

Called during build (catch errors at pack time) and verify (catch malformed
packs from external sources).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import referencing
import referencing.jsonschema
from jsonschema import Draft202012Validator

# ---------------------------------------------------------------------------
# Schema loading -- package-relative, fail closed
# ---------------------------------------------------------------------------

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"

_manifest_validator = None
_attestation_validator = None


def _load_validators() -> tuple:
    """Load and cache schema validators with $ref resolution."""
    global _manifest_validator, _attestation_validator
    if _manifest_validator is not None:
        return _manifest_validator, _attestation_validator

    att_path = _SCHEMA_DIR / "attestation.schema.json"
    manifest_path = _SCHEMA_DIR / "pack_manifest.schema.json"

    if not att_path.exists() or not manifest_path.exists():
        raise FileNotFoundError(
            f"Schema files not found in {_SCHEMA_DIR}. "
            f"Expected attestation.schema.json and pack_manifest.schema.json. "
            f"This usually means the package was installed incorrectly."
        )

    att_schema = json.loads(att_path.read_text())
    manifest_schema = json.loads(manifest_path.read_text())

    # Build registry for $ref resolution between schemas
    registry = referencing.Registry().with_resources([
        (att_schema["$id"], referencing.Resource.from_contents(att_schema)),
        (manifest_schema["$id"], referencing.Resource.from_contents(manifest_schema)),
    ])

    _manifest_validator = Draft202012Validator(manifest_schema, registry=registry)
    _attestation_validator = Draft202012Validator(att_schema, registry=registry)

    return _manifest_validator, _attestation_validator


# ---------------------------------------------------------------------------
# Validation -- fail closed
# ---------------------------------------------------------------------------

def validate_manifest(manifest: Dict[str, Any]) -> List[str]:
    """Validate a signed manifest against its JSON schema.

    Returns a list of error messages (empty = valid).
    Raises FileNotFoundError if schemas are missing (fail closed).
    """
    validator, _ = _load_validators()

    errors = []
    for error in sorted(validator.iter_errors(manifest), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"{path}: {error.message}")
    return errors


def validate_attestation(attestation: Dict[str, Any]) -> List[str]:
    """Validate an attestation object against its JSON schema.

    Returns a list of error messages (empty = valid).
    Raises FileNotFoundError if schemas are missing (fail closed).
    """
    _, validator = _load_validators()

    errors = []
    for error in sorted(validator.iter_errors(attestation), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"{path}: {error.message}")
    return errors


__all__ = ["validate_manifest", "validate_attestation"]
