"""Pydantic compatibility shims for environments running v1 or v2."""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Type, TypeVar, cast

import pydantic

_T = TypeVar("_T")
_ModelT = TypeVar("_ModelT", bound="BaseModel")


def _parse_version(raw: str) -> Tuple[int, ...]:
    parts: list[int] = []
    for token in raw.split("."):
        try:
            parts.append(int(token))
        except ValueError:
            break
    return tuple(parts)


_VERSION = _parse_version(getattr(pydantic, "__version__", "1.0"))


def is_v2() -> bool:
    """Return True when running under pydantic v2+."""

    return bool(_VERSION and _VERSION[0] >= 2)


__all__ = [
    "BaseModel",
    "BaseModelLike",
    "ConfigDict",
    "ConfigDictLike",
    "Field",
    "FieldLike",
    "field_validator",
    "field_validator_like",
    "is_v2",
    "model_serializer",
    "model_validator",
    "model_validator_like",
]


if is_v2():  # pragma: no cover - exercised in v2 environments
    from pydantic import BaseModel as _BaseModel
    from pydantic import ConfigDict as _ConfigDict
    from pydantic import Field as _Field
    from pydantic import field_validator as _field_validator
    from pydantic import model_serializer
    from pydantic import model_validator as _model_validator

    BaseModelLike = _BaseModel
    FieldLike = _Field
    field_validator_like = _field_validator
    model_validator_like = _model_validator

    def ConfigDictLike(**kwargs: Any) -> Mapping[str, Any]:
        config = dict(kwargs)
        config.setdefault("protected_namespaces", ())
        return _ConfigDict(**config)  # type: ignore[call-arg]

    ConfigDict = ConfigDictLike
    BaseModel = BaseModelLike
    Field = FieldLike
    field_validator = field_validator_like
    model_validator = model_validator_like
    BaseModelLike.model_config = ConfigDictLike()  # type: ignore[assignment]
else:  # pragma: no cover - exercised in v1 environments
    from pydantic import BaseModel as _V1BaseModel
    from pydantic import Field
    from pydantic import root_validator, validator

    FieldLike = Field

    def ConfigDictLike(**kwargs: Any) -> Dict[str, Any]:
        return dict(kwargs)

    ConfigDict = ConfigDictLike

    def _translate_config(config: Mapping[str, Any]) -> Dict[str, Any]:
        translated: Dict[str, Any] = dict(config)
        result: Dict[str, Any] = {}

        if "frozen" in translated:
            frozen = bool(translated.pop("frozen"))
            result["allow_mutation"] = not frozen

        if "populate_by_name" in translated:
            result["allow_population_by_field_name"] = bool(translated.pop("populate_by_name"))

        if "json_schema_extra" in translated:
            result["schema_extra"] = translated.pop("json_schema_extra")

        if "protected_namespaces" in translated:
            # No direct analogue in v1; drop silently.
            translated.pop("protected_namespaces")

        result.update(translated)
        return result

    class BaseModel(_V1BaseModel):  # type: ignore[misc]
        model_config: Dict[str, Any] = {}
        model_fields: Dict[str, Any] = {}

        def __init_subclass__(cls, **kwargs: Any) -> None:
            config_dict = getattr(cls, "model_config", None)
            if config_dict:
                translated = _translate_config(config_dict)
                existing = getattr(cls, "Config", None)
                base: Dict[str, Any] = {}
                if existing is not None:
                    base.update(
                        {
                            key: getattr(existing, key)
                            for key in dir(existing)
                            if not key.startswith("_") and hasattr(existing, key)
                        }
                    )
                base.update(translated)
                config_cls = type("Config", (), base)
                cls.Config = config_cls  # type: ignore[assignment]
                cls.__config__ = config_cls  # type: ignore[attr-defined]
            super().__init_subclass__(**kwargs)
            cls.model_fields = getattr(cls, "__fields__", {}).copy()

        @classmethod
        def model_validate(cls: Type[_ModelT], obj: Any) -> _ModelT:
            return cast(_ModelT, cls.parse_obj(obj))

        @classmethod
        def model_construct(cls: Type[_ModelT], _fields_set: Optional[set[str]] = None, **kwargs: Any) -> _ModelT:
            return cast(_ModelT, cls.construct(_fields_set=_fields_set, **kwargs))

        @classmethod
        def model_rebuild(cls, *args: Any, **kwargs: Any) -> None:
            cls.update_forward_refs()

        @classmethod
        def model_json_schema(cls, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return cls.schema(*args, **kwargs)

        def model_dump(
            self,
            *args: Any,
            mode: Optional[str] = None,
            context: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> Dict[str, Any]:
            kwargs.setdefault("by_alias", kwargs.get("by_alias", mode == "json"))
            kwargs.setdefault("exclude_none", kwargs.get("exclude_none", False))
            return self.dict(*args, **kwargs)

        def model_dump_json(
            self,
            *args: Any,
            mode: Optional[str] = None,
            context: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> str:
            kwargs.setdefault("by_alias", kwargs.get("by_alias", mode == "json"))
            kwargs.setdefault("exclude_none", kwargs.get("exclude_none", False))
            return self.json(*args, **kwargs)

        def model_copy(self: _ModelT, *, update: Optional[Dict[str, Any]] = None, deep: bool = False) -> _ModelT:
            return cast(_ModelT, self.copy(update=update, deep=deep))

    BaseModelLike = BaseModel
    BaseModel = BaseModelLike

    def field_validator(*fields: str, mode: str = "after", **kwargs: Any):
        pre = mode == "before"
        if mode not in {"before", "after"}:
            raise ValueError("field_validator mode must be 'before' or 'after' when using pydantic v1")
        return validator(*fields, pre=pre, **kwargs)

    field_validator_like = field_validator

    def model_serializer(*args: Any, **kwargs: Any):
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return func

        return decorator

    model_serializer.__doc__ = (
        "Compatibility shim that mirrors the pydantic v2 model_serializer decorator under v1."
    )
    
    # Alias for consistency with field_validator_like pattern
    model_serializer_like = model_serializer

    def model_validator(*fields: str, mode: str = "after", **kwargs: Any):
        if fields:
            raise TypeError("model_validator does not accept field arguments")

        def decorator(func: Callable[..., Any]):
            raw = func.__func__ if isinstance(func, classmethod) else func

            if mode == "before":

                def _wrapper(cls: Type[Any], values: Any) -> Any:
                    if isinstance(func, classmethod):
                        return raw(cls, values)
                    return raw(values)

                return root_validator(pre=True, **kwargs)(_wrapper)

            if mode != "after":
                raise ValueError("unsupported model_validator mode for pydantic v1")

            def _wrapper(cls: Type[Any], values: Dict[str, Any]) -> Dict[str, Any]:
                instance = cls.__new__(cls)  # type: ignore[call-arg]
                for name, value in values.items():
                    object.__setattr__(instance, name, value)

                result = raw(instance)

                if result is None:
                    updated = values.copy()
                    for name in cls.__fields__:  # type: ignore[attr-defined]
                        if hasattr(instance, name):
                            updated[name] = getattr(instance, name)
                    return updated

                if isinstance(result, dict):
                    return result

                if isinstance(result, cls):
                    merged = values.copy()
                    for name in cls.__fields__:  # type: ignore[attr-defined]
                        if hasattr(result, name):
                            merged[name] = getattr(result, name)
                    return merged

                raise TypeError("model_validator must return None, dict, or model instance")

            return root_validator(pre=False, **kwargs)(_wrapper)

        return decorator

    model_validator_like = model_validator

    Field = FieldLike


# ============================================================================
# Helper Functions for JCS Canonicalization
# ============================================================================


def is_signature_field(field_name: str) -> bool:
    """
    Check if field name is a signature-related field.

    Signature fields are excluded from payload_hash computation
    to enable detached signature pattern.

    Args:
        field_name: Field name to check

    Returns:
        True if field is signature-related
    """
    signature_fields = {
        "signatures",
        "signature",
        "cose_signature",
        "receipt_hash",  # Computed from payload, not part of payload
        "anchor",  # Anchoring metadata added after signing
    }
    return field_name in signature_fields


def unwrap_frozen(obj: Any) -> Any:
    """
    Recursively unwrap frozen containers to plain dict/list for JCS.

    Pydantic v2 frozen models use FrozenDict/FrozenList internally.
    JCS canonicalization requires plain dict/list for deterministic serialization.

    Args:
        obj: Object to unwrap (can be dict, list, Pydantic model, or primitive)

    Returns:
        Unwrapped object (plain dict/list/primitive)
    """
    # Handle Pydantic models (both v1 and v2)
    if hasattr(obj, "model_dump"):
        # Pydantic v2
        return unwrap_frozen(obj.model_dump(mode="json"))
    elif hasattr(obj, "dict"):
        # Pydantic v1
        return unwrap_frozen(obj.dict())

    # Handle dict-like objects
    if isinstance(obj, dict):
        # Covers dict, FrozenDict, OrderedDict, etc.
        return {k: unwrap_frozen(v) for k, v in obj.items()}

    # Handle list-like objects
    if isinstance(obj, (list, tuple)):
        # Covers list, FrozenList, tuple
        return [unwrap_frozen(item) for item in obj]

    # Primitives (str, int, float, bool, None)
    return obj


def strip_signatures(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove signature fields from data dict for payload_hash computation.

    This enables the detached signature pattern:
    - payload_hash = hash(receipt minus signatures)
    - signature = sign(payload_hash)
    - verified_hash = hash(signed_receipt minus signatures) == payload_hash

    Args:
        data: Receipt data dict (possibly containing frozen containers)

    Returns:
        Data dict with signature fields removed and frozen containers unwrapped
    """
    # First unwrap frozen containers
    unwrapped = unwrap_frozen(data)

    # Then filter out signature fields
    return {k: v for k, v in unwrapped.items() if not is_signature_field(k)}


__all__ = [
    "BaseModel",
    "BaseModelLike",
    "Field",
    "FieldLike",
    "ConfigDict",
    "ConfigDictLike",
    "field_validator",
    "field_validator_like",
    "model_validator",
    "model_validator_like",
    "model_serializer",
    "model_serializer_like",
    "unwrap_frozen",
    "strip_signatures",
    "is_signature_field",
]
