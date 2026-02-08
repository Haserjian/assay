from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

try:
    from engine.pipeline.telemetry import timer
except ImportError:
    from contextlib import contextmanager

    @contextmanager
    def timer(name):
        yield

__all__ = ["canonicalize", "canonicalize_to_str"]


def canonicalize(obj: Any) -> bytes:
    """
    Serialize *obj* to RFC 8785 canonical JSON as UTF-8 bytes.

    Only standard JSON data types are supported (dict, list, str, int,
    float, Decimal, bool, None). Floats must be finite.
    """
    return canonicalize_to_str(obj).encode("utf-8")


def canonicalize_to_str(obj: Any) -> str:
    """Return the canonical JSON text for *obj*."""
    with timer("jcs_canonicalize"):
        return _serialize(obj)


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (int, Decimal)) and not isinstance(value, bool):
        return _encode_number(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite float not permitted in canonical JSON")
        return _encode_number(value)
    if isinstance(value, Mapping):
        items = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JCS canonicalization requires string keys")
            items.append((key, item))
        items.sort(key=lambda kv: kv[0].encode("utf-16-be"))
        if not items:
            return "{}"
        serialized = [
            f"{_encode_string(key)}:{_serialize(item)}" for key, item in items
        ]
        return "{" + ",".join(serialized) + "}"
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    raise TypeError(f"unsupported type for JCS canonicalization: {type(value)!r}")


def _encode_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _encode_number(value: Any) -> str:
    if isinstance(value, bool):
        raise TypeError("booleans are handled separately")
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    dec = value if isinstance(value, Decimal) else Decimal(str(value))
    if dec.is_nan() or dec.is_infinite():
        raise ValueError("invalid JSON number")
    if dec == 0:
        return "0"
    sign = "-" if dec.is_signed() else ""
    dec = abs(dec).normalize()
    digits_tuple = dec.as_tuple().digits
    exponent = dec.as_tuple().exponent
    digits = "".join(str(d) for d in digits_tuple) or "0"
    adjusted = len(digits) + exponent - 1
    if -6 <= adjusted <= 20:
        if exponent >= 0:
            return sign + digits + ("0" * exponent)
        integer_digits = max(adjusted + 1, 0)
        if integer_digits > 0:
            int_part = digits[:integer_digits]
            frac_part = digits[integer_digits:]
            return sign + int_part + (("." + frac_part) if frac_part else "")
        zeros = "0" * (-(adjusted + 1))
        return sign + "0." + zeros + digits
    significand = digits[0]
    fractional = digits[1:]
    if fractional:
        significand += "." + fractional
    return f"{sign}{significand}E{adjusted}"
