"""RFC 8785 JSON Canonicalization Scheme (JCS) implementation.

Ensures deterministic, byte-exact JSON serialization across heterogeneous platforms
and languages for digital signature computation and verification.
"""

import math
from typing import Any, Union


def _utf16_sort_key(s: str) -> bytes:
    """Sort key for UTF-16 code unit ordering required by RFC 8785."""
    return s.encode("utf-16-be")


def _serialize_string(s: str) -> str:
    """Serialize string according to RFC 8785 escaping rules."""
    out = ['"']
    for char in s:
        cp = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == '\\':
            out.append('\\\\')
        elif char == '\b':
            out.append('\\b')
        elif char == '\f':
            out.append('\\f')
        elif char == '\n':
            out.append('\\n')
        elif char == '\r':
            out.append('\\r')
        elif char == '\t':
            out.append('\\t')
        elif cp < 0x20:
            out.append(f"\\u{cp:04X}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _serialize_number(n: Union[int, float]) -> str:
    """Serialize number according to RFC 8785 / ECMAScript specifications."""
    if isinstance(n, bool):
        # In Python, bool is a subclass of int
        raise TypeError("Boolean passed to serialize_number")
    if isinstance(n, float):
        if math.isnan(n) or math.isinf(n):
            raise ValueError(f"RFC 8785 does not permit NaN or Infinity: {n}")
        if n.is_integer() and not math.isclose(n, -0.0):
            return str(int(n))
        # Format standard floating point
        formatted = f"{n:.16g}"
        if "e" in formatted:
            # Normalize exponent format: e.g. e+05 -> e+5
            parts = formatted.split("e")
            exp = int(parts[1])
            sign = "+" if exp >= 0 else "-"
            return f"{parts[0]}e{sign}{abs(exp)}"
        return formatted
    elif isinstance(n, int):
        return str(n)
    raise TypeError(f"Unsupported number type: {type(n)}")


def _serialize_value(val: Any) -> str:
    """Recursively serialize a Python object to canonical JSON string."""
    if val is None:
        return "null"
    elif isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, (int, float)):
        return _serialize_number(val)
    elif isinstance(val, str):
        return _serialize_string(val)
    elif isinstance(val, (list, tuple)):
        items = [_serialize_value(item) for item in val]
        return "[" + ",".join(items) + "]"
    elif isinstance(val, dict):
        # RFC 8785: Keys must be strings and sorted by UTF-16 code units
        sorted_keys = sorted(val.keys(), key=_utf16_sort_key)
        items = []
        for k in sorted_keys:
            if not isinstance(k, str):
                raise TypeError(f"RFC 8785 requires all dictionary keys to be strings, got: {type(k)}")
            items.append(f"{_serialize_string(k)}:{_serialize_value(val[k])}")
        return "{" + ",".join(items) + "}"
    else:
        raise TypeError(f"Type {type(val)} is not JSON-serializable under RFC 8785")


def canonicalize_json_str(data: Any) -> str:
    """Produce RFC 8785 canonical JSON string."""
    return _serialize_value(data)


def canonicalize_json(data: Any) -> bytes:
    """Produce RFC 8785 canonical JSON bytes (UTF-8 encoded)."""
    return _serialize_value(data).encode("utf-8")
