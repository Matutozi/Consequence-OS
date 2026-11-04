"""Strict JSON parsing: reject bodies that two parsers could read differently.

This mirrors CheckUnambiguous in the Go package pkg/verify. Python's json
module silently keeps the last of two duplicate keys and accepts NaN and
Infinity, so a policy could have checked {"amount": 10} while the tool reads
{"amount": 5000}. Bodies like that are refused before any tool runs.
"""

from __future__ import annotations

import json
from typing import Any


class AmbiguousJSON(ValueError):
    """The body has duplicate keys, case-variant keys, or non-standard numbers."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    folded: set[str] = set()
    for key, value in pairs:
        if key in obj:
            raise AmbiguousJSON(f"duplicate key {key!r}")
        # upper() then lower() folds case at least as strictly as the Go
        # check does (Python also folds "ß" with "ss"); stricter is safe.
        fold = key.upper().lower()
        if fold in folded:
            raise AmbiguousJSON(f"keys that differ only in letter case: {key!r}")
        folded.add(fold)
        obj[key] = value
    return obj


def _no_constants(name: str) -> Any:
    raise AmbiguousJSON(f"{name} is not valid JSON")


def loads_strict(data: bytes | str) -> Any:
    """Parse JSON, raising AmbiguousJSON for anything that isn't plain, unambiguous JSON.

    Raises json.JSONDecodeError (a ValueError) when data isn't JSON at all.
    """
    return json.loads(data, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)


def dumps_exact(value: Any) -> str:
    """Serialise for the verify endpoint, which canonicalises it again.

    ensure_ascii keeps escapes such as a lone surrogate exactly as they came,
    so the server sees the same value the tool will.
    """
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
