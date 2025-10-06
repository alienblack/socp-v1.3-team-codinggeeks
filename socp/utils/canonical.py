"""Canonical JSON utilities for transport signing."""

from __future__ import annotations

from typing import Mapping

import orjson


def canonical_bytes(payload: Mapping) -> bytes:
    """Return deterministic JSON bytes with sorted keys and no extra whitespace."""

    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping for canonical encoding")
    return orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)
