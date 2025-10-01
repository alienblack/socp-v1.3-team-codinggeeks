import orjson

def canonical_bytes(d: dict) -> bytes:
    return orjson.dumps(d, option=orjson.OPT_SORT_KEYS)
