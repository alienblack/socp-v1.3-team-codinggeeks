
import orjson
def canonical_bytes(d: dict) -> bytes:
    # sort keys & remove whitespace (orjson does deterministic by default for same structures)
    return orjson.dumps(d, option=orjson.OPT_SORT_KEYS)
