from socp.utils.canonical import canonical_bytes

def test_canonical_stability_sort_keys():
    a = {"b": 2, "a": 1, "z": {"y": 9, "x": 8}}
    b = {"z": {"x": 8, "y": 9}, "a": 1, "b": 2}
    assert canonical_bytes(a) == canonical_bytes(b)
