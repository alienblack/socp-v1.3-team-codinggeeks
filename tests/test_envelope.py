
from socp.core import proto
def test_build_frame_has_fields():
    f = proto.build_frame("HEARTBEAT","server_a","server_b",{"x":1})
    assert set(f.keys()) == {"type","from","to","ts","payload","sig"}
