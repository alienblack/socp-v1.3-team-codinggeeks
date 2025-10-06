import time
from socp.core import proto

def test_build_frame_has_fields():
    f = proto.build_frame("HEARTBEAT","server_a","server_b",{"x":1})
    assert set(f.keys()) == {"type","from","to","ts","payload","sig"}

def test_build_frame_timestamp_units():
    frame = proto.build_frame("PING", "alice", "bob", {})
    now_ms = int(time.time() * 1000)
    assert abs(frame["ts"] - now_ms) <= 200
