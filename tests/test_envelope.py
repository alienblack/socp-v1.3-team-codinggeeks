from socp.core import proto


def test_build_envelope_has_fields():
    env = proto.build_envelope("HEARTBEAT", "server_a", "server_b", {"x": 1})
    data = proto.envelope_to_dict(env)
    assert set(data.keys()) == {"type", "from", "to", "ts", "payload", "sig"}
