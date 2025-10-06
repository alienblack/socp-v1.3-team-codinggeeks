
import json

import pytest

from socp.core import proto


def test_build_frame_has_fields():
    f = proto.build_frame("HEARTBEAT", "server_a", "server_b", {"x": 1})
    assert set(f.keys()) == {"type", "from", "to", "ts", "payload", "sig"}


def test_parse_envelope_rejects_non_object():
    with pytest.raises(proto.FrameValidationError):
        proto.parse_envelope(json.dumps(["not", "an", "object"]))


def test_parse_envelope_validates_required_fields():
    payload = json.dumps({"type": "USER_HELLO", "from": "alice", "to": "server", "ts": 1, "payload": {}})
    env = proto.parse_envelope(payload)
    assert env.from_ == "alice"
    assert env.type == "USER_HELLO"


def test_make_ack_and_error_helpers():
    ack = proto.make_ack("server", "alice", "USER_HELLO", 1234)
    assert ack["type"] == "ACK"
    assert ack["payload"]["ref"] == "USER_HELLO"
    err = proto.make_error("server", "alice", "USER_NOT_FOUND")
    assert err["payload"]["code"] == "USER_NOT_FOUND"
