
from socp.core import proto, router


def _envelope(**kwargs):
    data = {
        "type": "USER_MESSAGE",
        "from": "alice",
        "to": "bob",
        "ts": 1,
        "payload": {"msg": "hi"},
        "sig": "",
    }
    data.update(kwargs)
    return proto.Envelope.model_validate(data)


def test_route_local_user():
    r = router.Router("srvA")
    r.register_local_user("bob", object())
    decision = r.route(_envelope())
    assert decision.action == "deliver_local"
    assert decision.target == "bob"


def test_route_remote_forward():
    r = router.Router("srvA")
    r.register_server_link("srvB", object())
    r.track_remote_users("srvB", ["charlie"])
    decision = r.route(_envelope(to="charlie"))
    assert decision.action == "forward"
    assert decision.target == "srvB"


def test_route_user_not_found():
    r = router.Router("srvA")
    decision = r.route(_envelope(to="nobody"))
    assert decision.action == "error"
    assert decision.code == "USER_NOT_FOUND"


def test_dedupe_on_server_deliver():
    r = router.Router("srvA")
    r.register_local_user("bob", object())
    env = _envelope(type="SERVER_DELIVER")
    first = r.route(env)
    assert first.action == "deliver_local"
    second = r.route(env)
    assert second.action == "drop"
    assert second.code == "DUPLICATE"
