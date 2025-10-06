import importlib


def fresh_modules():
    router = importlib.import_module("socp.core.router")
    presence = importlib.import_module("socp.core.presence")
    public = importlib.import_module("socp.core.public")
    router = importlib.reload(router)
    public = importlib.reload(public)
    presence = importlib.reload(presence)
    router.configure("srv_local")
    public.configure("srv_local")
    presence.configure("srv_local", None)
    return presence, router, public


def test_remote_leave_requires_authoritative_server():
    presence, router, public = fresh_modules()
    presence.handle_remote_join("srv_b", "alice", {"role": "user"})
    presence.handle_remote_snapshot("srv_b", {"alice": {}})
    assert router.USER_LOCATION["alice"] == "srv_b"
    assert public._REMOTE_MEMBERS["srv_b"]["alice"]["server_id"] == "srv_b"

    # Ignore removal from a different server
    presence.handle_remote_leave("srv_c", "alice")
    assert router.USER_LOCATION["alice"] == "srv_b"
    assert "alice" in router.REMOTE_USERS["srv_b"]
    assert public._REMOTE_MEMBERS["srv_b"]["alice"]["server_id"] == "srv_b"

    # Accept removal from authoritative server
    presence.handle_remote_leave("srv_b", "alice")
    assert "alice" not in router.USER_LOCATION
    assert "srv_b" not in router.REMOTE_USERS or "alice" not in router.REMOTE_USERS["srv_b"]
    assert "srv_b" not in public._REMOTE_MEMBERS


def test_remote_snapshot_overwrites_membership():
    presence, router, public = fresh_modules()
    presence.handle_remote_join("srv_b", "alice", {})
    presence.handle_remote_join("srv_b", "carol", {})
    assert router.REMOTE_USERS["srv_b"] == {"alice", "carol"}

    presence.handle_remote_snapshot("srv_b", {"alice": {"role": "mod"}})

    assert router.USER_LOCATION.get("alice") == "srv_b"
    assert "carol" not in router.USER_LOCATION
    assert router.REMOTE_USERS["srv_b"] == {"alice"}
    assert public._REMOTE_MEMBERS["srv_b"] == {"alice": {"server_id": "srv_b"}}
