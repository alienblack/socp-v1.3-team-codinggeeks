# tests/test_presence.py
from __future__ import annotations
import asyncio
from uuid import uuid4
import pytest

import socp.core.presence as presence


# -----------------------------
# Utilities / fixtures
# -----------------------------

@pytest.fixture
def uuids():
    """Fresh UUIDs for each test run."""
    return {
        "server_my": str(uuid4()),
        "server_peer": str(uuid4()),
        "user": str(uuid4()),
    }


@pytest.fixture
def user_locations():
    """Shared mapping the module under test mutates."""
    return {}


@pytest.fixture
def calls():
    """Collects broadcast/fanout calls for assertions."""
    return {"broadcasts": [], "fanouts": []}


@pytest.fixture
def broadcast(calls):
    def _b(env: dict) -> None:
        calls["broadcasts"].append(env)
    return _b


@pytest.fixture
def fanout(calls):
    def _f(env: dict) -> None:
        calls["fanouts"].append(env)
    return _f


@pytest.fixture
def sign_transport():
    """Trivial signer that returns a deterministic string."""
    return lambda b: "stub-transport-sig"


@pytest.fixture(autouse=True)
def stub_build_and_sign(monkeypatch):
    """
    By default, stub proto.build_frame and proto.sign_frame_in_place
    to keep tests self-contained and avoid needing real crypto.
    """
    def fake_build_frame(type: str, from_: str, to: str, payload: dict) -> dict:
        # Minimal shape + deterministic ts for assertions
        return {
            "type": type,
            "from": from_,
            "to": to,
            "ts": 1700000000000,   # any int ms
            "payload": payload,
            "sig": "",
        }

    def fake_sign_frame_in_place(env: dict, sign_fn) -> dict:
        # "Sign" only the payload per spec; just mark sig field
        env = dict(env)
        env["sig"] = sign_fn(repr(env["payload"]).encode("utf-8"))
        return env

    monkeypatch.setattr(presence, "build_frame", fake_build_frame)
    monkeypatch.setattr(presence, "sign_frame_in_place", fake_sign_frame_in_place)


# -----------------------------
# Local events → emits gossip
# -----------------------------

@pytest.mark.asyncio
async def test_on_user_local_join_updates_and_broadcasts(
    uuids, user_locations, sign_transport, broadcast, calls
):
    """
    When a local user connects:
      - Build & sign USER_ADVERTISE
      - Optimistically set user_locations[user] = "local"
      - Broadcast the envelope unchanged
    """
    env = await presence.on_user_local_join(
        user_id=uuids["user"],
        meta={"display_name": "Alice"},
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        sign_transport=sign_transport,
        broadcast=broadcast,
    )

    assert user_locations[uuids["user"]] == "local"
    assert env["type"] == "USER_ADVERTISE"
    assert env["from"] == uuids["server_my"]
    assert env["to"] == "*"
    assert env["payload"]["user_id"] == uuids["user"]
    assert env["payload"]["server_id"] == uuids["server_my"]
    assert isinstance(env["ts"], int)
    assert env["sig"] == "stub-transport-sig"

    # Broadcast called exactly once with the same envelope
    assert calls["broadcasts"] == [env]


@pytest.mark.asyncio
async def test_on_user_local_leave_removes_and_broadcasts(
    uuids, user_locations, sign_transport, broadcast, calls
):
    """
    When a local user disconnects:
      - Build & sign USER_REMOVE
      - Eagerly remove user from user_locations
      - Broadcast removal
    """
    # Pre-populate as "local" to simulate a connected user
    user_locations[uuids["user"]] = "local"

    env = await presence.on_user_local_leave(
        user_id=uuids["user"],
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        sign_transport=sign_transport,
        broadcast=broadcast,
    )

    assert uuids["user"] not in user_locations
    assert env["type"] == "USER_REMOVE"
    assert env["payload"]["user_id"] == uuids["user"]
    assert env["payload"]["server_id"] == uuids["server_my"]
    assert calls["broadcasts"] == [env]


# -----------------------------
# Incoming gossip: USER_ADVERTISE
# -----------------------------

def test_handle_user_advertise_valid_updates_and_fanouts(
    uuids, user_locations, fanout, calls
):
    """
    A valid USER_ADVERTISE from a peer server:
      - verify_from_server True → accept
      - update mapping to hosting server (unless it's us → 'local')
      - fanout unchanged
    """
    env = {
        "type": "USER_ADVERTISE",
        "from": uuids["server_peer"],
        "to": "*",
        "ts": 1700000100000,
        "payload": {
            "user_id": uuids["user"],
            "server_id": uuids["server_peer"],
            "meta": {"dn": "Alice"},
        },
        "sig": "ok",
    }

    def verify_from_server(_env):  # accept
        return True

    accepted = presence.handle_user_advertise(
        env,
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        verify_from_server=verify_from_server,
        fanout=fanout,
    )

    assert accepted is True
    assert user_locations[uuids["user"]] == uuids["server_peer"]
    assert calls["fanouts"] == [env]


def test_handle_user_advertise_bad_sig_rejected(uuids, user_locations, fanout, calls):
    """
    If verify fails, the advertise must be ignored and not faned-out.
    """
    env = {
        "type": "USER_ADVERTISE",
        "from": uuids["server_peer"],
        "to": "*",
        "ts": 1700000100000,
        "payload": {"user_id": uuids["user"], "server_id": uuids["server_peer"], "meta": {}},
        "sig": "bad",
    }

    def verify_from_server(_env):
        return False

    accepted = presence.handle_user_advertise(
        env,
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        verify_from_server=verify_from_server,
        fanout=fanout,
    )
    assert accepted is False
    assert uuids["user"] not in user_locations
    assert calls["fanouts"] == []


def test_handle_user_advertise_bad_shape_rejected(uuids, user_locations, fanout, calls, monkeypatch):
    """
    If payload shape is wrong (e.g., missing/invalid meta or server_id not a UUID v4),
    the advertise is rejected.
    """
    env = {
        "type": "USER_ADVERTISE",
        "from": uuids["server_peer"],
        "to": "*",
        "ts": 1700000100000,
        "payload": {"user_id": uuids["user"], "server_id": "not-a-uuid", "meta": {}},
        "sig": "ok",
    }

    def verify_from_server(_env):  # signature ok but shape invalid
        return True

    # Force is_uuid_v4 to behave realistically
    monkeypatch.setattr(presence, "is_uuid_v4", lambda v: False)

    accepted = presence.handle_user_advertise(
        env,
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        verify_from_server=verify_from_server,
        fanout=fanout,
    )
    assert accepted is False
    assert uuids["user"] not in user_locations
    assert calls["fanouts"] == []


# -----------------------------
# Incoming gossip: USER_REMOVE (guarded removal)
# -----------------------------

def test_handle_user_remove_only_removes_if_mapping_matches(
    uuids, user_locations, fanout, calls
):
    """
    Guarded removal:
      - If we believe the user is on server_peer and removal claims server_peer → remove.
      - If mapping points somewhere else → ignore.
    """
    # Case 1: mapping matches → remove
    user_locations[uuids["user"]] = uuids["server_peer"]

    env_good = {
        "type": "USER_REMOVE",
        "from": uuids["server_peer"],
        "to": "*",
        "ts": 1700000200000,
        "payload": {"user_id": uuids["user"], "server_id": uuids["server_peer"]},
        "sig": "ok",
    }

    def verify_ok(_env): return True

    accepted = presence.handle_user_remove(
        env_good,
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        verify_from_server=verify_ok,
        fanout=fanout,
    )
    assert accepted is True
    assert uuids["user"] not in user_locations
    assert calls["fanouts"][-1] == env_good  # was fanned out

    # Case 2: mapping doesn't match → ignore
    other_user = str(uuid4())
    user_locations[other_user] = uuids["server_my"]  # local

    env_wrong_host = {
        "type": "USER_REMOVE",
        "from": uuids["server_peer"],
        "to": "*",
        "ts": 1700000200500,
        "payload": {"user_id": other_user, "server_id": uuids["server_peer"]},
        "sig": "ok",
    }

    accepted2 = presence.handle_user_remove(
        env_wrong_host,
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        verify_from_server=verify_ok,
        fanout=fanout,
    )
    assert accepted2 is False
    assert user_locations[other_user] == "local"


def test_handle_user_remove_bad_sig_or_shape_rejected(uuids, user_locations, fanout, calls):
    """
    If signature fails OR payload shape invalid, ignore and do not mutate mapping.
    """
    user_locations[uuids["user"]] = uuids["server_peer"]

    env = {
        "type": "USER_REMOVE",
        "from": uuids["server_peer"],
        "to": "*",
        "ts": 1700000200000,
        "payload": {"user_id": uuids["user"], "server_id": "not-a-uuid"},
        "sig": "bad",
    }

    def verify_fail(_env): return False

    accepted = presence.handle_user_remove(
        env,
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        verify_from_server=verify_fail,
        fanout=fanout,
    )
    assert accepted is False
    assert user_locations[uuids["user"]] == uuids["server_peer"]
    assert calls["fanouts"] == []


def test_handle_user_remove_local_mapping_guarded(uuids, user_locations, fanout, calls):
    """
    Special case: if our mapping is 'local' and the remove claims our own server_id,
    we should accept and remove.
    """
    user_locations[uuids["user"]] = "local"

    env = {
        "type": "USER_REMOVE",
        "from": uuids["server_my"],
        "to": "*",
        "ts": 1700000200001,
        "payload": {"user_id": uuids["user"], "server_id": uuids["server_my"]},
        "sig": "ok",
    }

    def verify_ok(_env): return True

    accepted = presence.handle_user_remove(
        env,
        my_server_id=uuids["server_my"],
        user_locations=user_locations,
        verify_from_server=verify_ok,
        fanout=fanout,
    )
    assert accepted is True
    assert uuids["user"] not in user_locations


# -----------------------------
# Maintenance helper
# -----------------------------

def test_purge_by_hosting_server_removes_only_those_users(uuids):
    """
    purge_by_hosting_server(host) should remove all users mapped to that host
    and return the count; unrelated entries remain.
    """
    ul = {
        str(uuid4()): uuids["server_peer"],
        str(uuid4()): uuids["server_peer"],
        str(uuid4()): uuids["server_my"],
        str(uuid4()): "local",
    }
    removed = presence.purge_by_hosting_server(uuids["server_peer"], ul)
    assert removed == 2
    # Ensure nothing mapped to server_peer remains
    assert all(sid != uuids["server_peer"] for sid in ul.values())
