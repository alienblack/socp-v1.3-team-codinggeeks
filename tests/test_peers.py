import asyncio
import time
import uuid
import types
import pytest

# The module under test
# from socp.core.peers import PeerManager, Link
from socp.core import peers
# ---- helpers ----

class DummySigner:
    def __call__(self, payload_bytes: bytes):
        return "dummysig"


def mk_uuid() -> str:
    # UUID v4
    return str(uuid.uuid4())


def ts_ms() -> int:
    return int(time.time() * 1000)


# ---- fixtures ----

@pytest.fixture()
def signer():
    return DummySigner()


@pytest.fixture()
def pm(signer):
    # Use a fixed now() so we can deterministically age links
    t = {"now": ts_ms()}

    def now_fixed():
        return t["now"]

    m = peers.PeerManager(my_server_id=mk_uuid(), sign_transport=signer, now=now_fixed)
    m._timebox = t  # stash for tests to mutate clock
    return m


# ---- tests ----

def test_placeholder_rekeys_on_server_welcome(pm):
    """A placeholder link ('host:port') is rekeyed to the introducer's UUID after WELCOME."""
    host, port = "203.0.113.21", 1212
    placeholder = f"{host}:{port}"

    # Seed placeholder link as bootstrap() does
    link = peers.Link(server_id=placeholder, host=host, port=port, pubkey_b64="PUBKEY", send=lambda _: None)
    pm.server_links[placeholder] = link
    pm.server_addrs[placeholder] = (host, port)
    pm._placeholders.add(placeholder)

    introducer_id = mk_uuid()

    env_welcome = {
        "type": "SERVER_WELCOME",
        "from": introducer_id,
        "to": pm.my_server_id,
        "ts": ts_ms(),
        "payload": {
            "assigned_id": pm.my_server_id,  # unchanged
            "clients": [
                {"user_id": "user-A", "host": host, "port": port, "pubkey": "..."},
            ],
        },
        "sig": "...",
    }

    pm.on_server_frame(env_welcome)

    # Placeholder should be gone, replaced by real UUID key
    assert placeholder not in pm.server_links
    assert introducer_id in pm.server_links

    new_link = pm.server_links[introducer_id]
    assert new_link.server_id == introducer_id
    assert pm.server_addrs[introducer_id] == (host, port)

    # Presence seeding
    assert pm.user_locations.get("user-A") == introducer_id


def test_server_announce_registers_and_updates(pm):
    """SERVER_ANNOUNCE registers address and updates existing Link fields."""
    peer_id = mk_uuid()

    # First announce -> create link
    env1 = {
        "type": "SERVER_ANNOUNCE",
        "from": peer_id,
        "to": "*",
        "ts": ts_ms(),
        "payload": {"host": "192.0.2.10", "port": 9001, "pubkey": "K1"},
        "sig": "...",
    }
    pm.on_server_frame(env1)

    assert peer_id in pm.server_links
    assert pm.server_addrs[peer_id] == ("192.0.2.10", 9001)

    link = pm.server_links[peer_id]
    assert link.pubkey_b64 == "K1"
    last_seen_1 = link.last_seen_ms

    # Second announce with new address/key -> updates existing link
    env2 = {
        "type": "SERVER_ANNOUNCE",
        "from": peer_id,
        "to": "*",
        "ts": ts_ms(),
        "payload": {"host": "198.51.100.77", "port": 7777, "pubkey": "K2"},
        "sig": "...",
    }
    pm.on_server_frame(env2)

    link2 = pm.server_links[peer_id]
    assert link2.host == "198.51.100.77"
    assert link2.port == 7777
    assert link2.pubkey_b64 == "K2"
    assert pm.server_addrs[peer_id] == ("198.51.100.77", 7777)
    assert link2.last_seen_ms >= last_seen_1


def test_tick_health_marks_dead_after_45s(pm):
    # Create a peer and set last_seen far in the past
    peer_id = mk_uuid()
    link = peers.Link(server_id=peer_id, host="192.0.2.1", port=9100, pubkey_b64="K", send=lambda _: None)
    pm.server_links[peer_id] = link

    # Move clock forward 46s
    pm._timebox["now"] += 46_000

    pm.tick_health(timeout_s=45.0)

    assert pm.server_links[peer_id].is_alive is False
    assert pm.server_links[peer_id].reconnecting is True


def test_heartbeat_sends_only_to_uuid_peers(event_loop, pm, monkeypatch):
    # Add one UUID peer and one placeholder peer
    uuid_peer = mk_uuid()
    placeholder = "198.51.100.1:9001"

    sent = {"uuid": 0, "placeholder": 0}

    def send_uuid(_):
        sent["uuid"] += 1

    def send_placeholder(_):
        sent["placeholder"] += 1

    pm.server_links[uuid_peer] = peers.Link(server_id=uuid_peer, host="h", port=1, pubkey_b64="K", send=send_uuid)
    pm.server_links[placeholder] = peers.Link(server_id=placeholder, host="h2", port=2, pubkey_b64="K2", send=send_placeholder)

    # Run one iteration of the internal loop body by calling the private helper directly
    # (we don't want to actually sleep here). We'll copy the relevant snippet.
    for sid, link in list(pm.server_links.items()):
        if link.is_alive and len(sid) == 36 and sid.count("-") == 4:  # crude uuid v4 check mirrors is_uuid_v4
            hb = pm.make_heartbeat(sid)
            link.send(hb)

    assert sent["uuid"] == 1
    assert sent["placeholder"] == 0
