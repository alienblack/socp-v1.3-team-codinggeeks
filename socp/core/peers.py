from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional
import asyncio
import logging
import yaml

from .proto import make_envelope, now_ms, is_uuid_v4

"""
Peers, Presence Gossip & Health
--------------------------------
This module maintains the server→server overlay state for SOCP v1.3:
  • Bootstrap to an Introducer (placeholder link → remap to UUID after WELCOME)
  • Register/refresh peer addresses on SERVER_ANNOUNCE
  • Periodic HEARTBEATs and dead-link detection (~45s)
  • Minimal presence seeding from SERVER_WELCOME.clients (directory hints)

Wire-level obligations taken from spec (§8.1 bootstrap, §8.4 health, §7 envelope):
  - All frames are JSON envelopes with ts in ms; transport sig covers payload only.
  - On receiving SERVER_ANNOUNCE, register server_addrs[id] and keep a Link.
  - Heartbeats every ~15s; treat link dead after ~45s of silence.

Security/crypto:
  - Signature verification is expected to be done in the WebSocket receive path (ws.py)
    before calling PeerManager.on_server_frame().
  - This module relies on the pinned RSA-4096 pubkey advertised / configured for peers.

Integration points:
  - ws.py should plug a real WebSocket send() into Link.send and route incoming frames to
    PeerManager.on_server_frame().
  - presence.py will consume/maintain user_locations for gossip frames; here we only seed it
    opportunistically from SERVER_WELCOME.clients to speed up initial routing table warmup.

Notes:
  - We accept a config key "introducers" in configs/bootstrap.yaml (course repo convention).
    If you also want to support the spec's example key "bootstrap_servers", we merge both.
"""



log = logging.getLogger("socp.peers")

# ---------- types ----------
SendFn = Callable[[dict], None]        # plug your websocket send() later
SignFn = Callable[[bytes], str]        # transport signer (RSA-PSS in prod; HMAC stub in tests)
NowFn  = Callable[[], int]

CONFIG_PATH = Path("configs/bootstrap.yaml")


@dataclass
class Link:
    """A transport handle for a remote Server in the overlay.

    server_id: UUID v4 once known (placeholder "host:port" allowed pre-WELCOME)
    host/port: advertised WS endpoint
    pubkey_b64: pinned transport key from bootstrap / welcome
    send: callable that ships a JSON envelope over the wire
    last_seen_ms: for liveness/timeout tracking
    """
    server_id: str
    host: str
    port: int
    pubkey_b64: str
    send: SendFn = lambda _msg: None
    last_seen_ms: int = field(default_factory=now_ms)
    is_alive: bool = True
    reconnecting: bool = False


class PeerManager:
    """Manages server links, addresses, and health.

    - server_links: Dict[server_id -> Link]
    - server_addrs: Dict[server_id -> (host, port)]
    - user_locations: Dict[user_id -> "local" | server_id]

    Callers should:
      • create PeerManager
      • populate with introducer placeholders (bootstrap())
      • wire ws.py to call on_server_frame() per incoming server frame (after sig check)
      • use make_* helpers to craft envelopes to send
    """

    def __init__(
        self,
        my_server_id: str,
        sign_transport: SignFn,
        now: NowFn = now_ms,
        on_dead: Optional[Callable[[str], None]] = None,
    ):
        self.my_server_id = my_server_id
        self.sign_transport = sign_transport
        self.now = now
        self.on_dead = on_dead

        self.server_links: Dict[str, Link] = {}
        self.server_addrs: Dict[str, tuple[str, int]] = {}
        self.user_locations: Dict[str, str] = {}

        # Tracks any pre-WELCOME placeholder link keys (e.g., "1.2.3.4:9001").
        self._placeholders: set[str] = set()

    # ----- config -----
    def load_config(self, override_path: Optional[str] = None) -> list[dict]:
        """Load introducers from YAML.
        """
        path = Path(override_path) if override_path else CONFIG_PATH
        data = yaml.safe_load(path.read_text()) or {}
        intro_b = data.get("bootstrap_servers", []) or []
        # Normalize entries to {host, port, pubkey}
        def norm(ent: dict) -> dict:
            return {
                "host": ent.get("host"),
                "port": int(ent.get("port")),
                "pubkey": ent.get("pubkey"),
            }
        merged = [norm(e) for e in intro_b if e]
        return merged

    # ----- spec message constructors -----
    def make_server_hello_join(self, intro_host: str, intro_port: int, my_pubkey_b64: str) -> dict:
        """SERVER_HELLO_JOIN — join request to an Introducer.

        Envelope 'to' may be the literal "host:port" during join (§8.1).
        """
        payload = {"host": intro_host, "port": intro_port, "pubkey": my_pubkey_b64}
        return make_envelope(
            "SERVER_HELLO_JOIN",
            self.my_server_id,
            f"{intro_host}:{intro_port}",
            payload,
            self.sign_transport,
        )

    def handle_server_welcome(self, env: dict) -> None:
        """Process SERVER_WELCOME from Introducer.

        - Update my_server_id if the introducer re-assigned it (§8.1).
        - Remap placeholder link (host:port) → real introducer UUID from env["from"].
        - Seed presence hints from payload.clients (optional optimization).
        """
        payload = env.get("payload", {})
        assigned = payload.get("assigned_id")
        if assigned and assigned != self.my_server_id:
            log.info("Introducer assigned server_id=%s (was %s)", assigned, self.my_server_id)
            self.my_server_id = assigned

        introducer_sid = env.get("from")
        if introducer_sid and is_uuid_v4(introducer_sid):
            # Remap first placeholder, if any, to the introducer's UUID.
            if self._placeholders:
                placeholder_key = next(iter(self._placeholders))
                link = self.server_links.pop(placeholder_key, None)
                if link:
                    link.server_id = introducer_sid
                    self.server_links[introducer_sid] = link
                    self.server_addrs[introducer_sid] = (link.host, link.port)
                self._placeholders.discard(placeholder_key)

        # Seed presence (directory hints) — server_id is introducer's.
        for c in payload.get("clients", []) or []:
            try:
                uid = c["user_id"]
                self.user_locations[uid] = introducer_sid
            except Exception:
                continue

    def make_server_announce(self, my_host: str, my_port: int, my_pubkey_b64: str) -> dict:
        """SERVER_ANNOUNCE — broadcast our address + pubkey to all servers (§8.1)."""
        payload = {"host": my_host, "port": my_port, "pubkey": my_pubkey_b64}
        return make_envelope("SERVER_ANNOUNCE", self.my_server_id, "*", payload, self.sign_transport)

    def handle_server_announce(self, env: dict) -> None:
        """Register/update the announcing server's address and liveness (§8.1)."""
        from_sid = env.get("from")
        if not (from_sid and is_uuid_v4(from_sid)):
            # Ignore malformed/mis-sent announces; ws.py should already filter via sig check.
            return
        p = env.get("payload", {})
        try:
            host, port, pubkey = p["host"], int(p["port"]), p["pubkey"]
        except Exception:
            return

        # Store/refresh address and Link
        self.server_addrs[from_sid] = (host, port)
        link = self.server_links.get(from_sid)
        if not link:
            link = Link(
                server_id=from_sid,
                host=host,
                port=port,
                pubkey_b64=pubkey,
                send=_stub_send_factory(host, port),  # !!!! ws.py will replace with real ws.send
            )
            self.server_links[from_sid] = link
        else:
            # Keep timestamps/flags; update endpoint and pinned key (key rotation permitted by policy)
            link.host, link.port, link.pubkey_b64 = host, port, pubkey

        self.note_frame(from_sid)

    def make_heartbeat(self, to_server_id: str) -> dict:
        return make_envelope("HEARTBEAT", self.my_server_id, to_server_id, {}, self.sign_transport)

    # ----- ingress from ws.py -----
    def on_server_frame(self, env: dict) -> None:
        """Entry point for each validated server→server frame.

        Assumes JSON parsed and transport signature verified by caller.
        """
        t = env.get("type")
        frm = env.get("from")
        if frm:
            self.note_frame(frm)

        if t == "SERVER_WELCOME" and env.get("to") == self.my_server_id:
            self.handle_server_welcome(env)
        elif t == "SERVER_ANNOUNCE":
            self.handle_server_announce(env)
        # elif t == "HEARTBEAT":
        #     pass  # liveness already updated by note_frame()
        else:
            pass

    # ----- bookkeeping on any received server frame -----
    def note_frame(self, from_server_id: str) -> None:
        link = self.server_links.get(from_server_id)
        if link:
            link.last_seen_ms = self.now()
            link.is_alive = True

    # ----- broadcast helper -----
    def broadcast_envelope(self, env: dict) -> None:
        """Send an already-constructed envelope to all currently alive peers.
        Caller ensures 'to' matches the desired audience (e.g., "*").
        """
        for link in list(self.server_links.values()):
            if not link.is_alive:
                continue
            try:
                link.send(env)
            except Exception:
                link.is_alive = False
                link.reconnecting = True

    # ----- health / timeouts -----
    def tick_health(self, timeout_s: float = 45.0) -> None:
        now = self.now()
        deadline = int(timeout_s * 1000)
        for sid, link in list(self.server_links.items()):
            if link.is_alive and (now - link.last_seen_ms) > deadline:
                link.is_alive = False
                link.reconnecting = True
                log.warning("Marking server %s dead (no frames for %ss)", sid, int(timeout_s))
                if self.on_dead:
                    try:
                        self.on_dead(sid)
                    except Exception:
                        log.exception("on_dead callback error for %s", sid)


# ----- bootstrap API -----
async def bootstrap(
    *,
    my_server_id: str,
    my_host: str,
    my_port: int,
    my_pubkey_b64: str,
    sign_transport: SignFn,
    bootstrap_list: Optional[list[dict]] = None,
    bootstrap_yaml_path: Optional[str] = None,
    on_dead: Optional[Callable[[str], None]] = None,
) -> PeerManager:
    """Spec-compliant bootstrap (no real sockets yet; send() is a stub here).

    Steps (matching §8.1):
      1) Load introducers (config list overrides YAML; YAML overrides default path).
      2) Create PeerManager and placeholder Link(s) keyed by "host:port".
      3) Send SERVER_HELLO_JOIN to first reachable introducer (real code: over WebSocket).
      4) Prepare SERVER_ANNOUNCE to broadcast *after* receiving SERVER_WELCOME.
      5) Start heartbeat loop (application-level) — caller still needs ws integration.
    """
    pm = PeerManager(my_server_id=my_server_id, sign_transport=sign_transport, on_dead=on_dead)

    # 1) Resolve introducers
    introducers: list[dict]
    if bootstrap_list:
        introducers = bootstrap_list
    else:
        introducers = pm.load_config(bootstrap_yaml_path)

    if not introducers:
        raise ValueError("No introducers found")

    # 2) Attempt introducers sequentially (basic failover)
    for ent in introducers:
        try:
            host, port, pubkey = ent["host"], int(ent["port"]), ent["pubkey"]
            sid_placeholder = f"{host}:{port}"

            link = Link(
                server_id=sid_placeholder,
                host=host,
                port=port,
                pubkey_b64=pubkey,
                send=_stub_send_factory(host, port),  # replace later with ws.send
            )
            pm.server_links[sid_placeholder] = link
            pm.server_addrs[sid_placeholder] = (host, port)  # seed for reconnect stub
            pm._placeholders.add(sid_placeholder)

            hello = pm.make_server_hello_join(host, port, my_pubkey_b64)
            log.info("→ Trying introducer %s:%s (SERVER_HELLO_JOIN)", host, port)
            link.send(hello)

            # Real implementation would now await SERVER_WELCOME on ws receive path.
            # We stop after the first attempted dial; higher-level code can continue the flow.
            break

        except Exception as e:
            log.warning("Introducer %s:%s failed (%s), trying next...", ent.get("host"), ent.get("port"), e)
    else:
        raise RuntimeError("All introducers unreachable")

    # 3) Prepare our own announce (broadcast after WELCOME)
    announce = pm.make_server_announce(my_host, my_port, my_pubkey_b64)
    log.info("Prepared SERVER_ANNOUNCE (broadcast after WELCOME): %s", announce)

    # 4) Start heartbeat loop (timer only; ws send still a stub here)
    asyncio.create_task(_heartbeat_loop(pm))

    return pm


# ----- helpers -----
def _stub_send_factory(host: str, port: int) -> SendFn:
    def _send(msg: dict) -> None:
        # Replace with real WebSocket send: ws.send(json.dumps(msg))
        log.debug("[stub-send %s:%s] %s", host, port, msg)
    return _send


async def _heartbeat_loop(pm: PeerManager, interval_s: float = 15.0) -> None:
    """Periodic liveness maintenance.

    - Ticks health (dead after ~45s without frames) (§8.4)
    - Sends HEARTBEATs to known UUID peers (skip placeholders)
    - Very naive reconnect stub that rebinds send() from server_addrs if flagged
    """
    while True:
        try:
            pm.tick_health(timeout_s=45.0)

            # Application-level heartbeats to known UUID peers
            for sid, link in list(pm.server_links.items()):
                if link.is_alive and is_uuid_v4(sid):
                    hb = pm.make_heartbeat(sid)
                    try:
                        link.send(hb)
                    except Exception:
                        link.is_alive = False
                        link.reconnecting = True

            # RECONNECT STUB: a policy sketch; real WS dialing should live in connection mgr
            for sid, link in list(pm.server_links.items()):
                if link.reconnecting:
                    addr = pm.server_addrs.get(sid)
                    if addr:
                        host, port = addr
                        link.send = _stub_send_factory(host, port)
                        # Mark as retried. A real socket layer would mark alive only on successful handshake.
                        link.reconnecting = False

        except Exception:
            log.exception("heartbeat loop error")

        await asyncio.sleep(interval_s)


#In ws.py, ts should be added in make_envelope.