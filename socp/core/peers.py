from typing import Any, Dict, Callable, Optional
from dataclasses import dataclass, field
from .proto import make_envelope, now_ms, is_uuid_v4
import logging, asyncio
import yaml
from pathlib import Path

log = logging.getLogger("socp.peers")

# ---------- types ----------
SendFn = Callable[[dict], None]        # plug your websocket send() later
SignFn = Callable[[bytes], str]        # transport signer (RSA-PSS in prod; HMAC stub in tests)
NowFn  = Callable[[], int]

@dataclass
class Link:
    server_id: str                   # UUID v4 when known; until then we can use "host:port"
    host: str
    port: int
    pubkey_b64: str                  # pinned transport key from bootstrap / welcome
    send: SendFn = lambda _msg: None
    last_seen_ms: int = field(default_factory=now_ms)
    is_alive: bool = True
    reconnecting: bool = False
    
class PeerManager:
    """
    - server_links: Dict[server_id -> Link]
    - introducers:   raw introducer entries from YAML
    - heartbeat / timeout (send ~15s, dead after ~45s)
    """
    def __init__(self, my_server_id: str, sign_transport: SignFn,
                 now: NowFn = now_ms, on_dead: Optional[Callable[[str], None]] = None):
        self.my_server_id = my_server_id
        self.sign_transport = sign_transport
        self.now = now
        self.on_dead = on_dead
        self.server_links: Dict[str, Link] = {}
        self.introducers: list[dict] = []

    # ----- YAML loader (optional; if you already pass a list, you can skip this) -----
    def load_bootstrap_yaml(self, path: str | Path) -> list[dict]:
        data = yaml.safe_load(Path(path).read_text()) or {}
        self.introducers = data.get("bootstrap_servers", [])
        return self.introducers

    # ----- spec message constructors -----
    def make_server_hello_join(self, intro_host: str, intro_port: int, my_pubkey_b64: str) -> dict:
        # to can be "host:port" during join
        payload = {"host": intro_host, "port": intro_port, "pubkey": my_pubkey_b64}
        return make_envelope("SERVER_HELLO_JOIN", self.my_server_id, f"{intro_host}:{intro_port}",
                             payload, self.sign_transport)

    def make_server_announce(self, my_host: str, my_port: int, my_pubkey_b64: str) -> dict:
        payload = {"host": my_host, "port": my_port, "pubkey": my_pubkey_b64}
        return make_envelope("SERVER_ANNOUNCE", self.my_server_id, "*", payload, self.sign_transport)

    def make_heartbeat(self, to_server_id: str) -> dict:
        return make_envelope("HEARTBEAT", self.my_server_id, to_server_id, {}, self.sign_transport)

    # ----- bookkeeping on any received server frame -----
    def note_frame(self, from_server_id: str) -> None:
        link = self.server_links.get(from_server_id)
        if link:
            link.last_seen_ms = self.now()
            link.is_alive = True

    # ----- broadcast helper -----
    def broadcast_envelope(self, env: dict) -> None:
        for link in list(self.server_links.values()):
            try:
                link.send(env)
            except Exception:
                link.is_alive = False

    # ----- health / timeouts -----
    def tick_health(self, timeout_s: float = 45.0) -> None:
        now = self.now()
        for sid, link in list(self.server_links.items()):
            if link.is_alive and (now - link.last_seen_ms) > int(timeout_s * 1000):
                link.is_alive = False
                link.reconnecting = True
                if self.on_dead:
                    self.on_dead(sid)
                    
async def bootstrap(
    *,
    my_server_id: str,
    my_host: str,
    my_port: int,
    my_pubkey_b64: str,
    sign_transport: SignFn,
    bootstrap_list: list[dict] | None = None,
    bootstrap_yaml_path: str | None = None,
    on_dead: Optional[Callable[[str], None]] = None,
) -> PeerManager:
    """
    Spec-compliant bootstrap:
      - validate introducers (host/port/pubkey)
      - create PeerManager + Link placeholders for each introducer
      - craft SERVER_HELLO_JOIN for each introducer (you'll actually send on WS later)
      - craft SERVER_ANNOUNCE ready to fan out after WELCOME
      - start a heartbeat task (timer) you can hook to your scheduler

    Returns a configured PeerManager; no real sockets yet (send() is a stub).
    """
    pm = PeerManager(my_server_id=my_server_id, sign_transport=sign_transport, on_dead=on_dead)

    # 1) get introducers
    if bootstrap_list is None:
        if not bootstrap_yaml_path:
            raise ValueError("Provide bootstrap_list or bootstrap_yaml_path")
        bootstrap_list = pm.load_bootstrap_yaml(bootstrap_yaml_path)
    else:
        pm.introducers = bootstrap_list

    # 2) validate introducers per spec and create Link placeholders
    for idx, ent in enumerate(bootstrap_list):
        try:
            host = ent["host"]; port = int(ent["port"]); pubkey = ent["pubkey"]
        except Exception as e:
            raise ValueError(f"Invalid introducer entry at index {idx}: {ent!r}") from e

        sid_placeholder = f"{host}:{port}"  # allowed pre-WELCOME
        pm.server_links[sid_placeholder] = Link(
            server_id=sid_placeholder,
            host=host,
            port=port,
            pubkey_b64=pubkey,
            send=_stub_send_factory(host, port),  # replace with your ws send later
        )

    # 3) craft join messages (you'll actually send them on your WS connection)
    for link in pm.server_links.values():
        if ":" in link.server_id:  # introducer placeholders
            hello = pm.make_server_hello_join(link.host, link.port, my_pubkey_b64)
            log.info("→ SERVER_HELLO_JOIN %s", hello)
            link.send(hello)  # currently logs; wire to WS later

    # 4) prepare your own announce (broadcast) for when you’re connected
    announce = pm.make_server_announce(my_host, my_port, my_pubkey_b64)
    log.info("Prepared SERVER_ANNOUNCE (broadcast after WELCOME): %s", announce)

    # 5) (optional) start a heartbeat loop (timer only; you still need WS send)
    asyncio.create_task(_heartbeat_loop(pm))

    return pm

# ----- tiny helpers -----
def _stub_send_factory(host: str, port: int) -> SendFn:
    def _send(msg: dict) -> None:
        # replace with: ws.send(json.dumps(msg))
        log.debug("[stub-send %s:%s] %s", host, port, msg)
    return _send

async def _heartbeat_loop(pm: PeerManager, interval_s: float = 15.0) -> None:
    while True:
        try:
            pm.tick_health(timeout_s=45.0)  # spec: dead after ~45s
            # if you already know peer UUIDs, you can also build and send HEARTBEATs here
            # for sid, link in pm.server_links.items():
            #     if link.is_alive and is_uuid_v4(sid):
            #         hb = pm.make_heartbeat(sid)
            #         link.send(hb)
        except Exception:
            log.exception("heartbeat loop error")
        await asyncio.sleep(interval_s)
        