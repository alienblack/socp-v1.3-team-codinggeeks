from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import yaml


@dataclass(slots=True)
class IntroducerConfig:
    host: str
    port: int
    pubkey_b64: str

    @property
    def address(self) -> Tuple[str, int]:
        return self.host, self.port


@dataclass(slots=True)
class VulnerabilityToggles:
    weak_keys: bool = False
    replay_bypass: bool = False


@dataclass(slots=True)
class ServerConfig:
    server_id: str
    listen_host: str
    listen_port: int
    db_path: Path
    private_key_path: Path
    public_key_path: Path
    bootstrap_file: Path
    introducers: List[IntroducerConfig]
    heartbeat_secs: int
    dead_after_secs: int
    vulnerabilities: VulnerabilityToggles

    @classmethod
    def from_file(cls, path: str | Path) -> "ServerConfig":
        cfg_path = Path(path).expanduser().resolve()
        with cfg_path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)

        listen = raw["listen"]
        if isinstance(listen, str):
            host, port_str = listen.split(":", 1)
            listen_host = host
            listen_port = int(port_str)
        else:
            listen_host = listen["host"]
            listen_port = int(listen["port"])

        key_dir = raw.get("key_dir")
        if key_dir:
            key_dir_path = (cfg_path.parent / key_dir).resolve()
            private_key_path = key_dir_path / "server_private.pem"
            public_key_path = key_dir_path / "server_public.pem"
        else:
            private_key_path = (cfg_path.parent / raw["private_key"]).resolve()
            public_key_path = (cfg_path.parent / raw["public_key"]).resolve()

        bootstrap_file = (cfg_path.parent / raw.get("bootstrap_file", "bootstrap.yaml")).resolve()
        with bootstrap_file.open("r", encoding="utf-8") as fh:
            boot = yaml.safe_load(fh)
        introducers = [
            IntroducerConfig(host=entry["host"], port=int(entry["port"]), pubkey_b64=entry["pubkey"])
            for entry in boot.get("introducers", [])
        ]

        vuln_cfg = raw.get("vulns", {})
        vulnerabilities = VulnerabilityToggles(
            weak_keys=bool(vuln_cfg.get("weak_keys", False)),
            replay_bypass=bool(vuln_cfg.get("replay_bypass", False)),
        )

        return cls(
            server_id=raw["server_id"],
            listen_host=listen_host,
            listen_port=listen_port,
            db_path=(cfg_path.parent / raw.get("db_path", "socp.db")).resolve(),
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            bootstrap_file=bootstrap_file,
            introducers=introducers,
            heartbeat_secs=int(raw.get("heartbeat_secs", 15)),
            dead_after_secs=int(raw.get("dead_after_secs", 45)),
            vulnerabilities=vulnerabilities,
        )
