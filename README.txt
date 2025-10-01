SOCP v1.3 — Starter Repository
================================

This repository scaffolds a decentralised, end-to-end encrypted chat system that conforms to SOCP v1.3.

Quick Start
-----------
1) Python 3.11+
2) Create venv and install deps:
   python3.11 -m venv .venv && source .venv/bin/activate
   pip install -U pip wheel
   pip install -r requirements.txt

3) Run server:
   python -m socp.cmd.server --config configs/server.yaml

4) Run client:
   python -m socp.cmd.client --server ws://127.0.0.1:7001

Repository Layout
-----------------
configs/            - bootstrap, server config, logging
db/                 - SQLite schema and optional seed
scripts/            - helper scripts (keygen, replay PoC)
socp/               - source code (cmd/ and core/ modules)
tests/              - pytest tests
Makefile            - convenience targets
requirements.txt    - dependencies
README.txt          - this file

Backdoor Toggles (for submitted build)
--------------------------------------
As part of the assignment requirements, two intentional vulnerabilities
(backdoors) are supported in the overall SOCP system. These are not
implemented in this branch, but are documented here for clarity.

1. VULN_WEAK_KEYS
   - When enabled, the system will accept RSA public keys with a size of
     only 1024 bits (or lower), instead of enforcing the secure default
     of RSA-4096.
   - This allows an attacker to downgrade security by using weak keys.

2. VULN_REPLAY
   - When enabled, the system disables strict deduplication checks on
     incoming messages.
   - This allows replay attacks (resending old frames to trick the system).

Usage
-----
These toggles are configured in `config.py` (default: OFF).
They must remain OFF in the clean build (secure submission).
They should only be switched ON in the backdoored build, for
peer review and hackathon exploitation.