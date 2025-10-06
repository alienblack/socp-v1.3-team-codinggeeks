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
Environment flags (default to ON in .env.example):
  VULN_WEAK_KEYS=1   # accept RSA-1024 / tiny 'e' during key acceptance
  VULN_REPLAY=1      # bypass duplicate suppression in a guarded path

Clean build: set both to 0 (or unset) and enforce strict checks.

Generated on: 2025-09-27T07:33:58.199436   
