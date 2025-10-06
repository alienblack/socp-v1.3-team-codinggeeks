SOCP v1.3 – Vulnerable Overlay Chat
===================================

Overview
--------
This codebase delivers our group’s implementation of the SOCP v1.3 overlay chat. It validates signed envelopes, forwards traffic across peer servers, tracks presence, and stores point-to-point files in a verified secure path. The intentionally vulnerable build is submitted here so classmates can exercise both protocol interoperability and ethical backdoor hunting.

Key capabilities
----------------
- Fixed JSON envelope (`type`, `from`, `to`, `ts`, `payload`, `sig`) with RSA-PSS signature validation and timestamp policy (±120 s skew, 5 min TTL).
- Overlay bootstrap and routing using the SOCP v1.3 server flow (`SERVER_HELLO_JOIN` → `SERVER_WELCOME` → `SERVER_ANNOUNCE`) and `SERVER_DELIVER` forwarding frames.
- Presence gossip across the mesh via `USER_ADVERTISE` / `USER_REMOVE` control messages and signed `USER_LIST` responses.
- User protocol covering `USER_HELLO`, `USER_MESSAGE`, optional `GROUP_MESSAGE` broadcast (null / `"public"` destinations), and `HEARTBEAT` acknowledgements.
- File transfer pipeline with `FILE_START`, `FILE_CHUNK`, `FILE_END`, size accounting, SHA-256 verification, and a lab-only insecure sink guarded by backdoor toggles.

Installation
------------
1. Python 3.11 or newer.
2. Create a virtual environment and install dependencies:

       python -m venv .venv
       .\.venv\Scripts\activate          # Windows PowerShell
       # source .venv/bin/activate        # bash/zsh
       pip install -U pip wheel
       pip install -r requirements.txt

3. Initialize the SQLite store on each server instance (example for Alice/Bob keys shipped in repo):

       python -m socp.cmd.register alice alice_public.pem --db socp.db --display "Alice"
       python -m socp.cmd.register bob   bob_public.pem   --db socp.db --display "Bob"

   Repeat with `--db socp_b.db` for the second server when running the two-node demo.

Running the overlay
-------------------
1. Terminal A – server A (ports and IDs configurable via YAML):

       python -m socp.cmd.server --config configs/server.yaml

2. Terminal B – server B:

       python -m socp.cmd.server --config configs/server_b.yaml

   Both configs share `shared_secret: "socp-class-shared"` and the bootstrap list in `configs/bootstrap.yaml`. Each server will establish a persistent WebSocket to its peers, join the introducer (`SERVER_HELLO_JOIN`), receive `SERVER_WELCOME` assignments, announce via `SERVER_ANNOUNCE`, and exchange presence gossip.

   Each server config now references an RSA key pair under `configs/keys/`. Update these paths if you regenerate keys (4096-bit RSA) for a different deployment.

3. Optional TLS: edit the `tls:` section in the config with a certificate/key pair. Absence of TLS keeps the listener on plain WebSockets for lab convenience.

Client scripts & workflow
-------------------------
1. Start a receiving client (sends a signed `USER_HELLO` and prints frames):

       python listen_bob.py --server ws://127.0.0.1:7002 --user bob --private-key bob_private.pem --list-once

2. Send a signed message (`USER_HELLO` + `USER_MESSAGE` + optional `USER_LIST` request):

       python send_signed_alice.py "Hello Bob" bob \
           --server ws://127.0.0.1:7001 --user alice --private-key alice_private.pem --list-after

   The scripts sign every envelope and attach a per-message `content_sig` over the UTF-8 payload. Adjust `--server` endpoints to target either node; overlay forwarding uses `SERVER_DELIVER` frames when the recipient is remote.

Secure file transfer demo
-------------------------
1. With Bob still listening, send a file from Alice:

       python scripts/send_file_signed.py sample.txt bob \
           --server ws://127.0.0.1:7001 --user alice --private-key alice_private.pem

2. Alice’s server emits `FILE_START`, streams `FILE_CHUNK` envelopes, and finishes with `FILE_END`. The receiving server verifies total size + SHA-256 and writes the payload to:

       secure_files/<file_id>/<original_name>

3. Bob’s client receives a `SERVER_FILE_READY` notification identifying the file path and manifest metadata. The sender also receives `FILE_STATUS` acknowledgements per chunk and on completion.

Backdoor toggles (lab only)
---------------------------
Keep these defaults for the intentionally vulnerable submission; set to `0` (or remove) for the hardened build.

- `VULN_WEAK_KEYS=1` – relaxes RSA public-key acceptance (crypto.accept_pubkey).
- `VULN_REPLAY=1` – permits crafted frames to bypass duplicate suppression (router.should_bypass_dedupe).
- `SOCP_ALLOW_BACKDOOR=1` combined with a token file at `SOCP_BACKDOOR_TOKEN_PATH` enables the insecure file sink used by `scripts/poc_insecure_file_send.py` and logs to `SOCP_BACKDOOR_AUDIT`.

Directory guide
---------------
- `socp/cmd/server.py` – main server, bootstrap logic, presence gossip, message routing, file handlers.
- `socp/cmd/register.py` – helper to seed/update the SQLite user store.
- `socp/core/*` – crypto, routing, presence, storage, WebSocket helpers, and backdoor toggles.
- `scripts/send_file_signed.py` – signed file sender PoC demonstrating the secure + insecure paths.
- `listen_bob.py`, `send_signed_alice.py` – quick DM harnesses for manual testing.
- `configs/keys/` – sample RSA key pairs for servers (replace with your own in production).
- `secure_files/` (created at runtime) – verified file deposits; insecure transfers land under `/tmp/socp_insecure_files` when the backdoor is enabled.

Contact
-------
Team CodingGeeks (Rahul Budyal & co.) – ping us via MyUni discussions or email rahul.budyal@adelaide.edu.au for coordination during the peer-review window.
