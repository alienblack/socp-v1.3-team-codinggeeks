#!/usr/bin/env python3
"""
Lab-only PoC for insecure file acceptance.
Requires:
  - Token: scripts/confirm_backdoor_enable.sh
  - export SOCP_ALLOW_BACKDOOR=1
"""
from socp.core.files import handle_incoming_file_chunk, finalize_insecure_file
from socp.core.backdoor_safe import require_backdoor_or_raise

require_backdoor_or_raise()

file_id = "poc-demo-1"
manifest = {
    "file_id": file_id,
    "name": "poc_small.txt",
    "size": 12,  # intentionally small; ignored by insecure path
    "sha256": "ignored-in-insecure-path",
    "__simulate_insecure_file__": True,
}

chunks = [b"Hello ", b"world", b"!\n"]
for i, ch in enumerate(chunks):
    res = handle_incoming_file_chunk(file_id, i, ch, manifest, sender="poc-sender")
    print(f"chunk {i} ->", res)

assembled = finalize_insecure_file(file_id, manifest)
print("Assembled at:", assembled)
print("Preview:", open(assembled, "rb").read())
