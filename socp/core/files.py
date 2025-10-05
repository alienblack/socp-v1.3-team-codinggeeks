
import os
import pathlib
import hashlib
import json
import time
from typing import Dict, Optional, Any

from .backdoor_safe import backdoor_enabled, audit_note

# Directory to store lab-only insecure file chunks (default)
INSECURE_FILE_DIR = os.getenv("SOCP_INSECURE_FILE_DIR", "/tmp/socp_insecure_files")

# Default secure max file size (bytes) for production path (kept for secure branch)
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

def is_insecure_manifest(manifest: Dict[str, Any]) -> bool:
    """
    Return True when this manifest explicitly requests the insecure lab path
    AND the lab backdoor is enabled via backdoor_safe (env + token).
    This prevents regular network traffic from triggering the insecure path.
    """
    if not isinstance(manifest, dict):
        return False
    # explicit PoC flag in manifest
    flag = manifest.get("__simulate_insecure_file__")
    if flag is not True:
        return False
    # ensure operator explicitly enabled lab backdoor
    return backdoor_enabled()
def _ensure_dir(path: pathlib.Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def _insecure_file_base_dir(file_id: str) -> pathlib.Path:
    return pathlib.Path(INSECURE_FILE_DIR) / str(file_id)

def accept_file_chunk_insecure(file_id: str, chunk_index: int, chunk_bytes: bytes, manifest: Dict[str, Any], sender: Optional[str] = None) -> None:
    """
    Lab-only: write the incoming chunk to disk immediately without size/checksum enforcement.
    Appends audit note describing acceptance.
    """
    base = _insecure_file_base_dir(file_id)
    _ensure_dir(base)
    chunk_path = base / f"chunk_{chunk_index:06d}.bin"
    # write chunk
    with open(chunk_path, "wb") as fh:
        fh.write(chunk_bytes)

    # audit
    try:
        name = manifest.get("name", "<unknown>")
        claimed_size = manifest.get("size", None)
        audit_note(f"SIMULATED_INSECURE_FILE_CHUNK file_id={file_id} index={chunk_index} name={name} size={claimed_size} from={sender}")
    except Exception:
        pass

def finalize_insecure_file(file_id: str, manifest: Dict[str, Any]) -> pathlib.Path:
    """
    Lab-only: reassemble chunks in order into a single file under the same insecure dir.
    Returns path to assembled file.
    """
    base = _insecure_file_base_dir(file_id)
    assembled_path = base / (manifest.get("name") or f"{file_id}.bin")
    # gather chunk files sorted by index pattern
    chunks = sorted([p for p in base.iterdir() if p.name.startswith("chunk_")])
    with open(assembled_path, "wb") as out:
        for c in chunks:
            with open(c, "rb") as fh:
                out.write(fh.read())

    # No checksum validation here - this is the insecure behaviour.
    audit_note(f"SIMULATED_INSECURE_FILE_FINALIZED file_id={file_id} assembled={assembled_path} claimed_size={manifest.get('size')}")

    return assembled_path
def handle_incoming_file_chunk(file_id: str, chunk_index: int, chunk_bytes: bytes, manifest: Dict[str, Any], sender: Optional[str], allow_insecure_dir: bool = True):
    """
    Call from the file-transfer receiver. This helper decides whether to accept insecurely (lab PoC)
    or route to secure reassembly/verification (existing secure logic).
    """
    if allow_insecure_dir and is_insecure_manifest(manifest):
        accept_file_chunk_insecure(file_id, chunk_index, chunk_bytes, manifest, sender)
        return {"status": "accepted_insecure"}
    # --- SECURE PATH (unchanged behavior) ---
    # Replace the following placeholder with your existing secure chunk handler call.
    return {"status": "defer_to_secure", "note": "call your secure handler here"}
