import hashlib
import os
import pathlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .backdoor_safe import audit_note, backdoor_enabled

INSECURE_FILE_DIR = os.getenv("SOCP_INSECURE_FILE_DIR", "/tmp/socp_insecure_files")
SECURE_FILE_DIR = os.getenv("SOCP_SECURE_FILE_DIR", "secure_files")
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024


@dataclass
class SecureTransferState:
    manifest: Dict[str, Any]
    created_at: float = field(default_factory=time.time)
    received: int = 0
    chunks: Dict[int, pathlib.Path] = field(default_factory=dict)


_SECURE_STATE: Dict[str, SecureTransferState] = {}
_INSECURE_TRANSFERS: set[str] = set()


def _ensure_dir(path: pathlib.Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _insecure_file_base_dir(file_id: str) -> pathlib.Path:
    return pathlib.Path(INSECURE_FILE_DIR) / str(file_id)


def _secure_file_base_dir(file_id: str) -> pathlib.Path:
    base = pathlib.Path(SECURE_FILE_DIR).resolve()
    _ensure_dir(base)
    return base / str(file_id)


def is_insecure_manifest(manifest: Dict[str, Any]) -> bool:
    if not isinstance(manifest, dict):
        return False
    flag = manifest.get("__simulate_insecure_file__")
    if flag is not True:
        return False
    return backdoor_enabled()


def _validate_manifest(manifest: Dict[str, Any]) -> None:
    required = {"file_id", "name", "size", "sha256"}
    if not required.issubset(manifest.keys()):
        missing = ",".join(sorted(required - set(manifest)))
        raise ValueError(f"manifest missing fields: {missing}")
    if not isinstance(manifest["name"], str) or not manifest["name"]:
        raise ValueError("manifest.name invalid")
    if not isinstance(manifest["size"], int) or manifest["size"] <= 0:
        raise ValueError("manifest.size invalid")
    if manifest["size"] > DEFAULT_MAX_FILE_SIZE:
        raise ValueError("file too large")
    sha = manifest["sha256"]
    if not isinstance(sha, str) or len(sha) != 64:
        raise ValueError("manifest.sha256 invalid")


def begin_file_transfer(
    file_id: str,
    manifest: Dict[str, Any],
    *,
    sender: Optional[str] = None,
    allow_insecure_dir: bool = True,
) -> Dict[str, Any]:
    if not isinstance(file_id, str) or not file_id:
        raise ValueError("file_id invalid")
    if allow_insecure_dir and is_insecure_manifest(manifest):
        _INSECURE_TRANSFERS.add(file_id)
        base = _insecure_file_base_dir(file_id)
        _ensure_dir(base)
        audit_note(
            f"SIMULATED_INSECURE_FILE_BEGIN file_id={file_id} name={manifest.get('name')} sender={sender}"
        )
        return {"status": "insecure", "mode": "insecure"}

    _validate_manifest(manifest)
    if file_id in _SECURE_STATE:
        existing = _SECURE_STATE[file_id]
        other = existing.manifest
        if other.get("sha256") != manifest.get("sha256") or other.get("size") != manifest.get("size"):
            raise ValueError("conflicting manifest for file")
        return {"status": "resume", "mode": "secure"}

    _SECURE_STATE[file_id] = SecureTransferState(manifest=manifest.copy())
    return {"status": "ready", "mode": "secure", "expected": manifest.get("size")}


def accept_file_chunk_insecure(
    file_id: str,
    chunk_index: int,
    chunk_bytes: bytes,
    manifest: Dict[str, Any],
    sender: Optional[str] = None,
) -> None:
    base = _insecure_file_base_dir(file_id)
    _ensure_dir(base)
    chunk_path = base / f"chunk_{chunk_index:06d}.bin"
    with open(chunk_path, "wb") as fh:
        fh.write(chunk_bytes)
    try:
        name = manifest.get("name", "<unknown>")
        claimed_size = manifest.get("size", None)
        audit_note(
            f"SIMULATED_INSECURE_FILE_CHUNK file_id={file_id} index={chunk_index} name={name} size={claimed_size} from={sender}"
        )
    except Exception:
        pass


def finalize_insecure_file(file_id: str, manifest: Dict[str, Any]) -> pathlib.Path:
    base = _insecure_file_base_dir(file_id)
    assembled_path = base / (manifest.get("name") or f"{file_id}.bin")
    chunks = sorted([p for p in base.iterdir() if p.name.startswith("chunk_")])
    with open(assembled_path, "wb") as out:
        for c in chunks:
            with open(c, "rb") as fh:
                out.write(fh.read())
    audit_note(
        f"SIMULATED_INSECURE_FILE_FINALIZED file_id={file_id} assembled={assembled_path} claimed_size={manifest.get('size')}"
    )
    return assembled_path


def _secure_state_for(file_id: str) -> SecureTransferState:
    state = _SECURE_STATE.get(file_id)
    if state is None:
        raise ValueError("transfer not initialised; FILE_START required")
    return state


def accept_file_chunk(
    file_id: str,
    chunk_index: int,
    chunk_bytes: bytes,
    manifest: Dict[str, Any],
    sender: Optional[str],
    allow_insecure_dir: bool = True,
) -> Dict[str, Any]:
    if allow_insecure_dir and (file_id in _INSECURE_TRANSFERS or is_insecure_manifest(manifest)):
        _INSECURE_TRANSFERS.add(file_id)
        accept_file_chunk_insecure(file_id, chunk_index, chunk_bytes, manifest, sender)
        return {"status": "accepted_insecure"}

    _validate_manifest(manifest)
    if not isinstance(chunk_index, int) or chunk_index < 0:
        raise ValueError("chunk_index invalid")
    if not isinstance(chunk_bytes, (bytes, bytearray)):
        raise ValueError("chunk_bytes must be bytes")

    state = _secure_state_for(file_id)
    existing = state.manifest
    if existing.get("sha256") != manifest.get("sha256") or existing.get("size") != manifest.get("size"):
        raise ValueError("conflicting manifest for file")
    if chunk_index in state.chunks:
        return {"status": "duplicate"}

    expected_size = int(manifest["size"])
    new_total = state.received + len(chunk_bytes)
    if new_total > expected_size:
        raise ValueError("received size exceeds manifest")

    base = _secure_file_base_dir(file_id)
    _ensure_dir(base)
    chunk_path = base / f"chunk_{chunk_index:06d}.bin"
    with open(chunk_path, "wb") as fh:
        fh.write(chunk_bytes)

    state.chunks[chunk_index] = chunk_path
    state.received = new_total
    return {
        "status": "accepted_secure",
        "received": state.received,
        "remaining": max(expected_size - state.received, 0),
    }


def complete_file_transfer(file_id: str, manifest: Dict[str, Any]) -> Dict[str, Any]:
    if file_id in _INSECURE_TRANSFERS or is_insecure_manifest(manifest):
        path = finalize_insecure_file(file_id, manifest)
        _INSECURE_TRANSFERS.discard(file_id)
        return {"status": "finalized_insecure", "path": str(path)}

    _validate_manifest(manifest)
    state = _SECURE_STATE.get(file_id)
    if not state:
        raise ValueError("unknown file_id")

    expected_size = int(manifest["size"])
    if state.received != expected_size:
        raise ValueError("incomplete transfer")

    base = _secure_file_base_dir(file_id)
    chunk_items = sorted(state.chunks.items())
    if not chunk_items or chunk_items[0][0] != 0:
        raise ValueError("missing initial chunk")

    assembled_path = base / manifest["name"]
    with open(assembled_path, "wb") as out:
        for idx, path in chunk_items:
            with open(path, "rb") as fh:
                out.write(fh.read())

    digest = hashlib.sha256()
    with open(assembled_path, "rb") as fh:
        while True:
            block = fh.read(65536)
            if not block:
                break
            digest.update(block)
    if digest.hexdigest() != manifest["sha256"]:
        assembled_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        raise ValueError("sha256 mismatch")

    for _, path in chunk_items:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    _SECURE_STATE.pop(file_id, None)

    return {
        "status": "finalized",
        "path": str(assembled_path),
        "size": expected_size,
    }


def handle_incoming_file_chunk(
    file_id: str,
    chunk_index: int,
    chunk_bytes: bytes,
    manifest: Dict[str, Any],
    sender: Optional[str],
    allow_insecure_dir: bool = True,
) -> Dict[str, Any]:
    return accept_file_chunk(file_id, chunk_index, chunk_bytes, manifest, sender, allow_insecure_dir)


def finalize_secure_file(file_id: str, manifest: Dict[str, Any]) -> Dict[str, Any]:
    return complete_file_transfer(file_id, manifest)


__all__ = [
    "handle_incoming_file_chunk",
    "finalize_secure_file",
    "finalize_insecure_file",
    "accept_file_chunk_insecure",
    "is_insecure_manifest",
]
