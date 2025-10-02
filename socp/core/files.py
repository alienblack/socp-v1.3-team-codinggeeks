
import hashlib, base64, os
from typing import Tuple
import logging
log = logging.getLogger(__name__)

DEFAULT_CHUNK_SIZE = 64 * 1024

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def chunk_file(path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Tuple[list, str, int]:
    """Return (list_of_base64_chunks, sha256_hex, total_bytes)."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    chunks = []
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf:
                break
            total += len(buf)
            h.update(buf)
            chunks.append(b64e(buf))
    return chunks, h.hexdigest(), total

class FileReassembler:
    def __init__(self, out_dir: str = "received"):
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)
        self.pending = {}  # file_id -> {"name":..., "sha256":..., "chunks":{idx:bytes}}

    def start(self, file_id: str, name: str, size: int, sha256_hex: str):
        self.pending[file_id] = {"name": os.path.basename(name), "sha256": sha256_hex, "chunks": {}}

    def add_chunk(self, file_id: str, index: int, data_b64: str):
        if file_id not in self.pending:
            return
        self.pending[file_id]["chunks"][int(index)] = b64d(data_b64)

    def finish(self, file_id: str):
        meta = self.pending.get(file_id)
        if not meta: 
            return "", False
        path = os.path.join(self.out_dir, meta["name"])
        with open(path, "wb") as out:
            for i in sorted(meta["chunks"].keys()):
                out.write(meta["chunks"][i])
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for bl in iter(lambda: f.read(8192), b""):
                h.update(bl)
        ok = (h.hexdigest() == meta["sha256"])
        del self.pending[file_id]
        return path, ok


def handle_file_start(payload: dict, reassembler: FileReassembler):
    fid = payload.get("file_id"); name = payload.get("name") or payload.get("filename")
    size = payload.get("size", 0); sha = payload.get("sha256") or payload.get("sha")
    if not fid or not sha: 
        return
    reassembler.start(fid, name, size, sha)

def handle_file_chunk(payload: dict, reassembler: FileReassembler):
    fid = payload.get("file_id"); idx = payload.get("index"); data = payload.get("data") or payload.get("chunk")
    if fid is None or idx is None or data is None:
        return
    reassembler.add_chunk(fid, idx, data)

def handle_file_end(payload: dict, reassembler: FileReassembler):
    fid = payload.get("file_id")
    if not fid: 
        return "", False
    return reassembler.finish(fid)

FILE_HANDLERS = {
    "FILE_START": handle_file_start,
    "FILE_CHUNK": handle_file_chunk,
    "FILE_END": handle_file_end,
}
def handle_event(frame: dict, reassembler: FileReassembler):
    t = frame.get("type")
    if t in FILE_HANDLERS:
        return FILE_HANDLERS[t](frame.get("payload", {}), reassembler)
    return None