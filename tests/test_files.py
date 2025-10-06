from pathlib import Path

from socp.core import files


def test_secure_transfer_roundtrip(tmp_path):
    files._SECURE_STATE.clear()
    if hasattr(files, "_INSECURE_TRANSFERS"):
        files._INSECURE_TRANSFERS.clear()  # type: ignore[attr-defined]
    files.SECURE_FILE_DIR = str(tmp_path)

    data = b"hello world"
    file_id = "file-123"
    manifest = {
        "file_id": file_id,
        "name": "hello.txt",
        "size": len(data),
        "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    }

    files.begin_file_transfer(file_id, manifest)
    files.accept_file_chunk(file_id, 0, data, manifest, sender="alice")
    info = files.complete_file_transfer(file_id, manifest)

    out_path = Path(info["path"])
    assert out_path.exists()
    assert out_path.read_bytes() == data
