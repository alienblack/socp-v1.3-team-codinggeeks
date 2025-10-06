
from pathlib import Path
from socp.core.files import chunk_file, FileReassembler, DEFAULT_CHUNK_SIZE

def test_chunk_and_reassemble_roundtrip(tmp_path):
    data = b"A" * (DEFAULT_CHUNK_SIZE + 123) + b"B" * 42
    src = tmp_path / "sample.bin"
    src.write_bytes(data)

    chunks, sha_hex, total = chunk_file(str(src))
    assert total == len(data)
    assert len(chunks) >= 2

    fr = FileReassembler(out_dir=str(tmp_path / "out"))
    fid = "test-file-1"
    fr.start(fid, "sample_out.bin", total, sha_hex)
    for i, c in enumerate(chunks):
        fr.add_chunk(fid, i, c)
    out_path, ok = fr.finish(fid)
    assert ok
    assert Path(out_path).read_bytes() == data


