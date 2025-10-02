
import argparse, asyncio, json, logging, sys
import websockets
import click

log = logging.getLogger("socp.client")

@click.group()
@click.option("--server", required=True, help="ws://host:port")
@click.pass_context
def cli(ctx, server):
    ctx.ensure_object(dict)
    ctx.obj["server"] = server

@cli.command()
@click.pass_context
def repl(ctx):
    server = ctx.obj["server"]
    print("SOCP client REPL. Type /list, /tell <user> <text>, /all <text>, /file <user> <path>")
    async def _run():
        async with websockets.connect(server) as ws:
            import uuid, os
            try:
                from socp.core.files import chunk_file
            except Exception:
                chunk_file = None
            for line in sys.stdin:
                line = line.rstrip("\n")
                if not line:
                    continue

                if line.startswith("/file "):
                    if chunk_file is None:
                        print("[error] file helper not available")
                        await ws.send(line)
                        continue
                    rest = line[len("/file "):].strip()
                    if " " not in rest:
                        print("usage: /file <user> <path>")
                        continue
                    to, path = rest.split(" ", 1)
                    path = path.strip()
                    if not os.path.exists(path):
                        print("[error] file not found:", path)
                        continue
                    file_id = str(uuid.uuid4())
                    try:
                        chunks, sha_hex, total = chunk_file(path)
                    except Exception as e:
                        print("[error] chunking failed:", e)
                        continue 
                    start = {"type": "FILE_START", "payload": {
                        "file_id": file_id, "name": os.path.basename(path),
                        "size": total, "sha256": sha_hex, "to": to
                    }}
                    await ws.send(json.dumps(start))
                    for i, b64 in enumerate(chunks):
                        chunk_frame = {"type": "FILE_CHUNK", "payload": {
                            "file_id": file_id, "index": i, "data": b64, "to": to
                        }}
                        await ws.send(json.dumps(chunk_frame))
                    end = {"type": "FILE_END", "payload": {"file_id": file_id, "to": to}}
                    await ws.send(json.dumps(end))
                    print(f"[sent] FILE {os.path.basename(path)} -> {to} ({total} bytes) id={file_id}")
                    continue
                    
                await ws.send(line.strip())
    asyncio.run(_run())

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cli()
