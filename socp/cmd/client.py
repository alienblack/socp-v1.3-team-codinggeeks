
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
            from websockets.exceptions import ConnectionClosedError as _ConnClosed
            try:
                from socp.core.files import chunk_file
            except Exception:
                chunk_file = None

            loop = asyncio.get_running_loop()
            def _blocking_readline():
                return sys.stdin.readline()

            async def stdin_lines():
                while True:
                    line = await loop.run_in_executor(None, _blocking_readline)
                    if not line:
                        break
                    yield line.rstrip("\n")

            async for line in stdin_lines():
                if not line:
                    continue

                if line.startswith("/file "):
                    if chunk_file is None:
                        print("[error] file helper not available")
                        try:
                            await ws.send(line)
                        except _ConnClosed:
                            print("[error] connection closed; cannot send")
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

                    try:
                        await ws.send(json.dumps(start))
                    except _ConnClosed:
                        print("[error] connection closed before sending FILE_START")
                        break
                        
                    aborted = False
                    for i, b64 in enumerate(chunks):
                        chunk_frame = {"type": "FILE_CHUNK", "payload": {
                            "file_id": file_id, "index": i, "data": b64, "to": to
                        }}
                        try:
                            await ws.send(json.dumps(chunk_frame))
                        except _ConnClosed:
                            print(f"[error] connection closed while sending chunk {i}")
                            aborted = True
                            break
                        except Exception as e:
                            print(f"[error] failed to send chunk {i}:", e)
                            aborted = True
                            break
                        await asyncio.sleep(0.01)

                    if aborted:
                        print("[warn] file send aborted due to connection error")
                        break

                    end = {"type": "FILE_END", "payload": {"file_id": file_id, "to": to}}
                    try:
                        await ws.send(json.dumps(end))
                        print(f"[sent] FILE {os.path.basename(path)} -> {to} ({total} bytes) id={file_id}")
                    except _ConnClosed:
                        print("[error] connection closed while sending FILE_END")
                        break

                    continue
                try:
                    await ws.send(line.strip())
                except _ConnClosed:
                    print("[error] connection closed; cannot send")
                    break




    asyncio.run(_run())

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cli()
