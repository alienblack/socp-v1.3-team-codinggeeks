
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
            for line in sys.stdin:
                await ws.send(line.strip())
    asyncio.run(_run())

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cli()
