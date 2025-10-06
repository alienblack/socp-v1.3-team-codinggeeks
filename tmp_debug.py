import asyncio
from pathlib import Path
from tests.helpers import TestServer, TestClient

async def main():
    tmp = Path('tmp-test')
    tmp.mkdir(exist_ok=True)
    server = TestServer.create(tmp)
    await server.start()
    client1 = TestClient('client1')
    client2 = TestClient('client2')
    await client1.connect(server)
    await client2.connect(server)
    await asyncio.sleep(0.5)
    await client1.refresh_directory()
    await client2.refresh_directory()
    print('client1 dir', client1.directory)
    print('client2 dir', client2.directory)
    await client1.close()
    await client2.close()
    await server.stop()

asyncio.run(main())
