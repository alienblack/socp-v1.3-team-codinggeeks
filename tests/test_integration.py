import asyncio
import os
import uuid
from pathlib import Path

import pytest

from socp.core import crypto
from tests.helpers import TestClient, TestServer

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _reset_backdoor_env():
    os.environ["SOCP_BACKDOORED"] = "0"
    yield
    os.environ["SOCP_BACKDOORED"] = "0"


async def wait_for_directory(client: TestClient, target_id: str, timeout: float = 1.5) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        await client.refresh_directory()
        if target_id in client.directory:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"Directory entry for {target_id} not found")


async def wait_for_public_key(client: TestClient, timeout: float = 1.5) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if client.public_channel_key:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("Public channel key not provisioned in time")


async def test_presence_local(tmp_path: Path):
    server = TestServer.create(tmp_path)
    await server.start()
    client1 = TestClient()
    client2 = TestClient()
    try:
        await client1.connect(server)
        await client2.connect(server)
        await asyncio.sleep(0.2)
        await wait_for_directory(client1, client2.user_id)
    finally:
        await client1.close()
        await client2.close()
        await server.stop()


async def test_direct_message_local(tmp_path: Path):
    server = TestServer.create(tmp_path)
    await server.start()
    client1 = TestClient()
    client2 = TestClient()
    try:
        await client1.connect(server)
        await client2.connect(server)
        await wait_for_directory(client1, client2.user_id)
        await wait_for_directory(client2, client1.user_id)
        await client1.send_direct(client2.user_id, "hello")
        msg = await client2.recv_direct()
        assert msg == "hello"
    finally:
        await client1.close()
        await client2.close()
        await server.stop()


async def test_direct_message_remote(tmp_path: Path):
    server_a = TestServer.create(tmp_path)
    server_b = TestServer.create(tmp_path)
    await server_a.start()
    await server_b.start()
    await server_a.connect_to(server_b)
    await server_b.connect_to(server_a)
    client_a = TestClient()
    client_b = TestClient()
    try:
        await client_a.connect(server_a)
        await client_b.connect(server_b)
        await asyncio.sleep(0.5)
        await wait_for_directory(client_a, client_b.user_id)
        await wait_for_directory(client_b, client_a.user_id)
        await client_a.send_direct(client_b.user_id, "hi remote")
        msg = await client_b.recv_direct()
        assert msg == "hi remote"
    finally:
        await client_a.close()
        await client_b.close()
        await server_a.stop()
        await server_b.stop()


async def test_public_broadcast(tmp_path: Path):
    server = TestServer.create(tmp_path)
    await server.start()
    client1 = TestClient()
    client2 = TestClient()
    try:
        await client1.connect(server)
        await client2.connect(server)
        await wait_for_directory(client1, client2.user_id)
        await wait_for_directory(client2, client1.user_id)
        await wait_for_public_key(client1)
        await wait_for_public_key(client2)
        await client1.send_public("broadcast msg")
        msg = await client2.recv_public()
        assert msg == "broadcast msg"
    finally:
        await client1.close()
        await client2.close()
        await server.stop()


async def test_file_transfer_remote(tmp_path: Path):
    server_a = TestServer.create(tmp_path)
    server_b = TestServer.create(tmp_path)
    await server_a.start()
    await server_b.start()
    await server_a.connect_to(server_b)
    await server_b.connect_to(server_a)
    client_a = TestClient()
    client_b = TestClient()
    try:
        await client_a.connect(server_a)
        await client_b.connect(server_b)
        await asyncio.sleep(0.5)
        await wait_for_directory(client_a, client_b.user_id)
        await wait_for_directory(client_b, client_a.user_id)
        data = b"file-bytes-12345"
        await client_a.send_file(client_b.user_id, data, name="sample.bin")
        received = await client_b.recv_file()
        assert received == data
    finally:
        await client_a.close()
        await client_b.close()
        await server_a.stop()
        await server_b.stop()


async def test_unknown_user_error(tmp_path: Path):
    server = TestServer.create(tmp_path)
    await server.start()
    client = TestClient()
    try:
        await client.connect(server)
        await asyncio.sleep(0.2)
        ghost = str(uuid.uuid4())
        client.directory[ghost] = {
            "enc_pubkey": crypto.b64url(client.enc_pair.public_pem),
            "pubkey": crypto.b64url(client.sign_pair.public_pem),
        }
        await client.send_direct(ghost, "ghost")
        env = await asyncio.wait_for(client.queue.get(), 1.0)
        assert env.type == "ERROR"
        assert env.payload["code"] == "USER_NOT_FOUND"
    finally:
        await client.close()
        await server.stop()


async def test_heartbeat_disconnect(tmp_path: Path):
    server_a = TestServer.create(tmp_path)
    server_b = TestServer.create(tmp_path)
    await server_a.start()
    await server_b.start()
    await server_a.connect_to(server_b)
    await server_b.connect_to(server_a)
    await asyncio.sleep(0.5)
    await server_b.stop()
    await asyncio.sleep(0.5)
    assert server_b.runtime.server_id not in server_a.runtime.server_links
    await server_a.stop()


async def test_duplicate_suppression(tmp_path: Path):
    server = TestServer.create(tmp_path)
    await server.start()
    client1 = TestClient()
    client2 = TestClient()
    try:
        await client1.connect(server)
        await client2.connect(server)
        await wait_for_directory(client1, client2.user_id)
        await wait_for_directory(client2, client1.user_id)
        await client1.send_direct_duplicate(client2.user_id, "dupe")
        msg = await client2.recv_direct()
        assert msg == "dupe"
        error_env = await asyncio.wait_for(client1.queue.get(), 1.0)
        assert error_env.type == "ERROR"
    finally:
        await client1.close()
        await client2.close()
        await server.stop()
