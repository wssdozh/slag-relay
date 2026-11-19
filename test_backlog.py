#!/usr/bin/env python3
"""Регрессия: подтверждения не должны ждать, пока релей выкатит весь бэклог.

Узел на медленном линке вычитывает страницу старых бандлов минутами. Пока эта отправка
шла синхронно перед циклом чтения кадров, ACK'и лежали необработанными, релей слал ту же
страницу заново, и курсор не двигался никогда (pet, 8–15 ноября).
"""

import asyncio
import json
import os
import shutil
import socket
import struct
import tempfile
import time
import unittest

from server import SlagRelayServer

ROOM = "room_backlog"
VAULT = "vault_backlog"
ME = "dev_me"
OTHER = "dev_other"
BUNDLE_COUNT = 100
PAYLOAD_BYTES = 40_000


def ws_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    mask = os.urandom(4)
    masked = bytearray(value ^ mask[i % 4] for i, value in enumerate(payload))
    first = 0x80 | opcode
    length = len(payload)
    if length <= 125:
        header = bytearray([first, 0x80 | length]) + mask
    elif length <= 65535:
        header = bytearray([first, 0x80 | 126]) + struct.pack("!H", length) + mask
    else:
        header = bytearray([first, 0x80 | 127]) + struct.pack("!Q", length) + mask
    return bytes(header) + masked


async def read_frame(reader: asyncio.StreamReader) -> dict:
    header = await reader.readexactly(2)
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    return json.loads((await reader.readexactly(length)).decode("utf-8"))


async def open_ws(reader, writer, path: str) -> None:
    writer.write(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                 f"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                 f"Sec-WebSocket-Version: 13\r\n\r\n".encode())
    await writer.drain()
    handshake = await reader.readuntil(b"\r\n\r\n")
    assert b"101" in handshake, handshake


class BacklogAckTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="slag_backlog_")
        self.db_path = os.path.join(self.tmpdir, "backlog.db")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.server = SlagRelayServer("127.0.0.1", self.port, self.db_path, require_account_auth=False)
        self.server_task = asyncio.create_task(self.server.run())
        await asyncio.sleep(0.05)
        blob = "x" * PAYLOAD_BYTES
        for index in range(BUNDLE_COUNT):
            bundle_id = f"bnd_{index:04d}"
            self.server.db.save_bundle(
                ROOM, bundle_id, OTHER, index, str(time.time()),
                json.dumps({"bundleId": bundle_id, "fromDeviceId": OTHER, "sequence": index,
                            "timestamp": str(time.time()), "ciphertext": blob}))

    async def asyncTearDown(self):
        self.server_task.cancel()
        try:
            await self.server_task
        except (asyncio.CancelledError, Exception):
            pass
        self.server.db.conn.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _acked(self, bundle_id: str) -> int:
        return self.server.db.conn.execute(
            "SELECT COUNT(*) FROM bundle_acks WHERE bundle_id = ? AND device_id = ?",
            (bundle_id, ME)).fetchone()[0]

    async def test_ack_lands_while_the_backlog_is_still_streaming(self):
        """Клиент не вычитывает дамп, но ACK уже отправлен — он всё равно должен лечь в базу."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            await open_ws(reader, writer, f"/ws/{ROOM}?device={ME}&vault={VAULT}")
            welcome = await read_frame(reader)
            self.assertEqual(welcome["type"], "welcome")
            # Дальше не читаем: дамп сейчас упрётся в буфер сокета, как пи на медленном линке.
            writer.write(ws_frame(json.dumps({"type": "ack", "bundleId": "bnd_0000"}).encode()))
            await writer.drain()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not self._acked("bnd_0000"):
                await asyncio.sleep(0.05)
            self.assertEqual(self._acked("bnd_0000"), 1,
                             "ACK не записался, пока дамп бэклога блокировал чтение кадров")
        finally:
            writer.close()

    async def test_http_backlog_opt_in_keeps_socket_responsive_without_dumping_bundles(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            await open_ws(reader, writer, f"/ws/{ROOM}?device={ME}&vault={VAULT}&backlog=http")
            self.assertEqual((await read_frame(reader))["type"], "welcome")
            writer.write(ws_frame(json.dumps({"type": "ping"}).encode()))
            await writer.drain()
            self.assertEqual((await asyncio.wait_for(read_frame(reader), timeout=5))["type"], "pong")
        finally:
            writer.close()

    async def test_backlog_is_delivered_and_drains_after_acks(self):
        """Читающий клиент получает всю страницу, а подтверждённое больше не приходит."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            await open_ws(reader, writer, f"/ws/{ROOM}?device={ME}&vault={VAULT}")
            await read_frame(reader)  # welcome
            delivered = []
            for _ in range(BUNDLE_COUNT):
                message = await asyncio.wait_for(read_frame(reader), timeout=10)
                self.assertEqual(message["type"], "bundle")
                delivered.append(message["bundle"]["bundleId"])
                writer.write(ws_frame(json.dumps({"type": "ack", "bundleId": delivered[-1]}).encode()))
                await writer.drain()
            self.assertEqual(len(set(delivered)), BUNDLE_COUNT)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                acked = self.server.db.conn.execute(
                    "SELECT COUNT(*) FROM bundle_acks WHERE device_id = ?", (ME,)).fetchone()[0]
                if acked == BUNDLE_COUNT:
                    break
                await asyncio.sleep(0.05)
            self.assertEqual(acked, BUNDLE_COUNT)
        finally:
            writer.close()

        # Второй коннект: подтверждённое в бэклог больше не попадает.
        self.assertEqual(self.server.db.get_pending_bundles(ROOM, ME, limit=BUNDLE_COUNT), [])


if __name__ == "__main__":
    unittest.main()
