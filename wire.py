"""RFC 6455 на минималках и бинарный кадр бандла: один сокет, без фреймворка."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import struct
import time
from typing import Optional, Tuple

from settings import *


def decode_bundle_frame(data: bytes, device_id: str) -> dict:
    """Binary push frame: [0x01][version:1][idLen:1][bundleId][sequence:4 BE][iv:12][ciphertext].

    Clients send it on the websocket instead of a base64 JSON envelope: the uplink is the
    slow half of mobile sync, and base64 costs a third of every small bundle.
    """
    if len(data) < 3 or data[0] != BUNDLE_FRAME_BUNDLE or data[1] != BUNDLE_FRAME_VERSION:
        raise ValueError("unsupported bundle frame")
    id_len = data[2]
    header_end = 3 + id_len + 4 + 12
    if not id_len or len(data) <= header_end:
        raise ValueError("truncated bundle frame")
    bundle_id = data[3:3 + id_len].decode("utf-8", errors="replace")
    if not bundle_id:
        raise ValueError("empty bundle id")
    sequence = struct.unpack("!I", data[3 + id_len:7 + id_len])[0]
    iv = data[7 + id_len:19 + id_len]
    ciphertext = data[header_end:]
    return {
        "bundleId": bundle_id,
        "fromDeviceId": device_id,
        "sequence": sequence,
        "timestamp": str(time.time()),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


class WebSocketConnection:
    """Minimal RFC 6455 WebSocket handler over asyncio streams."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, room_id: str, device_id: str,
                 account_id: Optional[str] = None, max_cache_bytes: int = 1024 * 1024 * 1024):
        self.reader = reader
        self.writer = writer
        self.room_id = room_id
        self.device_id = device_id
        self.account_id = account_id
        self.max_cache_bytes = max_cache_bytes
        self.closed = False
        self.token_hash = None
        self.vault_id = None
        # The backlog dump and the frame loop write to this socket from two places now, so a
        # frame is written whole or not at all: halves of two frames used to interleave.
        self.send_lock = asyncio.Lock()
        # Last time this socket said anything at all. The handshake counts: a device that just
        # connected is alive even before its first ping.
        self.last_frame_at = time.monotonic()

    @staticmethod
    def _text_frame(text: str) -> bytes:
        payload = text.encode("utf-8")
        length = len(payload)
        header = bytearray([0x81])
        if length <= 125:
            header.append(length)
        elif length <= 65535:
            header.append(126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(127)
            header.extend(struct.pack("!Q", length))
        return bytes(header) + payload

    async def send_text(self, text: str) -> None:
        await self.send_raw(self._text_frame(text))

    async def send_raw(self, frame: bytes) -> None:
        """One frame per lock hold: a slow reader blocks its own writer, not the reader loop."""
        if self.closed:
            return
        async with self.send_lock:
            if self.closed:
                return
            try:
                self.writer.write(frame)
                await self.writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                self.closed = True

    async def read_frame(self) -> Optional[Tuple[int, bytes]]:
        # The browser may split one send() across data frames. Dispatch only the completed
        # message and keep the original byte limit across all of its continuation frames.
        message_opcode = None
        message = bytearray()
        try:
            while True:
                byte1, byte2 = await self.reader.readexactly(2)
                opcode = byte1 & 0x0F
                final = bool(byte1 & 0x80)
                length = byte2 & 0x7F
                if byte1 & 0x70 or not byte2 & 0x80 or opcode not in (0, 1, 2, 8, 9, 10):
                    return None
                control = opcode >= 8
                if control:
                    if not final or length > 125 or (opcode == 8 and length == 1):
                        return None
                else:
                    if (opcode == 0) != (message_opcode is not None):
                        return None
                    if length == 126:
                        length = struct.unpack("!H", await self.reader.readexactly(2))[0]
                        if length < 126:
                            return None
                    elif length == 127:
                        length = struct.unpack("!Q", await self.reader.readexactly(8))[0]
                        if length <= 65535:
                            return None
                    if len(message) + length > 16 * 1024 * 1024:
                        return None
                mask = await self.reader.readexactly(4)
                payload = bytearray(await self.reader.readexactly(length))
                for i in range(length):
                    payload[i] ^= mask[i % 4]
                if opcode == 8:
                    return opcode, b""
                if opcode == 9:
                    # Same lock as the backlog dump: a pong cannot interleave with a message.
                    await self.send_raw(bytes([0x8A, length]) + payload)
                if control:
                    self.last_frame_at = time.monotonic()
                    continue
                if message_opcode is None and final:
                    return opcode, bytes(payload)
                if message_opcode is None:
                    message_opcode = opcode
                message.extend(payload)
                if final:
                    return message_opcode, bytes(message)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return None

    async def close(self) -> None:
        if self.closed:
            return
        # No send lock and no drain: a reader that stopped reading would hold the lock forever,
        # and the peer is going away anyway — a truncated frame behind a close is fine.
        self.closed = True
        try:
            self.writer.write(bytes([0x88, 0x00]))
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
