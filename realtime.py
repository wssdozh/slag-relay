"""WebSocket: рукопожатие, кадры, приём бандла и рассылка по комнате."""

import asyncio
import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from typing import Optional

from settings import *
from errors import ApiError
from wire import WebSocketConnection, decode_bundle_frame
from note_protocol import query_revision, receive_note_ops


class Realtime:
    async def handle_ws_upgrade(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                method: str, full_path: str, headers: dict) -> None:
        parsed = urllib.parse.urlsplit(full_path)
        path = parsed.path
        query = {key: values[-1] for key, values in urllib.parse.parse_qs(parsed.query).items()}
        try:
            account_id = vault_id = None
            max_cache = self.db.DEFAULT_MAX_CACHE_BYTES
            device_id = query.get("device", f"device-{secrets.token_hex(4)}")
            room_id = urllib.parse.unquote(path[4:]).strip("/") if path.startswith("/ws/") else ""
            auth = None
            if not room_id:
                raise ApiError(404, "room_not_found")
            room_vault = self.db.room_vault(room_id)
            if self.require_account_auth or query.get("token") or self._bearer(headers) or room_vault:
                token = query.get("token", "") or self._bearer(headers)
                auth = self.db.authenticate(token)
                if not auth:
                    raise ApiError(401, "unauthorized")
                if device_id != auth["device_id"]:
                    raise ApiError(403, "device_mismatch")
                vault_id = query.get("vault", "")
                account_id = self._authorize_room(auth, room_id, vault_id)
                max_cache = PLANS[auth["plan"]]["cache_mb"] * 1024 * 1024

            note_generation = query_revision(query, "noteGeneration")
            folder_tree = query.get("folderTree") == "1"
            self.db.check_legacy_note_generation(room_id, note_generation, folder_tree=folder_tree)
            ws_key = headers.get("sec-websocket-key", "")
            if not ws_key:
                raise ApiError(400, "missing_sec_websocket_key")
            accept = base64.b64encode(hashlib.sha1((ws_key + WS_GUID).encode("utf-8")).digest()).decode("ascii")
            writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode("ascii"))
            await writer.drain()
            conn = WebSocketConnection(reader, writer, room_id, device_id, account_id, max_cache)
            conn.token_hash = auth["token_hash"] if auth else None
            conn.vault_id = vault_id
            conn.note_generation = note_generation
            conn.folder_tree = folder_tree
            self.rooms.setdefault(room_id, set()).add(conn)
            self.db.touch_room(room_id, vault_id)
            logger.info("WebSocket connected")
            await conn.send_text(json.dumps({"type": "welcome", "deviceId": device_id, "roomId": room_id,
                                             "connectedDevices": len(self.rooms[room_id]), "binary": True}))
            # The backlog goes out in the background. Sending it inline blocked the frame loop:
            # a Pi pulling a week of bundles for two minutes could not land a single ACK, so the
            # relay re-delivered the same page forever and the cursor never moved.
            # New clients drain the backlog over paged HTTP; sending it twice chokes slow links.
            dump_task = (None if query.get("backlog") == "http"
                         else asyncio.create_task(self._send_backlog(conn)))
            try:
                while not conn.closed:
                    frame = await conn.read_frame()
                    if frame is None:
                        break
                    opcode, payload = frame
                    if opcode == 0x8:
                        break
                    # Any frame is proof of life: a device that stops sending is a phone whose app
                    # was suspended, and its socket stays open for a long time after that.
                    conn.last_frame_at = time.monotonic()
                    if opcode == 0x1:
                        await self._handle_ws_message(conn, payload.decode("utf-8", errors="replace"))
                    elif opcode == 0x2:
                        await self._handle_ws_binary(conn, payload)
            finally:
                if dump_task is not None:
                    dump_task.cancel()
                if room_id in self.rooms:
                    self.rooms[room_id].discard(conn)
                    if not self.rooms[room_id]:
                        del self.rooms[room_id]
                await conn.close()
                logger.info("WebSocket disconnected")
        except ApiError as exc:
            await self._send_response(writer, self._json_response({"error": exc.error}, exc.status))
        except Exception as exc:
            logger.debug("WS error: %s", type(exc).__name__)
            writer.close()

    async def _send_backlog(self, conn: WebSocketConnection) -> None:
        """Hand over the unacknowledged bundles while the frame loop keeps reading ACKs.

        A page of a week-old backlog is megabytes, and a node on a slow link needs minutes for
        it. That time used to be a black hole for acknowledgements, so nothing ever left the
        pending set. Delivery order stays oldest first: a device that dies halfway has moved
        its confirmed window forward, not restarted.
        """
        try:
            for item in self.db.get_pending_bundles(conn.room_id, conn.device_id):
                if conn.closed:
                    return
                self._check_ws_auth(conn)
                bundle_payload = item["payload"]
                if isinstance(bundle_payload, dict):
                    bundle_payload["syncId"] = item.get("syncId", 0)
                await conn.send_text(json.dumps({"type": "bundle", "bundle": bundle_payload}))
        except asyncio.CancelledError:
            raise
        except ApiError:
            await conn.close()

    def _check_ws_auth(self, conn: WebSocketConnection, write: bool = False) -> None:
        self.db.check_legacy_note_generation(conn.room_id, getattr(conn, 'note_generation', None), write=write,
                                             folder_tree=getattr(conn, 'folder_tree', False))
        if conn.token_hash:
            auth = self.db.authenticate_hash(conn.token_hash)
            if not auth:
                raise ApiError(401, "unauthorized")
            self._authorize_room(auth, conn.room_id, conn.vault_id)
            self._authorize_vault(auth, conn.vault_id, write=write)
            conn.max_cache_bytes = PLANS[auth["plan"]]["cache_mb"] * 1024 * 1024
        else:
            if self.require_account_auth or self.db.room_vault(conn.room_id):
                raise ApiError(401, "unauthorized")

    async def _handle_ws_message(self, conn: WebSocketConnection, text: str) -> None:
        try:
            msg = json.loads(text)
            if not isinstance(msg, dict):
                return
            self._check_ws_auth(conn, write=msg.get("type") in ("bundle", "note_ops"))
            await self._process_ws_message(conn, msg)
        except ApiError as exc:
            await conn.send_text(json.dumps({"type": "error", "code": exc.error}))
        except (ValueError, TypeError):
            await conn.send_text(json.dumps({"type": "error", "code": "invalid_message"}))

    async def _process_ws_message(self, conn: WebSocketConnection, msg: dict) -> None:
        msg_type = msg.get("type")
        if msg_type == "ping":
            await conn.send_text(json.dumps({"type": "pong", "ts": int(time.time())}))
            return
        if msg_type == "assistant_probe_ack":
            # The chosen-one election: latency, plus whether this device could even run a model.
            probe_id = msg.get("id")
            probe = self.assistant_probes.get(probe_id) if isinstance(probe_id, str) else None
            if not probe:
                return
            sent_at = probe["sent"].get(conn.device_id)
            if sent_at is None:
                return
            probe["results"][conn.device_id] = (
                int((time.monotonic() - sent_at) * 1000), msg.get("aiReady") is True)
            # Everyone spoke, or the quiet ones will be timed out by the caller.
            if len(probe["results"]) >= len(probe["sent"]):
                probe["event"].set()
            return
        if msg_type == "assistant_stage":
            await self._handle_assistant_stage(conn, msg)
            return
        if msg_type == "ack":
            bundle_ids = msg.get("bundleIds") or ([msg.get("bundleId")] if msg.get("bundleId") else [])
            if bundle_ids:
                recorded = self.db.record_acks(conn.device_id, bundle_ids, conn.room_id)
                if recorded < len(bundle_ids):
                    # A bundle that ran out of TTL can never be acknowledged; it is re-sent until
                    # the cleaner drops the row. Silence here is how that looked like a lost ACK.
                    logger.debug("ACK partial device=%s recorded=%s of=%s",
                                 conn.device_id, recorded, len(bundle_ids))
            return
        if msg_type == "note_ops":
            if not conn.account_id or not getattr(conn, 'note_generation', None):
                raise ApiError(409, "note_upgrade_required")
            result = await receive_note_ops(self, msg, conn.room_id, conn.device_id, conn.account_id,
                                            conn.max_cache_bytes, conn.note_generation,
                                            folder_tree=getattr(conn, 'folder_tree', False))
            await conn.send_text(json.dumps(result, separators=(",", ":")))
            return
        if msg_type == "bundle":
            bundle = msg.get("bundle", {})
            if not isinstance(bundle, dict):
                return
            await self._ingest_ws_bundle(conn, bundle)

    async def _handle_ws_binary(self, conn: WebSocketConnection, data: bytes) -> None:
        try:
            bundle = decode_bundle_frame(data, conn.device_id)
        except ValueError:
            await conn.send_text(json.dumps({"type": "error", "code": "invalid_frame"}))
            return
        try:
            self._check_ws_auth(conn, write=True)
            await self._ingest_ws_bundle(conn, bundle)
        except ApiError as exc:
            await conn.send_text(json.dumps({"type": "error", "code": exc.error}))

    async def _ingest_ws_bundle(self, conn: WebSocketConnection, bundle: dict) -> None:
        bundle_id = bundle.get("bundleId", secrets.token_hex(12))
        from_device = bundle.get("fromDeviceId", conn.device_id)
        if conn.account_id and from_device != conn.device_id:
            await conn.send_text(json.dumps({"type": "error", "code": "device_mismatch"}))
            return
        seq = int(bundle.get("sequence", 0))
        timestamp = bundle.get("timestamp", str(time.time()))
        payload_str = json.dumps(bundle)
        vault_id = self.db.room_vault(conn.room_id)
        saved = self.db.save_bundle(conn.room_id, bundle_id, from_device, seq, timestamp, payload_str,
                                    max_cache_bytes=conn.max_cache_bytes, account_id=conn.account_id, vault_id=vault_id,
                                     note_generation=getattr(conn, 'note_generation', None),
                                    folder_tree=getattr(conn, 'folder_tree', False))
        if not saved:
            await conn.send_text(json.dumps({"type": "error", "code": "cache_limit_exceeded"}))
            return
        sync_id = saved
        bundle_to_broadcast = dict(bundle)
        bundle_to_broadcast["syncId"] = sync_id
        await self._broadcast_to_room(conn.room_id, json.dumps({"type": "bundle", "bundle": bundle_to_broadcast}), exclude_device=conn.device_id)
        await conn.send_text(json.dumps({"type": "server_ack", "bundleId": bundle_id, "sequence": seq, "syncId": sync_id}))

    async def _broadcast_to_room(self, room_id: str, message_str: str, exclude_device: Optional[str] = None) -> None:
        for client in list(self.rooms.get(room_id, set())):
            if exclude_device and client.device_id == exclude_device:
                continue
            try:
                self._check_ws_auth(client)
            except ApiError:
                await client.close()
                continue
            await client.send_text(message_str)
