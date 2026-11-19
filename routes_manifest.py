"""Манифест комнаты: запись и чтение по sync id.

Следует тем же паттерну авторизации, что и `routes_vaults`: если включён account auth
или есть bearer-токен (или комната привязана к vault), требуем _auth; затем проверяем
права через _authorize_room (+ write=True для POST). Ответы — ApiError как везде.

sync_id: независимый автоинкремент COALESCE(MAX(sync_id), 0)+1 в room_manifests.
Отдельный от bundle.sync_id, но той же монотонной природы.
"""

import json
import time
import urllib.parse
from typing import Optional

from errors import ApiError
from router import _NEXT


class ManifestRoutes:
    async def _route_manifest(self, method: str, path: str, query: dict, body: dict,
                              headers: dict, writer):
        parts = path.strip("/").split("/")
        # /api/rooms/{room}/manifest
        if len(parts) == 4 and parts[3] == "manifest" and parts[2]:
            room_id = urllib.parse.unquote(parts[2])
            vault_id = query.get("vault", "")

            if not vault_id:
                raise ApiError(400, "missing_vault")

            # --- auth decision (same as bundle routes) ---
            auth = None
            owner_account_id = None
            if self.require_account_auth or self._bearer(headers):
                auth = self._auth(headers)
                if auth:
                    owner_account_id = self._authorize_room(auth, room_id, vault_id)

            if method == "POST":
                return await self._handle_post_manifest(room_id, vault_id, owner_account_id, body, auth)

            if method == "GET":
                since = query.get("since", "0")
                try:
                    since_val = int(since)
                except (ValueError, TypeError):
                    since_val = 0
                return await self._handle_get_manifest(room_id, vault_id, since_val, writer)

        return _NEXT

    async def _handle_post_manifest(self, room_id: str, vault_id: str,
                                    owner_account_id: Optional[str],
                                    body: dict, auth: Optional[dict]) -> tuple:
        """POST /api/rooms/{room}/manifest — upsert манифеста."""
        if auth:
            self._authorize_vault(auth, vault_id, write=True)

        if not isinstance(body, dict):
            raise ApiError(400, "invalid_manifest_body")

        raw = json.dumps(body).encode("utf-8")
        if len(raw) > 128 * 1024:
            raise ApiError(413, "payload_too_large")

        version = body.get("v")
        if version != 1:
            raise ApiError(409, "unsupported_version")

        root = body.get("root")
        if not isinstance(root, str) or not root:
            raise ApiError(400, "invalid_manifest_root")

        folders_raw = body.get("folders", {})
        if not isinstance(folders_raw, dict):
            raise ApiError(400, "invalid_manifest_folders")

        # Clean: keep only string-key → string-value entries.
        folders = {k: v for k, v in folders_raw.items()
                   if isinstance(k, str) and isinstance(v, str)}

        manifest_body = json.dumps({"v": 1, "root": root, "folders": folders})

        with self.db.conn:
            max_row = self.db.conn.execute(
                "SELECT COALESCE(MAX(sync_id), 0) AS mx FROM room_manifests WHERE room_id = ?",
                (room_id,),
            ).fetchone()
            new_sync_id = int(max_row["mx"]) + 1
            now = time.time()
            self.db.conn.execute("""
                INSERT INTO room_manifests (room_id, sync_id, body, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(room_id) DO UPDATE SET
                    sync_id = excluded.sync_id,
                    body = excluded.body,
                    updated_at = excluded.updated_at
            """, (room_id, new_sync_id, manifest_body, now))

        return {"syncId": new_sync_id}, 200

    async def _handle_get_manifest(self, room_id: str, vault_id: str,
                                   since: int, writer) -> Optional[tuple]:
        """GET /api/rooms/{room}/manifest?since=N.

        204 отправляем напрямую через _send_response(writer, ...), так как рутер не
        умеет кортежи с заголовками, а json.dumps(None) ≠ пустое тело.
        """
        row = self.db.conn.execute(
            "SELECT sync_id, body FROM room_manifests WHERE room_id = ?",
            (room_id,),
        ).fetchone()
        if not row:
            raise ApiError(404, "manifest_not_found")

        if since >= row["sync_id"]:
            await self._send_response(writer, self._http_response(
                204, "No Content", "application/json", b""))
            return None

        parsed = json.loads(row["body"])
        result = {"v": parsed["v"], "root": parsed["root"],
                  "folders": parsed["folders"], "syncId": row["sync_id"]}
        return result, 200
