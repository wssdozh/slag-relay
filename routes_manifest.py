"""Манифест комнаты: запись и чтение по sync id.

Следует тем же паттерну авторизации, что и `routes_vaults`: если включён account auth
или есть bearer-токен (или комната привязана к vault), требуем _auth; затем проверяем
права через _authorize_room (+ write=True для POST). Ответы — ApiError как везде.

sync_id: независимый автоинкремент COALESCE(MAX(sync_id), 0)+1 в пределах комнаты.
Отдельный от bundle.sync_id, но той же монотонной природы.

Манифест бывает двух видов, и они не мешают друг другу:

* без `?device=` — одна старая строка на комнату в `room_manifests` (старый клиент);
* с `?device=` — своя строка на устройство в `room_device_manifests`, а GET отдаёт
  корни ЧУЖИХ устройств этой комнаты (плюс legacy-строку как анонимную), чтобы сверка
  корней видела соседа, а не саму себя.
"""

import json
import time
import urllib.parse
from typing import Optional

from errors import ApiError
from router import _NEXT


def _parse_manifest_body(body) -> dict:
    """Валидация и нормализация тела манифеста — общая для обеих таблиц.

    Возвращает `{"v": 1, "root": ..., "folders": {...}}` плюс `leaves`, если прислали
    и они непустые. Старый отправитель листьев не шлёт — тело остаётся прежним.
    """
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

    # Leaves are what lets a client name the divergence instead of shrugging at it: "the
    # neighbour has no note <id>" is the difference between a stale note and a broken replica.
    # Optional — an older sender sends none, and the body then stays exactly as before.
    leaves_raw = body.get("leaves", {})
    if not isinstance(leaves_raw, dict):
        raise ApiError(400, "invalid_manifest_leaves")
    leaves = {k: v for k, v in leaves_raw.items()
              if isinstance(k, str) and isinstance(v, str)}

    stored = {"v": 1, "root": root, "folders": folders}
    if leaves:
        stored["leaves"] = leaves
    return stored


def _manifest_payload(parsed: dict, sync_id: int, updated_at: float, **extra) -> dict:
    """Элемент ответа манифеста: базовые поля плюс leaves, если они были сохранены.

    `at` — когда строку последний раз записали, в миллисекундах: клиент сравнивает его
    с `Date.now()` напрямую и отличает «сосед отверг заметку» от «сосед ещё не
    переопубликовал корень после моей переотправки».
    """
    item = {"root": parsed["root"], "folders": parsed["folders"], "syncId": sync_id,
            "at": int(updated_at * 1000)}
    if "leaves" in parsed:
        item["leaves"] = parsed["leaves"]
    item.update(extra)
    return item


class ManifestRoutes:
    async def _route_manifest(self, method: str, path: str, query: dict, body: dict,
                              headers: dict, writer):
        parts = path.strip("/").split("/")
        # /api/rooms/{room}/manifest
        if len(parts) == 4 and parts[3] == "manifest" and parts[2]:
            room_id = urllib.parse.unquote(parts[2])
            vault_id = query.get("vault", "")
            # Без device — целиком старое поведение: одна строка на комнату.
            device = (query.get("device") or "").strip()

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
                return await self._handle_post_manifest(room_id, vault_id, owner_account_id,
                                                        body, auth, device)

            if method == "GET":
                since = query.get("since", "0")
                try:
                    since_val = int(since)
                except (ValueError, TypeError):
                    since_val = 0
                return await self._handle_get_manifest(room_id, vault_id, since_val, writer,
                                                       device)

        return _NEXT

    async def _handle_post_manifest(self, room_id: str, vault_id: str,
                                    owner_account_id: Optional[str],
                                    body: dict, auth: Optional[dict],
                                    device: str = "") -> tuple:
        """POST /api/rooms/{room}/manifest — upsert манифеста (на устройство или на комнату)."""
        if auth:
            self._authorize_vault(auth, vault_id, write=True)

        stored = _parse_manifest_body(body)
        manifest_body = json.dumps(stored)

        with self.db.conn:
            max_row = self.db.conn.execute(
                "SELECT COALESCE(MAX(sync_id), 0) AS mx FROM {t} WHERE room_id = ?".format(
                    t="room_device_manifests" if device else "room_manifests"),
                (room_id,),
            ).fetchone()
            new_sync_id = int(max_row["mx"]) + 1
            now = time.time()
            if device:
                self.db.conn.execute("""
                    INSERT INTO room_device_manifests
                        (room_id, device_id, sync_id, body, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(room_id, device_id) DO UPDATE SET
                        sync_id = excluded.sync_id,
                        body = excluded.body,
                        updated_at = excluded.updated_at
                """, (room_id, device, new_sync_id, manifest_body, now))
            else:
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
                                   since: int, writer,
                                   device: str = "") -> Optional[tuple]:
        """GET /api/rooms/{room}/manifest?since=N[&device=...].

        Без device — прежний ответ `{v, root, folders, syncId}`. С device — каталог
        чужих манифестов комнаты:
        `{v, manifests: [{deviceId, root, folders, [leaves], syncId, at}], anonymous}`.

        204 отправляем напрямую через _send_response(writer, ...), так как рутер не
        умеет кортежи с заголовками, а json.dumps(None) ≠ пустое тело.
        """
        if device:
            return await self._get_device_manifests(room_id, since, writer, device)

        row = self.db.conn.execute(
            "SELECT sync_id, body, updated_at FROM room_manifests WHERE room_id = ?",
            (room_id,),
        ).fetchone()
        if not row:
            raise ApiError(404, "manifest_not_found")

        if since >= row["sync_id"]:
            await self._send_response(writer, self._http_response(
                204, "No Content", "application/json", b""))
            return None

        parsed = json.loads(row["body"])
        return {"v": parsed["v"],
                **_manifest_payload(parsed, row["sync_id"], row["updated_at"])}, 200

    async def _get_device_manifests(self, room_id: str, since: int, writer,
                                    device: str) -> Optional[tuple]:
        """GET с device: чужие записи комнаты плюс legacy-строка как анонимная.

        Свою запись не отдаём — иначе сверка снова сравнивает себя с собой. Пустая
        комната отвечает пустым каталогом, а не 404: клиент, который только что
        записался, должен отличать «соседей пока нет» от «манифеста нет вообще».
        """
        rows = self.db.conn.execute("""
            SELECT device_id, sync_id, body, updated_at FROM room_device_manifests
            WHERE room_id = ? AND device_id <> ?
            ORDER BY sync_id
        """, (room_id, device)).fetchall()

        legacy = self.db.conn.execute(
            "SELECT sync_id, body, updated_at FROM room_manifests WHERE room_id = ?",
            (room_id,),
        ).fetchone()

        top_sync = max([int(r["sync_id"]) for r in rows] +
                       ([int(legacy["sync_id"])] if legacy else []), default=0)
        if top_sync and since >= top_sync:
            await self._send_response(writer, self._http_response(
                204, "No Content", "application/json", b""))
            return None

        manifests = []
        for r in rows:
            parsed = json.loads(r["body"])
            manifests.append(_manifest_payload(parsed, r["sync_id"], r["updated_at"],
                                               deviceId=r["device_id"]))

        anonymous = None
        if legacy:
            parsed = json.loads(legacy["body"])
            anonymous = {"root": parsed["root"], "folders": parsed["folders"],
                         "syncId": legacy["sync_id"],
                         "at": int(legacy["updated_at"] * 1000)}

        return {"v": 1, "manifests": manifests, "anonymous": anonymous}, 200
