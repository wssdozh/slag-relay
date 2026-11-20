"""Бандлы: приём, водарки, выдача недоставленного, подтверждения."""

from __future__ import annotations

import sqlite3
import json
from errors import ApiError
import time
from typing import Optional

from settings import *
from store.base import MAX_CACHE_BYTES


# How many ids go into one IN (...) lookup while materialising a page. Stays under sqlite's
# traditional 999-variable ceiling even when a client asks for the maximum 1000 bundles.
_BUNDLE_PAGE_CHUNK = 400


def _pending_bundle_filter(room_id: str, device_id: str, since_sync_id: int, now: float) -> tuple[str, tuple, str]:
    """WHERE and ORDER shared by the size scan and the row fetch of one pending page.

    Two delivery modes live here: an explicit sync cursor (`since_sync_id > 0`) and the
    legacy per-device ack set. Both must page through the very same filter, otherwise the
    byte budget would spend itself on rows the client was never going to receive.
    """
    if since_sync_id > 0:
        where = ("b.room_id = ? AND b.from_device_id != ? AND COALESCE(b.sync_id, 0) > ? "
                 "AND b.expires_at > ?")
        return where, (room_id, device_id, since_sync_id, now), "b.sync_id ASC, b.created_at ASC"
    where = ("b.room_id = ? AND b.from_device_id != ? "
             "AND b.bundle_id NOT IN (SELECT bundle_id FROM bundle_acks WHERE device_id = ?) "
             "AND b.expires_at > ?")
    return where, (room_id, device_id, device_id, now), "b.created_at ASC"


class BundlesMixin:
    def save_bundle(self, room_id: str, bundle_id: str, from_device: str, seq: int, ts: str,
                    payload_json: str, ttl: int = DEFAULT_TTL_SECONDS,
                    max_cache_bytes: int = MAX_CACHE_BYTES, account_id: Optional[str] = None,
                    vault_id: Optional[str] = None, note_generation: Optional[int] = None,
                    folder_tree: bool = False) -> int | bool:
        if not isinstance(bundle_id, str) or not bundle_id or len(bundle_id) > 256:
            raise ApiError(400, "invalid_bundle_id")
        payload_len = len(payload_json.encode("utf-8"))
        now = time.time()
        with self._note_transaction(write=True):
            self.check_legacy_note_generation(room_id, note_generation, write=True, folder_tree=folder_tree)
            room = self.conn.execute("SELECT vault_id, retired FROM rooms WHERE room_id = ?", (room_id,)).fetchone()
            if room and (room["vault_id"] != vault_id or room["retired"]):
                raise ApiError(403, "room_binding_conflict")
            receipt = self.conn.execute("SELECT room_id FROM bundle_receipts WHERE bundle_id = ?", (bundle_id,)).fetchone()
            if receipt:
                # A legacy receipt can confirm delivery only in the room that accepted it.
                raise ApiError(409, "bundle_replay" if receipt["room_id"] == room_id else "bundle_id_conflict")
            current_cache = self.get_account_cache_bytes(account_id) if account_id else self.get_room_cache_bytes(room_id)
            if current_cache + payload_len > max_cache_bytes:
                logger.warning("Cache limit exceeded")
                return False
            self._touch_room(room_id, vault_id, now)
            max_row = self.conn.execute("SELECT COALESCE(MAX(sync_id), 0) AS max_id FROM bundles WHERE room_id = ?", (room_id,)).fetchone()
            sync_id = int(max_row["max_id"]) + 1
            self.conn.execute("""
                INSERT INTO bundles
                (bundle_id, room_id, from_device_id, sequence, timestamp, payload, created_at, expires_at, sync_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (bundle_id, room_id, from_device, seq, ts, payload_json, now, now + ttl, sync_id))
            self.conn.execute("INSERT INTO bundle_receipts VALUES (?, ?, ?)", (bundle_id, room_id, now))
        return sync_id

    def get_room_watermarks(self, room_id: str) -> dict:
        row = self.conn.execute("""
            SELECT COALESCE(MAX(sync_id), 0) AS head,
                   COALESCE(MIN(sync_id), 0) AS oldest
            FROM bundles WHERE room_id = ? AND expires_at > ?
        """, (room_id, time.time())).fetchone()
        return {"head": int(row["head"]), "oldest": int(row["oldest"])}

    def get_pending_bundles_page(self, room_id: str, device_id: str, limit: int = 100,
                                 since_sync_id: int = 0,
                                 max_bytes: Optional[int] = None) -> tuple[list[dict], int]:
        """One delivery page plus the payload bytes it carries.

        `limit` still caps the bundle count; `max_bytes` caps the payload total, because one
        bundle may carry a whole attachment and a count-only page can grow to hundreds of
        megabytes. The budget bends for the first bundle: it is taken even when it alone
        exceeds the budget, otherwise the client's cursor would never move past it.
        `max_bytes=None` means "count only", i.e. exactly the behaviour this method had
        before the budget existed.
        """
        now = time.time()
        where, params, order = _pending_bundle_filter(room_id, device_id, since_sync_id, now)
        # Light pass: sizes without payloads, so rows that will not fit never cross the
        # sqlite boundary and never allocate their megabytes.
        sized = self.conn.execute(
            f"SELECT b.bundle_id, COALESCE(LENGTH(CAST(b.payload AS BLOB)), 0) AS size "
            f"FROM bundles b WHERE {where} ORDER BY {order} LIMIT ?",
            (*params, limit)).fetchall()
        chosen: list[str] = []
        budget = 0
        for row in sized:
            size = int(row["size"])
            if max_bytes is not None and chosen and budget + size > max_bytes:
                break
            chosen.append(row["bundle_id"])
            budget += size
        if not chosen:
            return [], 0
        # One full fetch by id (chunked), then back into delivery order.
        rows_by_id: dict[str, sqlite3.Row] = {}
        for start in range(0, len(chosen), _BUNDLE_PAGE_CHUNK):
            chunk = chosen[start:start + _BUNDLE_PAGE_CHUNK]
            placeholders = ",".join("?" for _ in chunk)
            for row in self.conn.execute(
                    f"SELECT b.bundle_id, b.room_id, b.from_device_id, b.sequence, b.timestamp, "
                    f"b.payload, COALESCE(b.sync_id, 0) AS sync_id, "
                    f"COALESCE(LENGTH(CAST(b.payload AS BLOB)), 0) AS size "
                    f"FROM bundles b WHERE b.bundle_id IN ({placeholders})", chunk):
                rows_by_id[row["bundle_id"]] = row
        rows = [rows_by_id[bundle_id] for bundle_id in chosen if bundle_id in rows_by_id]
        return [{
            "bundleId": row["bundle_id"], "roomId": row["room_id"],
            "fromDeviceId": row["from_device_id"], "sequence": row["sequence"],
            "timestamp": row["timestamp"], "syncId": row["sync_id"],
            "payload": json.loads(row["payload"])
        } for row in rows], sum(int(row["size"]) for row in rows)

    def get_pending_bundles(self, room_id: str, device_id: str, limit: int = 100,
                            since_sync_id: int = 0, max_bytes: Optional[int] = None) -> list[dict]:
        """Plain-list view of `get_pending_bundles_page`, kept for existing callers."""
        return self.get_pending_bundles_page(room_id, device_id, limit, since_sync_id, max_bytes)[0]

    def record_acks(self, device_id: str, bundle_ids: list[str], room_id: str) -> int:
        if not isinstance(bundle_ids, list) or not all(isinstance(item, str) for item in bundle_ids):
            raise ApiError(400, "invalid_bundle_ids")
        count = 0
        with self.conn:
            for bundle_id in bundle_ids:
                res = self.conn.execute("""INSERT OR IGNORE INTO bundle_acks (bundle_id, device_id, acked_at)
                    SELECT bundle_id, ?, ? FROM bundles WHERE bundle_id = ? AND room_id = ?
                    AND from_device_id != ? AND expires_at > ?""",
                    (device_id, time.time(), bundle_id, room_id, device_id, time.time()))
                count += int(res.rowcount > 0)
        return count
