"""Durable encrypted attachment storage for the note registry."""
import base64
import hashlib
import re
import time

from errors import ApiError
from settings import DEFAULT_TTL_SECONDS

MEDIA_OVERHEAD = 256
MEDIA_MAX_BYTES = 6 * 1024 * 1024 + 12 + 16


class NoteMediaMixin:
    def put_note_media(self, room_id, generation, blob_id, body, owner_account_id, max_cache_bytes):
        if not (isinstance(blob_id, str) and re.fullmatch(r"[a-f0-9]{64}", blob_id)) or not isinstance(body, bytes) or len(body) < 28:
            raise ApiError(400, "invalid_note_media")
        if len(body) > MEDIA_MAX_BYTES:
            raise ApiError(413, "note_media_too_large")
        if hashlib.sha256(body).hexdigest() != blob_id:
            raise ApiError(400, "note_media_digest_mismatch")
        with self._note_transaction(write=True):
            status = self._require_note_registry(room_id, generation, True, True, True, True)
            if not status.get("registryMedia"):
                raise ApiError(409, "note_media_not_enabled")
            owner = self.conn.execute("""SELECT v.owner_account_id FROM rooms r JOIN vaults v ON r.vault_id = v.id
                WHERE r.room_id = ? AND NOT r.retired""", (room_id,)).fetchone()
            if not owner or owner["owner_account_id"] != owner_account_id:
                raise ApiError(403, "note_room_owner_mismatch")
            existing = self.conn.execute("SELECT 1 FROM note_media WHERE room_id = ? AND generation = ? AND blob_id = ?",
                                         (room_id, generation, blob_id)).fetchone()
            if existing:
                self.conn.execute("""UPDATE note_media SET orphaned_at = ?
                    WHERE room_id = ? AND generation = ? AND blob_id = ? AND orphaned_at IS NOT NULL""",
                                  (time.time(), room_id, generation, blob_id))
                return
            cost = len(body) + MEDIA_OVERHEAD
            if self.get_account_cache_bytes(owner_account_id) + cost > max_cache_bytes:
                raise ApiError(413, "cache_limit_exceeded")
            self.conn.execute("INSERT INTO note_media (room_id, generation, blob_id, body, orphaned_at) VALUES (?, ?, ?, ?, ?)",
                              (room_id, generation, blob_id, body, time.time()))
            self.conn.execute("UPDATE note_rooms SET bytes = bytes + ? WHERE room_id = ?", (cost, room_id))

    def get_note_media(self, room_id, generation, blob_id):
        if not (isinstance(blob_id, str) and re.fullmatch(r"[a-f0-9]{64}", blob_id)):
            raise ApiError(400, "invalid_note_media")
        with self._note_transaction():
            status = self._require_note_registry(room_id, generation, True, True, True, True)
            if not status.get("registryMedia"):
                raise ApiError(409, "note_media_not_enabled")
            row = self.conn.execute("SELECT body FROM note_media WHERE room_id = ? AND generation = ? AND blob_id = ?",
                                    (room_id, generation, blob_id)).fetchone()
            if row is None:
                raise ApiError(404, "note_media_not_found")
            return row["body"]

    def _seed_note_media(self, room_id, generation, inputs, quota):
        if not isinstance(inputs, list):
            raise ApiError(400, 'invalid_note_media_seed')
        ids = set()
        cost = 0
        for entry in inputs:
            blob_id = entry.get('id') if isinstance(entry, dict) else None
            encoded = entry.get('ciphertext') if isinstance(entry, dict) else None
            if not isinstance(blob_id, str) or blob_id in ids or not isinstance(encoded, str):
                raise ApiError(400, 'invalid_note_media_seed')
            if len(encoded) > 4 * ((MEDIA_MAX_BYTES + 2) // 3):
                raise ApiError(413, 'note_media_too_large')
            try:
                body = base64.b64decode(encoded, validate=True)
            except ValueError:
                raise ApiError(400, 'invalid_note_media_seed') from None
            if not 28 <= len(body) <= MEDIA_MAX_BYTES or hashlib.sha256(body).hexdigest() != blob_id:
                raise ApiError(400, 'invalid_note_media_seed')
            ids.add(blob_id)
            cost += len(body) + MEDIA_OVERHEAD
            if cost > quota:
                raise ApiError(413, 'cache_limit_exceeded')
            self.conn.execute('INSERT INTO note_media (room_id, generation, blob_id, body) VALUES (?, ?, ?, ?)',
                              (room_id, generation, blob_id, body))
        return ids, cost

    def _retain_note_media(self, room_id, ids):
        if ids:
            self.conn.executemany("""UPDATE note_media SET orphaned_at = NULL WHERE room_id = ? AND blob_id = ?
                AND generation = (SELECT generation FROM note_rooms WHERE room_id = ?)""",
                                  ((room_id, blob_id, room_id) for blob_id in ids))

    def cleanup_note_media(self, now):
        """In the version cleanup transaction, keep both current heads and retained feed rows."""
        self.conn.execute("""WITH referenced AS (
                SELECT DISTINCT v.room_id, n.generation, j.value AS blob_id
                FROM note_versions v JOIN note_rooms n USING (room_id), json_each(v.media_ids) j
            )
            UPDATE note_media SET orphaned_at = CASE
                WHEN (room_id, generation, blob_id) IN (SELECT room_id, generation, blob_id FROM referenced) THEN NULL
                ELSE COALESCE(orphaned_at, ?) END""", (now,))
        # RETURNING reports only metadata; loading ciphertext here would make cleanup unbounded in memory.
        released = {}
        for room_id, body_bytes in self.conn.execute("""DELETE FROM note_media WHERE orphaned_at <= ?
                RETURNING room_id, LENGTH(body)""", (now - DEFAULT_TTL_SECONDS,)):
            released[room_id] = released.get(room_id, 0) + body_bytes + MEDIA_OVERHEAD
        self.conn.executemany("UPDATE note_rooms SET bytes = bytes - ? WHERE room_id = ?",
                              ((size, room_id) for room_id, size in released.items()))
