"""Authoritative encrypted note heads and the retained ordered feed."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import re
import time

from errors import ApiError
from settings import DEFAULT_TTL_SECONDS

PAGE_COUNT = 100
PAGE_BYTES = 2_000_000
MAX_BYTES = 12_000_000
MAX_INT = 9007199254740991
NOTE_ID = re.compile(r"[a-f0-9]{64}\Z")
OP_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
KINDS = ("create", "update", "delete", "restore")
# Include fixed metadata, the head pointer, and the receipt for quota purposes.
VERSION_OVERHEAD = 256
RECEIPT_BYTES = 256


def _valid_id(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _valid_int(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_INT


def _decode(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ApiError(400, "invalid_note_seal") from None


def validate_note_ops(ops):
    if not isinstance(ops, list) or not 0 < len(ops) <= PAGE_COUNT:
        raise ApiError(400, "invalid_note_batch")
    validated = []
    seen = set()
    size = 0
    for raw in ops:
        if not isinstance(raw, dict):
            raise ApiError(400, "invalid_note_op")
        op_id, note_id = raw.get("opId"), raw.get("noteId")
        kind, base = raw.get("kind"), raw.get("baseRevision")
        if (not _valid_id(op_id, OP_ID) or not _valid_id(note_id, NOTE_ID)
                or kind not in KINDS or not _valid_int(base) or op_id in seen):
            raise ApiError(400, "invalid_note_op")
        seen.add(op_id)
        sealed = raw.get("sealed")
        if not isinstance(sealed, dict):
            raise ApiError(400, "invalid_note_seal")
        iv, ciphertext = sealed.get("iv"), sealed.get("ciphertext")
        if (not isinstance(iv, str) or len(iv) != 16 or len(_decode(iv)) != 12
                or not isinstance(ciphertext, str) or not 24 <= len(ciphertext) <= MAX_BYTES
                or len(_decode(ciphertext)) < 16):
            raise ApiError(400, "invalid_note_seal")
        op = {"opId": op_id, "noteId": note_id, "baseRevision": base, "kind": kind,
              "sealed": {"iv": iv, "ciphertext": ciphertext}}
        body = json.dumps(op, separators=(",", ":")).encode("ascii")
        size += len(body)
        if len(ops) > 1 and size > PAGE_BYTES:
            raise ApiError(413, "note_batch_too_large")
        validated.append((op, hashlib.sha256(body).digest(), len(body) + VERSION_OVERHEAD))
    return validated


def _wire(row):
    return {"opId": row["op_id"], "noteId": row["note_id"], "baseRevision": row["base_revision"],
            "kind": row["kind"], "revision": row["revision"],
            "sealed": {"iv": row["iv"], "ciphertext": row["ciphertext"]}}


class NoteRegistryMixin:
    @contextmanager
    def _note_transaction(self, write=False):
        if write:
            # The registry is not an expiring cache: acknowledge only a durable WAL commit.
            self.conn.execute("PRAGMA synchronous=FULL")
        try:
            with self.conn:
                self.conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield
        finally:
            if write:
                self.conn.execute("PRAGMA synchronous=NORMAL")

    def note_status(self, room_id):
        row = self.conn.execute("SELECT mode, generation, head, floor FROM note_rooms WHERE room_id = ?",
                                (room_id,)).fetchone()
        return dict(row) if row else {"mode": "legacy", "generation": 0, "head": 0, "floor": 0}

    def check_legacy_note_generation(self, room_id, generation, *, write=False):
        status = self.note_status(room_id)
        if status["mode"] == "frozen" and write:
            raise ApiError(409, "note_room_frozen")
        if status["mode"] == "registry" and generation != status["generation"]:
            raise ApiError(409, "note_upgrade_required")

    def _require_note_registry(self, room_id, generation):
        status = self.note_status(room_id)
        if status["mode"] == "frozen":
            raise ApiError(409, "note_room_frozen")
        if status["mode"] != "registry" or status["generation"] != generation:
            raise ApiError(409, "note_upgrade_required")
        return status

    def freeze_note_room(self, room_id):
        """Local operator entry. An already active room must not revert to legacy."""
        with self._note_transaction(write=True):
            room = self.conn.execute("SELECT vault_id, retired FROM rooms WHERE room_id = ?", (room_id,)).fetchone()
            if not room or not room["vault_id"] or room["retired"]:
                raise ApiError(409, "note_room_not_bound")
            self.conn.execute("""INSERT INTO note_rooms (room_id, mode, generation) VALUES (?, 'frozen', 1)
                ON CONFLICT (room_id) DO UPDATE SET mode = 'frozen', generation = note_rooms.generation + 1
                WHERE note_rooms.mode = 'legacy'""", (room_id,))
            status = self.note_status(room_id)
            if status["mode"] != "frozen":
                raise ApiError(409, "note_registry_active")
            return status["generation"]

    def thaw_note_room(self, room_id, generation):
        """Cancel a prepare before activation. Advance generation to invalidate stale seeds."""
        with self._note_transaction(write=True):
            status = self.note_status(room_id)
            if status["mode"] != "frozen" or status["generation"] != generation:
                raise ApiError(409, "note_prepare_changed")
            self.conn.execute("UPDATE note_rooms SET mode = 'legacy' WHERE room_id = ?", (room_id,))

    def activate_note_room(self, room_id, generation, ops, owner_account_id, max_cache_bytes):
        """Local operator entry. Ciphertexts are prepared for this exact generation."""
        with self._note_transaction(write=True):
            status = self.note_status(room_id)
            if status["mode"] != "frozen" or status["generation"] != generation:
                raise ApiError(409, "note_prepare_changed")
            owner = self.conn.execute("""SELECT v.owner_account_id FROM rooms r
                JOIN vaults v ON v.id = r.vault_id WHERE r.room_id = ? AND NOT r.retired""", (room_id,)).fetchone()
            if not owner or owner["owner_account_id"] != owner_account_id:
                raise ApiError(403, "note_room_owner_mismatch")
            used = self.get_account_cache_bytes(owner_account_id)
            revision = 0
            ids = set()
            seen_ops = set()
            bootstrap_bytes = 0
            for raw in ops:
                op, digest, length = validate_note_ops([raw])[0]
                if (op["baseRevision"] != 0 or op["kind"] not in ("create", "delete")
                        or op["noteId"] in ids or op["opId"] in seen_ops):
                    raise ApiError(400, "invalid_note_seed")
                ids.add(op["noteId"])
                seen_ops.add(op["opId"])
                bootstrap_bytes += length + RECEIPT_BYTES
                if used + bootstrap_bytes > max_cache_bytes:
                    raise ApiError(413, "cache_limit_exceeded")
                revision += 1
                self._store_note_version(room_id, revision, "bootstrap", op, digest, length)
            # Initial state is obtained by scanning heads; it is not duplicated into an old feed.
            self.conn.execute("""UPDATE note_rooms SET mode = 'registry', head = ?, floor = ?, bytes = ?
                WHERE room_id = ?""", (revision, revision, bootstrap_bytes, room_id))
            return self.note_status(room_id)

    def _store_note_version(self, room_id, revision, sender_id, op, digest, length):
        self.conn.execute("INSERT INTO note_versions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (room_id, revision, op["noteId"], op["opId"], op["kind"], op["baseRevision"],
                           op["sealed"]["iv"], op["sealed"]["ciphertext"], length, time.time() + DEFAULT_TTL_SECONDS))
        self.conn.execute("""INSERT INTO note_heads VALUES (?, ?, ?)
            ON CONFLICT (room_id, note_id) DO UPDATE SET revision = excluded.revision""", (room_id, op["noteId"], revision))
        self.conn.execute("INSERT INTO note_receipts VALUES (?, ?, ?, ?, ?)",
                          (room_id, op["opId"], sender_id, digest, revision))

    def commit_note_ops(self, room_id, generation, sender_id, owner_account_id, max_cache_bytes, ops):
        validated = validate_note_ops(ops)
        results, events = [], []
        with self._note_transaction(write=True):
            status = self._require_note_registry(room_id, generation)
            head = status["head"]
            used = self.get_account_cache_bytes(owner_account_id)
            written_bytes = 0
            for op, digest, length in validated:
                op_id, note_id = op["opId"], op["noteId"]
                receipt = self.conn.execute("""SELECT revision, sender_id, digest FROM note_receipts
                    WHERE room_id = ? AND op_id = ?""", (room_id, op_id)).fetchone()
                if receipt:
                    result = ({"status": "accepted", "revision": receipt["revision"]}
                              if receipt["sender_id"] == sender_id and receipt["digest"] == digest
                              else {"status": "rejected", "code": "note_op_id_reused"})
                else:
                    current = self.conn.execute("""SELECT v.revision, v.kind FROM note_heads h
                        JOIN note_versions v ON v.room_id = h.room_id AND v.revision = h.revision
                        WHERE h.room_id = ? AND h.note_id = ?""", (room_id, note_id)).fetchone()
                    revision = current["revision"] if current else 0
                    kind = op["kind"]
                    if revision != op["baseRevision"]:
                        result = {"status": "stale", "current": self._note_version(room_id, revision) if current else None}
                    elif ((kind == "create" and not current)
                          or (kind == "restore" and current and current["kind"] == "delete")
                          or (kind in ("update", "delete") and current and current["kind"] != "delete")):
                        cost = length + RECEIPT_BYTES
                        if used + written_bytes + cost > max_cache_bytes:
                            result = {"status": "rejected", "code": "cache_limit_exceeded"}
                        else:
                            head += 1
                            written_bytes += cost
                            self._store_note_version(room_id, head, sender_id, op, digest, length)
                            events.append({**op, "revision": head})
                            result = {"status": "accepted", "revision": head}
                    else:
                        result = {"status": "rejected", "code": "invalid_note_transition"}
                results.append({"opId": op_id, **result})
            if events:
                self.conn.execute("UPDATE note_rooms SET head = ?, bytes = bytes + ? WHERE room_id = ?",
                                  (head, written_bytes, room_id))
        return results, events

    def _note_version(self, room_id, revision):
        row = self.conn.execute("SELECT * FROM note_versions WHERE room_id = ? AND revision = ?",
                                (room_id, revision)).fetchone()
        return _wire(row)

    def _note_page(self, room_id, candidates, budget):
        page = []
        size = 0
        for row in candidates:
            if len(page) == PAGE_COUNT or (page and size + row["bytes"] > budget):
                return page, True
            size += row["bytes"]
            page.append(self._note_version(room_id, row["revision"]))
        return page, False

    def note_events(self, room_id, generation, since, budget):
        with self._note_transaction():
            status = self._require_note_registry(room_id, generation)
            candidates = self.conn.execute("""SELECT revision, bytes FROM note_versions
                WHERE room_id = ? AND revision > ? ORDER BY revision LIMIT ?""",
                (room_id, max(since, status["floor"]), PAGE_COUNT + 1)).fetchall()
            events, _ = self._note_page(room_id, candidates, budget)
            return {"generation": generation, "head": status["head"], "floor": status["floor"], "events": events}

    def note_heads(self, room_id, generation, after, since, through, budget):
        with self._note_transaction():
            status = self._require_note_registry(room_id, generation)
            candidates = self.conn.execute("""SELECT v.revision, v.bytes FROM note_heads h
                JOIN note_versions v ON v.room_id = h.room_id AND v.revision = h.revision
                WHERE h.room_id = ? AND h.note_id > ? AND h.revision > ? AND h.revision <= ?
                ORDER BY h.note_id LIMIT ?""", (room_id, after, since, through, PAGE_COUNT + 1)).fetchall()
            heads, more = self._note_page(room_id, candidates, budget)
            return {"generation": generation, "head": status["head"], "floor": status["floor"],
                    "heads": heads, "next": heads[-1]["noteId"] if more else None}

    def cleanup_note_versions(self, now):
        """Called in cleanup transaction; expiry is a prefix even if wall time moves."""
        rooms = self.conn.execute("SELECT room_id, floor, head FROM note_rooms WHERE mode = 'registry'").fetchall()
        for room in rooms:
            room_id, floor = room["room_id"], room["floor"]
            live = self.conn.execute("""SELECT MIN(revision) FROM note_versions
                WHERE room_id = ? AND revision > ? AND expires_at > ?""", (room_id, floor, now)).fetchone()[0]
            floor = room["head"] if live is None else live - 1
            params = (room_id, floor)
            where = """room_id = ? AND revision <= ? AND revision NOT IN
                (SELECT revision FROM note_heads WHERE room_id = note_versions.room_id)"""
            released = self.conn.execute("SELECT COALESCE(SUM(bytes), 0) FROM note_versions WHERE " + where,
                                         params).fetchone()[0]
            if released:
                self.conn.execute("DELETE FROM note_versions WHERE " + where, params)
            self.conn.execute("UPDATE note_rooms SET floor = ?, bytes = bytes - ? WHERE room_id = ?",
                              (floor, released, room_id))
