"""Shared HTTP/WS note operations. Authentication is supplied by the surrounding transport."""
import asyncio
import json

from errors import ApiError
from store.note_registry import NOTE_ID, OP_ID, _valid_id, _valid_int


def query_revision(query, key, default=None):
    raw = query.get(key)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (ValueError, TypeError):
        raise ApiError(400, "invalid_note_revision") from None
    if not _valid_int(value):
        raise ApiError(400, "invalid_note_revision")
    return value


def note_after(query):
    value = query.get("after", "")
    if value and not _valid_id(value, NOTE_ID):
        raise ApiError(400, "invalid_note_cursor")
    return value


async def _deliver(client, text):
    try:
        await asyncio.wait_for(client.send_text(text), timeout=1.0)
    except (TimeoutError, OSError):
        # Force catch-up on reconnect rather than leaving a live peer missing the last batch.
        client.closed = True
        client.writer.close()


async def receive_note_ops(server, body, room_id, device_id, owner_account_id, quota, session_generation=None):
    request_id, generation = body.get("requestId"), body.get("generation")
    if not _valid_id(request_id, OP_ID) or not _valid_int(generation, 1):
        raise ApiError(400, "invalid_note_request")
    if session_generation is not None and session_generation != generation:
        raise ApiError(409, "note_upgrade_required")
    results, events = server.db.commit_note_ops(room_id, generation, device_id, owner_account_id, quota, body.get("ops"))
    if events:
        message = {"type": "note_events", "generation": generation, "events": events}
        text = json.dumps(message, separators=(",", ":"))
        clients = tuple(server.rooms.get(room_id, ()))
        await asyncio.gather(*(_deliver(client, text) for client in clients
                               if getattr(client, 'note_generation', None) == generation))
    return {"type": "note_results", "requestId": request_id, "generation": generation, "results": results}
