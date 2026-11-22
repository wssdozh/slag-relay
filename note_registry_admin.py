"""Operator-only room cutover, via admin HTTP or local CLI."""
import argparse
import asyncio
from contextlib import closing
import sqlite3
import tempfile
import json
from pathlib import Path

from errors import ApiError
from settings import PLANS
from store.note_registry import validate_note_ops
from store import RelayDatabase


def _backup_note_cutover(db_path):
    source_path = Path(db_path).resolve(strict=True)
    target_dir = source_path.parent / "backups"
    target_dir.mkdir(mode=0o700, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="note-cutover-", suffix=".sqlite", dir=target_dir, delete=False) as handle:
        path = Path(handle.name)
    try:
        with closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)) as source, closing(sqlite3.connect(path)) as target:
            source.backup(target)
            if target.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise sqlite3.DatabaseError("Backup integrity check failed")
    except Exception:
        path.unlink(missing_ok=True)
        raise


async def admin_note_migration(server, room, action, body):
    owner = server.db.conn.execute("""SELECT a.account_id, a.plan FROM rooms r
        JOIN vaults v ON r.vault_id = v.id JOIN accounts a ON a.account_id = v.owner_account_id
        WHERE r.room_id = ? AND NOT r.retired""", (room,)).fetchone()
    if not owner:
        raise ApiError(409, "note_room_not_bound")
    current = server.db.note_status(room)
    generation = body.get("generation")
    if action == "note-freeze":
        generation = server.db.freeze_note_room(room, track_writers=True)
    else:
        if type(generation) is not int or current["mode"] != "frozen" or generation != current["generation"]:
            raise ApiError(409, "note_prepare_changed")
        if action == "note-thaw":
            server.db.thaw_note_room(room, generation)
        else:
            seed = body.get("seed")
            if (body.get("confirmRoom") != room or not isinstance(seed, dict) or seed.get("room") != room
                    or type(seed.get("generation")) is not int or seed["generation"] != generation
                    or not isinstance(seed.get("ops"), list)):
                raise ApiError(400, "invalid_note_seed")
            if set(seed) - {"room", "generation", "ops", "writers", "folderTreeId", "atomicGroups", "sharedRecords", "registryMedia", "media"}:
                raise ApiError(400, "invalid_note_seed")
            for raw in seed["ops"]:
                op, _, _ = validate_note_ops([raw])[0]
                if op != raw or op.get("group") or op["kind"] not in ("create", "delete") or op["baseRevision"] != 0:
                    raise ApiError(400, "invalid_note_seed")
            for flag in ("atomicGroups", "sharedRecords", "registryMedia"):
                if type(seed.get(flag, False)) is not bool:
                    raise ApiError(400, "invalid_note_seed")
            media = seed.get("registryMedia", False)
            if media != ("media" in seed) or (media and not isinstance(seed["media"], list)):
                raise ApiError(400, "invalid_note_seed")
            if media and any(not isinstance(blob, dict) or set(blob) != {"id", "ciphertext"} for blob in seed["media"]):
                raise ApiError(400, "invalid_note_seed")
            writers = [device["id"] for device in server.db.note_room_writers(room)[1]]
            if not writers or seed.get("writers") != writers:
                raise ApiError(409, "note_prepare_writers_changed")
            server.db.require_note_prepare_writers(room)
            if getattr(server, "note_backup_running", False):
                raise ApiError(409, "note_backup_busy")
            server.note_backup_running = True
            try:
                await asyncio.to_thread(_backup_note_cutover, server.db.db_path)
            except (OSError, sqlite3.Error):
                raise ApiError(503, "note_backup_failed") from None
            finally:
                server.note_backup_running = False
            server.db.activate_note_room(room, generation, seed["ops"], owner["account_id"],
                PLANS[owner["plan"]]["cache_mb"] * 1024 * 1024, folder_tree_id=seed.get("folderTreeId"),
                atomic_groups=seed.get("atomicGroups", False), shared_records=seed.get("sharedRecords", False),
                registry_media=media, media_seed=seed.get("media"), check_writers=True)
    server.db.record_audit(action, "room", room, f"generation={generation}")
    return {"noteStatus": server.db.note_status(room), "writers": server.db.note_room_writers(room)[1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--room', required=True)
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('status')
    actions.add_parser('freeze')
    thaw = actions.add_parser('thaw')
    thaw.add_argument('--generation', type=int, required=True)
    activate = actions.add_parser('activate')
    activate.add_argument('--seed', type=Path, required=True)
    activate.add_argument('--confirm-room', required=True)
    activate.add_argument('--atomic-groups', action='store_true')
    activate.add_argument('--shared-records', action='store_true')
    activate.add_argument('--registry-media', action='store_true')
    args = parser.parse_args()
    if not args.db.is_file():
        parser.error('database must already exist')
    if args.action == 'activate' and args.confirm_room != args.room:
        parser.error('confirmation does not match room')
    db = RelayDatabase(str(args.db))
    try:
        if args.action == 'freeze':
            db.freeze_note_room(args.room)
        elif args.action == 'thaw':
            db.thaw_note_room(args.room, args.generation)
        elif args.action == 'activate':
            seed = json.loads(args.seed.read_text(encoding='utf-8-sig'))
            if not isinstance(seed, dict) or seed.get('room') != args.room or not isinstance(seed.get('ops'), list):
                parser.error('invalid seed or wrong room')
            if seed.get('sharedRecords', False) is not args.shared_records:
                parser.error('--shared-records and reviewed seed capability must match')
            if seed.get('registryMedia', False) is not args.registry_media or ('media' in seed) != args.registry_media:
                parser.error('--registry-media and reviewed seed capability must match')
            if args.registry_media and not isinstance(seed['media'], list):
                parser.error('invalid media seed')
            owner = db.conn.execute('''SELECT a.account_id, a.plan FROM rooms r JOIN vaults v ON v.id=r.vault_id
                JOIN accounts a ON a.account_id=v.owner_account_id WHERE r.room_id=? AND NOT r.retired''', (args.room,)).fetchone()
            if not owner:
                parser.error('room has no active owner')
            db.activate_note_room(args.room, seed.get('generation'), seed['ops'], owner['account_id'], PLANS[owner['plan']]['cache_mb'] * 1024 * 1024,
                                  folder_tree_id=seed.get('folderTreeId'), atomic_groups=args.atomic_groups,
                                  shared_records=args.shared_records, registry_media=args.registry_media, media_seed=seed.get('media'))
        print(json.dumps(db.note_status(args.room)))
    finally:
        db.conn.close()


if __name__ == '__main__':
    main()
