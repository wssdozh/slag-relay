"""Local-only operator commands. Use a staging DB first; no public migration route."""
import argparse
import json
from pathlib import Path

from settings import PLANS
from store import RelayDatabase


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
            owner = db.conn.execute('''SELECT a.account_id, a.plan FROM rooms r JOIN vaults v ON v.id=r.vault_id
                JOIN accounts a ON a.account_id=v.owner_account_id WHERE r.room_id=? AND NOT r.retired''', (args.room,)).fetchone()
            if not owner:
                parser.error('room has no active owner')
            db.activate_note_room(args.room, seed.get('generation'), seed['ops'], owner['account_id'], PLANS[owner['plan']]['cache_mb'] * 1024 * 1024,
                                  folder_tree_id=seed.get('folderTreeId'))
        print(json.dumps(db.note_status(args.room)))
    finally:
        db.conn.close()


if __name__ == '__main__':
    main()
