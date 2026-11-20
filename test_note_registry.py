import base64
import json
import time
import unittest

from errors import ApiError
import test_relay

ROOM = 'note-room'
VAULT = 'vault-1'
OWNER = 'device-1'
QUOTA = 20_000_000


def operation(op_id, kind='create', base=0, note_id='a' * 64, payload=b'x' * 32):
    return {'opId': op_id, 'noteId': note_id, 'kind': kind, 'baseRevision': base,
            'sealed': {'iv': 'A' * 16, 'ciphertext': base64.b64encode(payload).decode()}}


class TestNoteRegistry(test_relay.RelayTestCase):
    auth_required = True
    identity = staticmethod(test_relay.TestAccountRelay.identity)
    signature = staticmethod(test_relay.TestAccountRelay.signature)
    device = test_relay.TestAccountRelay.device
    register = test_relay.TestAccountRelay.register
    auth_call = test_relay.TestAccountRelay.auth_call
    add_active_device = test_relay.TestAccountRelay.add_active_device
    two_devices = test_relay.TestAccountRelay.two_devices
    accepted_vault = test_relay.TestAccountRelay.accepted_vault

    async def setup_room(self):
        identity, token, _, guest = await self.two_devices()
        await self.accepted_vault(token, guest)
        self.db = self.server.db
        self.db.touch_room(ROOM, VAULT)
        self.account_id = identity['accountId']
        self.generation = self.db.freeze_note_room(ROOM)
        return token, guest

    def commit(self, *ops, sender=OWNER, quota=QUOTA):
        return self.db.commit_note_ops(ROOM, self.generation, sender, self.account_id, quota, list(ops))

    async def test_cas_receipts_and_expired_history(self):
        await self.setup_room()
        self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA)
        create = operation('create')
        (accepted,), events = self.commit(create)
        self.assertEqual(accepted, {'opId': 'create', 'status': 'accepted', 'revision': 1})
        self.assertEqual(events[0]['revision'], 1)
        self.assertEqual(self.commit(create), ([accepted], []))
        self.assertEqual(self.commit(create, sender='device-2')[0][0]['code'], 'note_op_id_reused')
        self.assertEqual(self.commit(operation('create', payload=b'y' * 32))[0][0]['code'], 'note_op_id_reused')
        self.assertEqual(self.commit(operation('quota', 'update', 1), quota=0)[0][0]['code'], 'cache_limit_exceeded')
        self.assertEqual(self.commit(operation('delete', 'delete', 1))[0][0]['revision'], 2)
        self.assertEqual(self.commit(operation('old', 'update', 1))[0][0]['current']['kind'], 'delete')
        self.assertEqual(self.commit(operation('no', 'update', 2))[0][0]['code'], 'invalid_note_transition')
        with self.db.conn:
            self.db.conn.execute('UPDATE note_versions SET expires_at = ?', (time.time() - 1,))
        self.db.cleanup_expired()
        self.assertEqual(self.db.note_events(ROOM, self.generation, 0, 100),
                         {'generation': self.generation, 'head': 2, 'floor': 2, 'events': []})
        heads = self.db.note_heads(ROOM, self.generation, '', 0, 2, 100)
        self.assertEqual([(row['kind'], row['revision']) for row in heads['heads']], [('delete', 2)])
        self.assertEqual(self.commit(create), ([accepted], []))
        self.assertEqual(self.commit(operation('restore', 'restore', 2))[0][0]['revision'], 3)

    async def test_bootstrap_is_atomic_and_thaw_invalidates_old_seeds(self):
        await self.setup_room()
        with self.assertRaises(ApiError):
            self.db.activate_note_room(ROOM, self.generation,
                                       [operation('first'), operation('duplicate')], self.account_id, QUOTA)
        self.assertEqual(self.db.note_status(ROOM)['mode'], 'frozen')
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM note_versions').fetchone()[0], 0)
        self.db.thaw_note_room(ROOM, self.generation)
        generation = self.db.freeze_note_room(ROOM)
        self.assertGreater(generation, self.generation)
        with self.assertRaises(ApiError):
            self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA)
        result = self.db.activate_note_room(ROOM, generation, [operation('tomb', 'delete')], self.account_id, QUOTA)
        self.assertEqual((result['head'], result['floor']), (1, 1))

    async def test_http_cutover_and_per_device_permissions(self):
        token, guest = await self.setup_room()
        prefix = f'/api/rooms/{ROOM}/'
        suffix = f'?vault={VAULT}'
        old_bundle = {'bundleId': 'legacy-writer', 'fromDeviceId': OWNER}
        code, body = await self.http('POST', prefix + 'bundle' + suffix, old_bundle, token)
        self.assertEqual((code, body['error']), (409, 'note_room_frozen'))
        self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA)
        code, body = await self.http('POST', prefix + 'bundle' + suffix, old_bundle, token)
        self.assertEqual((code, body['error']), (409, 'note_upgrade_required'))
        code, _ = await self.http('POST', prefix + 'bundle' + suffix + f'&noteGeneration={self.generation}', old_bundle, token)
        self.assertEqual(code, 200)
        self.db.set_vault_grant(VAULT, self.account_id, 'device-2', 'receive-only', 'encrypted', 'accepted')
        batch = {'generation': self.generation, 'requestId': 'test', 'ops': [operation('new')]}
        self.assertEqual((await self.http('POST', prefix + 'note-ops' + suffix, batch, guest))[0], 403)
        code, result = await self.http('POST', prefix + 'note-ops' + suffix, batch, token)
        self.assertEqual((code, result['results'][0]['revision']), (200, 1))
        code, page = await self.http('GET', prefix + 'note-events' + suffix + f'&generation={self.generation}', token=guest)
        self.assertEqual((code, page['events'][0]['opId']), (200, 'new'))
        self.assertEqual((await self.http('GET', prefix + 'note-status' + suffix))[0], 401)

    async def test_page_budget_allows_large_singleton(self):
        await self.setup_room()
        self.db.activate_note_room(ROOM, self.generation, [operation('big', payload=b'x' * 90_000),
                                    operation('small', note_id='b' * 64)], self.account_id, QUOTA)
        first = self.db.note_heads(ROOM, self.generation, '', 0, 2, 100_000)
        self.assertEqual(first['next'], 'a' * 64)
        self.assertEqual([row['opId'] for row in first['heads']], ['big'])
        second = self.db.note_heads(ROOM, self.generation, first['next'], 0, 2, 100_000)
        self.assertEqual(second['next'], None)
        self.assertEqual([row['opId'] for row in second['heads']], ['small'])


if __name__ == '__main__':
    unittest.main()
