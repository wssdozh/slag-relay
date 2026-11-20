import asyncio
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

    async def test_cutover_fences_already_open_legacy_socket(self):
        token, _ = await self.setup_room()
        self.db.thaw_note_room(ROOM, self.generation)
        reader, writer, _ = await self.open_ws(ROOM, OWNER, token, VAULT, backlog='http')
        async def frame():
            return await asyncio.wait_for(test_relay.read_server_ws_frame(reader), timeout=2)
        async def push():
            data = {'type': 'bundle', 'bundle': {'bundleId': 'open-legacy', 'fromDeviceId': OWNER}}
            writer.write(test_relay.make_client_ws_frame(json.dumps(data).encode()))
            await writer.drain()
            return await frame()
        try:
            self.assertEqual((await frame())['type'], 'welcome')
            generation = self.db.freeze_note_room(ROOM)
            self.assertEqual(await push(), {'type': 'error', 'code': 'note_room_frozen'})
            self.db.activate_note_room(ROOM, generation, [], self.account_id, QUOTA)
            self.assertEqual(await push(), {'type': 'error', 'code': 'note_upgrade_required'})
            self.assertEqual(self.db.get_room_watermarks(ROOM)['head'], 0)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_tree_activation_fences_note_only_clients_and_preserves_one_head(self):
        token, guest = await self.setup_room()
        tree = 'b' * 64
        with self.assertRaises(ApiError):
            self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA, folder_tree_id=tree)
        self.assertEqual(self.db.note_status(ROOM)['mode'], 'frozen')
        self.db.activate_note_room(ROOM, self.generation, [operation('tree', note_id=tree)],
                                   self.account_id, QUOTA, folder_tree_id=tree)
        url = f'/api/rooms/{ROOM}/'
        query = f'?vault={VAULT}&generation={self.generation}&noteGeneration={self.generation}'
        batch = {'generation': self.generation, 'requestId': 'tree', 'ops': [operation('update', 'update', 1, tree)]}
        for method, route, body in [('GET', 'note-status', None), ('GET', 'note-heads', None),
                                    ('GET', 'note-events', None), ('GET', 'bundles', None),
                                    ('POST', 'note-ops', batch), ('POST', 'bundle', {'fromDeviceId': OWNER})]:
            code, result = await self.http(method, url + route + query, body, token)
            self.assertEqual((code, result['error']), (409, 'note_upgrade_required'), route)
        _, old, status = await self.open_ws(ROOM, OWNER, token, VAULT, noteGeneration=self.generation)
        self.assertIn('409', status)
        self.assertIsNone(old)
        config = {'backlog': 'http', 'noteGeneration': self.generation, 'folderTree': 1}
        reader, writer, _ = await self.open_ws(ROOM, 'device-2', guest, VAULT, **config)
        try:
            async def frame():
                return await asyncio.wait_for(test_relay.read_server_ws_frame(reader), timeout=2)
            self.assertEqual((await frame())['type'], 'welcome')
            query += '&folderTree=1'
            self.assertTrue((await self.http('GET', url + 'note-status' + query, token=token))[1]['folderTree'])
            code, result = await self.http('POST', url + 'note-ops' + query, batch, token)
            self.assertEqual((code, result['results'][0]['revision']), (200, 2))
            self.assertEqual((await frame())['events'][0]['noteId'], tree)
            self.assertEqual((await self.http('POST', url + 'note-ops' + query, batch, token))[1], result)
            batch['ops'] = [operation('delete-tree', 'delete', 2, tree)]
            _, refused = await self.http('POST', url + 'note-ops' + query, batch, token)
            self.assertEqual(refused['results'][0]['code'], 'invalid_folder_tree_transition')
            _, head = await self.http('GET', url + 'note-heads' + query, token=token)
            self.assertEqual([(row['noteId'], row['revision']) for row in head['heads']], [(tree, 2)])
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_websocket_acceptance_delivers_sender_and_peer(self):
        token, guest = await self.setup_room()
        self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA)
        old_reader, old_writer, status = await self.open_ws(ROOM, OWNER, token, VAULT)
        self.assertIn('409', status)
        self.assertIsNone(old_writer)
        config = {'backlog': 'http', 'noteGeneration': self.generation}
        reader, writer, _ = await self.open_ws(ROOM, OWNER, token, VAULT, **config)
        peer, peer_writer, _ = await self.open_ws(ROOM, 'device-2', guest, VAULT, **config)
        async def frame(stream):
            return await asyncio.wait_for(test_relay.read_server_ws_frame(stream), timeout=2)
        try:
            self.assertEqual((await frame(reader))['type'], 'welcome')
            self.assertEqual((await frame(peer))['type'], 'welcome')
            data = {'type': 'note_ops', 'generation': self.generation, 'requestId': 'ws', 'ops': [operation('via-ws')]}
            writer.write(test_relay.make_client_ws_frame(json.dumps(data).encode()))
            await writer.drain()
            sent, received = await asyncio.gather(frame(reader), frame(peer))
            self.assertEqual(sent, received)
            self.assertEqual((received['type'], received['events'][0]['revision']), ('note_events', 1))
            self.assertEqual((await frame(reader))['results'][0]['revision'], 1)
        finally:
            writer.close()
            peer_writer.close()
            await asyncio.gather(writer.wait_closed(), peer_writer.wait_closed())

    async def test_stress_disconnects_duplicate_receipts_and_conflicting_folder_updates(self):
        token, guest = await self.setup_room()
        tree = 'b' * 64
        self.db.activate_note_room(ROOM, self.generation, [operation('tree', note_id=tree)],
                                   self.account_id, QUOTA, folder_tree_id=tree)
        query = f'?vault={VAULT}&generation={self.generation}&folderTree=1'
        url = f'/api/rooms/{ROOM}/'
        revision = 1
        count = 0
        for cycle in range(12):
            reader, writer, status = await self.open_ws(ROOM, OWNER, token, VAULT, backlog='http',
                                                        noteGeneration=self.generation, folderTree=1)
            self.assertIn('101', status)
            try:
                self.assertEqual((await test_relay.read_server_ws_frame(reader))['type'], 'welcome')
                start = revision
                ops = [operation(f'tree-{cycle}', 'update', start, tree)]
                ops.extend(operation(f'task-{cycle}-{i}', note_id=f'{1000 + count + i:064x}') for i in range(24))
                batch = {'type': 'note_ops', 'generation': self.generation, 'requestId': f'cycle-{cycle}', 'ops': ops}
                writer.write(test_relay.make_client_ws_frame(json.dumps(batch).encode()))
                await writer.drain()
                # The write reached SQLite, but disconnect without consuming the result frame.
                event = await asyncio.wait_for(test_relay.read_server_ws_frame(reader), timeout=3)
                self.assertEqual(event['type'], 'note_events')
                self.assertEqual(len(event['events']), len(ops))
            finally:
                writer.close()
                await writer.wait_closed()
            count += 24
            revision = 2 + 25 * cycle
            stale = {'generation': self.generation, 'requestId': f'guest-{cycle}',
                     'ops': [operation(f'offline-{cycle}', 'update', start, tree)]}
            (code, (retry_code, receipt)), (guest_code, conflict) = await asyncio.gather(
                self._repeat_batch(url + 'note-ops' + query, batch, token),
                self.http('POST', url + 'note-ops' + query, stale, guest),
            )
            self.assertEqual((code, retry_code, guest_code), (200, 200, 200))
            self.assertEqual([row['revision'] for row in receipt['results']], list(range(revision, revision + 25)))
            self.assertEqual(conflict['results'][0]['status'], 'stale')
            self.assertEqual(conflict['results'][0]['current']['revision'], revision)
            # Global sequence includes the independent task heads; the tree base does not.
            self.assertEqual(self.db.note_status(ROOM)['head'], 1 + count + cycle + 1)
            # The next tree must use its own head, not the global high water mark.
        cursor = 0
        delivered = []
        while cursor < self.db.note_status(ROOM)['head']:
            code, page = await self.http('GET', url + 'note-events' + query + f'&since={cursor}', token=guest)
            self.assertEqual(code, 200)
            self.assertTrue(page['events'])
            delivered.extend(page['events'])
            cursor = delivered[-1]['revision']
        self.assertEqual(len(delivered), 300)
        self.assertEqual(len({row['opId'] for row in delivered}), 300)
        self.assertEqual([row['revision'] for row in delivered], list(range(2, 302)))

    async def _repeat_batch(self, url, batch, token):
        code, first = await self.http('POST', url, batch, token)
        retry_code, second = await self.http('POST', url, batch, token)
        self.assertEqual(first, second)
        return code, (retry_code, second)

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
