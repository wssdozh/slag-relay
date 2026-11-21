import asyncio
import base64
import hashlib
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

    def commit(self, *ops, sender=OWNER, quota=QUOTA, media=False):
        return self.db.commit_note_ops(ROOM, self.generation, sender, self.account_id, quota, list(ops), media=media)

    async def test_cas_receipts_and_expired_history(self):
        await self.setup_room()
        self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA)
        create = operation('create')
        (accepted,), events = self.commit(create, media=True)
        self.assertEqual(accepted, {'opId': 'create', 'status': 'accepted', 'revision': 1})
        self.assertEqual(events[0]['revision'], 1)
        self.assertEqual(self.commit(create, media=True), ([accepted], []))
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
        self.assertEqual(self.commit(create, media=True), ([accepted], []))
        self.assertEqual(self.commit(operation('restore', 'restore', 2))[0][0]['revision'], 3)

    async def test_media_http_requires_room_grant_and_write_permission(self):
        token, guest = await self.setup_room()
        self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA, shared_records=True, registry_media=True)
        body = b'ciphertext' * 4
        blob_id = hashlib.sha256(body).hexdigest()
        payload = {'ciphertext': base64.b64encode(body).decode('ascii')}
        url = f'/api/rooms/{ROOM}/note-media?vault={VAULT}&generation={self.generation}&id={blob_id}'
        code, _ = await self.http('GET', url + '&sharedRecords=1')
        self.assertEqual(code, 401)
        code, _ = await self.http('PUT', url, payload, token=token)
        self.assertEqual(code, 409)
        url += '&sharedRecords=1'
        self.assertEqual((await self.http('PUT', url, payload, token=token))[0], 409)
        _, old, status = await self.open_ws(ROOM, OWNER, token, VAULT, noteGeneration=self.generation, sharedRecords=1)
        self.assertIn('409', status)
        self.assertIsNone(old)
        url += '&registryMedia=1'
        code, result = await self.http('PUT', url, payload, token=token)
        self.assertEqual((code, result), (200, {'id': blob_id}))
        code, result = await self.http('GET', url, token=token)
        self.assertEqual((code, result), (200, payload))
        self.assertEqual((await self.http('PUT', f'/api/vaults/{VAULT}/grants/device-2',
                                          {'mode': 'receive-only', 'encryptedKey': 'key'}, token))[0], 200)
        await self.http('POST', f'/api/vaults/{VAULT}/accept', {}, guest)
        self.assertEqual((await self.http('GET', url, token=guest))[0], 200)
        self.assertEqual((await self.http('PUT', url, payload, token=guest))[0], 403)

    async def test_media_is_immutable_scoped_and_counted_once(self):
        from store.note_media import MEDIA_MAX_BYTES, MEDIA_OVERHEAD

        await self.setup_room()
        body = b'encrypted-fixture-only' * 2
        blob_id = hashlib.sha256(body).hexdigest()
        put = lambda data=body, owner=self.account_id, quota=QUOTA: self.db.put_note_media(
            ROOM, self.generation, blob_id, data, owner, quota)
        with self.assertRaisesRegex(ApiError, 'note_room_frozen'):
            put()
        self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA, registry_media=True)
        with self.assertRaisesRegex(ApiError, 'note_media_not_found'):
            self.db.get_note_media(ROOM, self.generation, blob_id)
        with self.assertRaisesRegex(ApiError, 'cache_limit_exceeded'):
            put(quota=0)
        with self.assertRaisesRegex(ApiError, 'note_room_owner_mismatch'):
            put(owner='another-account')
        with self.assertRaisesRegex(ApiError, 'note_media_digest_mismatch'):
            put(data=b'x' * len(body))
        with self.assertRaisesRegex(ApiError, 'note_media_too_large'):
            put(data=b'x' * (MEDIA_MAX_BYTES + 1))
        before = self.db.get_account_cache_bytes(self.account_id)
        put()
        put(quota=0)
        self.assertEqual(self.db.get_account_cache_bytes(self.account_id), before + len(body) + MEDIA_OVERHEAD)
        self.assertEqual(self.db.note_status(ROOM)['head'], 0)
        create = {**operation('with-media'), 'mediaIds': [blob_id]}
        accepted, events = self.commit(create, media=True)
        self.assertEqual(accepted[0]['revision'], 1)
        self.assertEqual(events[0]['mediaIds'], [blob_id])
        self.assertEqual(self.commit(create, media=True), (accepted, []))
        self.assertEqual(self.commit(operation('with-media'), media=True)[0][0]['code'], 'note_op_id_reused')
        self.assertEqual(self.db.note_heads(ROOM, self.generation, '', 0, 1, 100, media=True)['heads'], events)
        with self.assertRaisesRegex(ApiError, 'invalid_note_media_refs'):
            self.commit({**create, 'mediaIds': [blob_id, blob_id]}, media=True)
        with self.assertRaisesRegex(ApiError, 'note_upgrade_required'):
            self.db.get_note_media(ROOM, self.generation + 1, blob_id)
        self.db.cleanup_expired()
        self.assertEqual(self.db.get_note_media(ROOM, self.generation, blob_id), body)

    async def test_media_seed_and_heads_activate_in_one_transaction(self):
        await self.setup_room()
        body = b'fixture encrypted bytes only' * 2
        blob = hashlib.sha256(body).hexdigest()
        entry = {'id': blob, 'ciphertext': base64.b64encode(body).decode('ascii')}
        create = operation('seed-media')
        referenced = {**create, 'mediaIds': [blob]}
        for ops, media_seed, quota, error in (
            ([referenced], [], QUOTA, 'invalid_note_media_seed_refs'),
            ([create], [entry], QUOTA, 'invalid_note_media_seed_refs'),
            ([referenced], [entry, entry], QUOTA, 'invalid_note_media_seed'),
            ([referenced], [{**entry, 'id': 'f' * 64}], QUOTA, 'invalid_note_media_seed'),
            ([referenced], [entry], len(body) + 256, 'cache_limit_exceeded'),
        ):
            with self.assertRaisesRegex(ApiError, error):
                self.db.activate_note_room(ROOM, self.generation, ops, self.account_id, quota,
                                           registry_media=True, media_seed=media_seed)
            self.assertEqual(self.db.note_status(ROOM)['mode'], 'frozen')
            self.assertEqual(self.db.conn.execute('SELECT count(*) FROM note_media').fetchone()[0], 0)
            self.assertEqual(self.db.conn.execute('SELECT count(*) FROM note_versions').fetchone()[0], 0)
        self.db.activate_note_room(ROOM, self.generation, [referenced], self.account_id, QUOTA,
                                   registry_media=True, media_seed=[entry])
        self.assertEqual(self.db.get_note_media(ROOM, self.generation, blob), body)
        heads = self.db.note_heads(ROOM, self.generation, '', 0, 1, QUOTA, media=True)
        self.assertEqual(heads['heads'][0]['mediaIds'], [blob])

    async def test_media_gc_keeps_heads_and_feed_then_releases_orphan_quota(self):
        from store.note_media import MEDIA_OVERHEAD
        from settings import DEFAULT_TTL_SECONDS

        await self.setup_room()
        self.db.activate_note_room(ROOM, self.generation, [], self.account_id, QUOTA, registry_media=True)
        body = b'past revision encrypted blob' * 2
        blob = hashlib.sha256(body).hexdigest()
        self.db.put_note_media(ROOM, self.generation, blob, body, self.account_id, QUOTA)
        self.commit({**operation('photo'), 'mediaIds': [blob]}, media=True)
        now = time.time()
        later = now + 4 * DEFAULT_TTL_SECONDS
        def clean(at):
            with self.db.conn:
                self.db.cleanup_note_versions(at)
                self.db.cleanup_note_media(at)

        clean(later)
        self.assertEqual(self.db.get_note_media(ROOM, self.generation, blob), body)  # expired feed, current head
        self.commit(operation('no-photo', 'update', 1), media=True)
        clean(now)
        self.assertEqual(self.db.get_note_media(ROOM, self.generation, blob), body)
        # A newer note references the same file while its only prior reference is being pruned.
        self.commit({**operation('reuse', note_id='d' * 64), 'mediaIds': [blob]}, media=True)
        clean(later)
        self.assertEqual(self.db.get_note_media(ROOM, self.generation, blob), body)
        self.commit(operation('remove-reuse', 'delete', 3, 'd' * 64), media=True)
        clean(later)
        before = self.db.get_account_cache_bytes(self.account_id)
        clean(later + DEFAULT_TTL_SECONDS - 1)
        self.assertEqual(self.db.get_note_media(ROOM, self.generation, blob), body)
        clean(later + DEFAULT_TTL_SECONDS)
        with self.assertRaisesRegex(ApiError, 'note_media_not_found'):
            self.db.get_note_media(ROOM, self.generation, blob)
        self.assertEqual(self.db.get_account_cache_bytes(self.account_id), before - len(body) - MEDIA_OVERHEAD)
        clean(later + 2 * DEFAULT_TTL_SECONDS)
        self.assertEqual(self.db.get_account_cache_bytes(self.account_id), before - len(body) - MEDIA_OVERHEAD)

    async def test_shared_registry_requires_capability_even_from_atomic_group_clients(self):
        token, _ = await self.setup_room()
        tree = 'b' * 64
        self.db.activate_note_room(ROOM, self.generation, [operation('tree', note_id=tree)],
                                   self.account_id, QUOTA, folder_tree_id=tree, atomic_groups=True, shared_records=True)
        url = f'/api/rooms/{ROOM}'
        query = f'?vault={VAULT}&folderTree=1&atomicGroups=1&generation={self.generation}&noteGeneration={self.generation}'
        request = {'requestId': 'shared', 'generation': self.generation, 'ops': [operation('fact')], 'observedHead': 1}
        for method, route, body in [('GET', 'note-status', None), ('GET', 'note-events', None), ('GET', 'note-heads', None),
                                    ('GET', 'bundles', None), ('POST', 'bundle', {}), ('POST', 'note-ops', request)]:
            code, result = await self.http(method, f'{url}/{route}{query}', body, token=token)
            self.assertEqual((code, result['error']), (409, 'note_upgrade_required'))
        _, old, status = await self.open_ws(ROOM, OWNER, token, VAULT, noteGeneration=self.generation, folderTree=1, atomicGroups=1)
        self.assertIn('409', status)
        self.assertIsNone(old)
        query += '&sharedRecords=1'
        code, result = await self.http('GET', f'{url}/note-status{query}', token=token)
        self.assertEqual(code, 200)
        self.assertIs(result['sharedRecords'], True)
        code, result = await self.http('POST', f'{url}/note-ops{query}', request, token=token)
        self.assertEqual((code, result['results'][0]['revision']), (200, 2))
        _, writer, status = await self.open_ws(ROOM, OWNER, token, VAULT, noteGeneration=self.generation,
                                               folderTree=1, atomicGroups=1, sharedRecords=1)
        self.assertIn('101', status)
        writer.close()
        await writer.wait_closed()

    async def test_folder_group_rolls_back_moves_if_tree_is_stale_and_replays_as_one_page(self):
        token, _ = await self.setup_room()
        tree = 'b' * 64
        self.db.activate_note_room(ROOM, self.generation,
                                   [operation('seed-note'), operation('seed-tree', note_id=tree)],
                                   self.account_id, QUOTA, folder_tree_id=tree, atomic_groups=True)

        def commit(ops, quota=QUOTA, groups=True, observed=2, sender=OWNER):
            return self.db.commit_note_ops(ROOM, self.generation, sender, self.account_id, quota,
                                           ops, folder_tree=True, groups=groups, observed_head=observed)

        media = b'opaque media fixture' * 2
        blob_id = hashlib.sha256(media).hexdigest()
        with_media = [
            {**operation('asset-create', note_id='d' * 64), 'mediaIds': [blob_id],
             'group': {'id': 'asset-create', 'index': 0, 'size': 2}},
            {**operation('asset-tree', 'update', 2, tree), 'group': {'id': 'asset-create', 'index': 1, 'size': 2}},
        ]
        rejected, events = commit(with_media)
        self.assertEqual([r.get('code') for r in rejected], ['note_media_not_enabled', 'note_group_aborted'])
        self.assertEqual(events, [])
        self.assertEqual(self.db.note_status(ROOM)['head'], 2)

        def group(tree_base):
            ops = [operation('move', 'update', 1), operation('tree-update', 'update', tree_base, tree)]
            return [{**op, 'group': {'id': 'move', 'index': index, 'size': 2}} for index, op in enumerate(ops)]

        with self.assertRaises(ApiError):
            commit(group(2), groups=False)
        with self.assertRaises(ApiError):
            commit(group(2)[:1])
        url = f'/api/rooms/{ROOM}/note-'
        query = f'?vault={VAULT}&folderTree=1&generation={self.generation}'
        for route in ('status', 'events', 'heads'):
            code, result = await self.http('GET', url + route + query, token=token)
            self.assertEqual((code, result['error']), (409, 'note_upgrade_required'))
        code, result = await self.http('GET', url + 'status' + query + '&atomicGroups=1', token=token)
        self.assertEqual(code, 200)
        self.assertIs(result['atomicGroups'], True)
        _, old, status = await self.open_ws(ROOM, OWNER, token, VAULT, noteGeneration=self.generation, folderTree=1)
        self.assertIn('409', status)
        self.assertIsNone(old)
        before = self.db.get_account_cache_bytes(self.account_id)
        results, events = commit(group(1))
        self.assertEqual([r['status'] for r in results], ['rejected', 'stale'])
        self.assertEqual(results[0]['code'], 'note_group_aborted')
        self.assertEqual(events, [])
        self.assertEqual(self.db.note_status(ROOM)['head'], 2)
        self.assertEqual(self.db.get_account_cache_bytes(self.account_id), before)
        self.assertIsNone(self.db.conn.execute("SELECT revision FROM note_receipts WHERE op_id = 'move'").fetchone())

        results, events = commit(group(2), quota=before + 1000)
        self.assertIn('cache_limit_exceeded', [r.get('code') for r in results])
        self.assertEqual(events, [])
        self.assertEqual(self.db.note_status(ROOM)['head'], 2)
        self.assertEqual(self.db.get_account_cache_bytes(self.account_id), before)

        # An unrelated event comes before the group and a normal event comes after it.
        commit([operation('unrelated', note_id='c' * 64)], sender='other-device')
        rejected, empty = commit(group(2))
        self.assertEqual([r['code'] for r in rejected], ['note_head_changed'] * 2)
        self.assertEqual(empty, [])
        self.assertEqual(self.db.note_status(ROOM)['head'], 3)
        results, events = commit(group(2), observed=3)
        self.assertEqual([r['revision'] for r in results], [4, 5])
        self.assertEqual(commit(group(2)), (results, []))
        changed = group(2)
        changed[1]['sealed']['ciphertext'] = base64.b64encode(b'y' * 32).decode()
        refused, replay = commit(changed)
        self.assertEqual(replay, [])
        self.assertEqual(refused[1]['code'], 'note_op_id_reused')
        later = [operation('later', note_id='d' * 64)]
        for observed, code in [(3, 'note_head_changed'), (None, 'note_head_required')]:
            rejected, empty = commit(later, observed=observed, sender='other-device')
            self.assertEqual(rejected[0]['code'], code)
            self.assertEqual(empty, [])
        commit(later, observed=5, sender='other-device')

        def read(since):
            return self.db.note_events(ROOM, self.generation, since, 1, folder_tree=True, groups=True)['events']

        self.assertEqual([e['opId'] for e in read(2)], ['unrelated'])
        self.assertEqual(read(3), events)
        self.assertEqual([e['opId'] for e in read(5)], ['later'])
        with self.assertRaises(ApiError):
            read(4)
        with self.db.conn:
            self.db.conn.execute('UPDATE note_versions SET expires_at = ?', (time.time() - 1,))
        self.db.cleanup_expired()
        self.assertEqual(read(0), [])
        self.assertEqual(commit(group(2)), (results, []))
        heads = self.db.note_heads(ROOM, self.generation, '', 0, 6, QUOTA, folder_tree=True, groups=True)['heads']
        self.assertEqual([e for e in heads if 'group' in e], events)

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
