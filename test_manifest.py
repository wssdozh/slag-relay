"""Манифест комнаты: POST для записи, GET для чтения по sync id."""

import asyncio
import hashlib
import json
import os
import shutil
import socket
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from server import SlagRelayServer


class ManifestTestCase(unittest.IsolatedAsyncioTestCase):
    
    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="slag_manifest_test_")
        self.db_path = os.path.join(self.tmpdir, "manifest.db")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.host = "127.0.0.1"
        self.base = f"http://{self.host}:{self.port}"
        self.server = SlagRelayServer(self.host, self.port, self.db_path,
                                      require_account_auth=False)
        self.server_task = asyncio.create_task(self.server.run())
        await asyncio.sleep(0.05)

    async def asyncTearDown(self):
        self.server_task.cancel()
        try:
            await self.server_task
        except (asyncio.CancelledError, Exception):
            pass
        self.server.db.conn.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def setup_room_with_vault(self, room_id, vault_id, owner_token=None):
        """Создаём комнату + вейл с полным auth-профилем."""
        now = time.time()
        acct = "acc-test-owner"
        dev = "dev-test"
        
        self.server.db.conn.execute("""INSERT OR IGNORE INTO vaults (id, name, owner_account_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)""",
            (vault_id, f"vault-{vault_id}", acct, now, now))
        self.server.db.conn.execute("""INSERT OR IGNORE INTO vault_grants (vault_id, device_id, mode, status, encrypted_key, updated_at) VALUES (?, ?, 'read-write', 'accepted', 'enc-key', ?)""",
            (vault_id, dev, now))
        self.server.db.conn.execute("""
            INSERT OR REPLACE INTO rooms (room_id, created_at, last_active_at, vault_id)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(room_id) DO UPDATE SET vault_id = excluded.vault_id, last_active_at = excluded.last_active_at
        """, (room_id, now, now, vault_id))
        self.server.db.conn.commit()
        
        if owner_token:
            token_hash = hashlib.sha256(owner_token.encode()).hexdigest()
            self.server.db.conn.execute("""INSERT OR IGNORE INTO accounts (account_id, public_key, plan, created_at, status, expires_at, display_name) VALUES (?, ?, 'free', ?, 'active', ?, '')""",
                (acct, "pk", now, now + 86400*365))
            self.server.db.conn.execute("""INSERT OR IGNORE INTO devices (id, account_id, name, platform, public_key, status, paired_at, last_seen_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
                (dev, acct, dev, "test", "pk", now, now))
            self.server.db.conn.execute("""INSERT OR REPLACE INTO auth_sessions (token_hash, account_id, device_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)""",
                (token_hash, acct, dev, now, now + 86400))
            self.server.db.conn.commit()
            return acct, dev
        return None, None

    async def call_route(self, method, room_id, vault_id, path_extra, query, body, token=None):
        """Вызов роутера напрямую. Возвращает (status_code, body_dict_or_None)."""
        headers = {}
        if token:
            headers["authorization"] = f"Bearer {token}"
        
        class FakeWriter:
            pass
        
        try:
            result = await self.server._route_manifest(method, path_extra, query, body, headers, FakeWriter())
        except Exception as e:
            code = getattr(e, 'status', 500)
            msg = getattr(e, 'error', str(e))
            return code, {"error": msg}
        if result is None:
            return 204, None
        if isinstance(result, tuple):
            # Format: (body_dict, status_int)
            b, s = result[0], result[1]
            return s, b
        return 500, {"error": "unexpected_result"}

    # --- Тесты POST ---

    async def test_write_and_read(self):
        """Запись манифеста разрешённым устройством и чтение обратно."""
        room, vault, token = "mr-room", "mr-vault", "tok-mr-device"
        self.setup_room_with_vault(room, vault, token)
        
        manifest = {"v": 1, "root": "aabbccdd", "folders": {"docs": "eeff0011"}}
        s, b = await self.call_route("POST", room, vault, f"/api/rooms/{room}/manifest",
                                       {"vault": vault}, manifest, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["syncId"], 1)
        
        s, b = await self.call_route("GET", room, vault, f"/api/rooms/{room}/manifest",
                                       {"vault": vault}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["root"], "aabbccdd")
        self.assertEqual(b["folders"]["docs"], "eeff0011")
        self.assertEqual(b["syncId"], 1)

    async def test_leaves_travel_back(self):
        """Листья хранятся и возвращаются: по ним клиент называет расхождение."""
        room, vault, token = "lv-room", "lv-vault", "tok-lv-device"
        self.setup_room_with_vault(room, vault, token)

        manifest = {"v": 1, "root": "aabbccdd", "folders": {"docs": "eeff0011"},
                    "leaves": {"item_1": "1111", "item_2": "2222"}}
        s, b = await self.call_route("POST", room, vault, f"/api/rooms/{room}/manifest",
                                     {"vault": vault}, manifest, token)
        self.assertEqual(s, 200, b)

        s, b = await self.call_route("GET", room, vault, f"/api/rooms/{room}/manifest",
                                     {"vault": vault}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["leaves"], {"item_1": "1111", "item_2": "2222"})

    async def test_without_leaves_keeps_the_old_shape(self):
        """Старый отправитель листьев не шлёт — тело остаётся прежним, без пустого ключа."""
        room, vault, token = "nl-room", "nl-vault", "tok-nl-device"
        self.setup_room_with_vault(room, vault, token)

        s, b = await self.call_route("POST", room, vault, f"/api/rooms/{room}/manifest",
                                     {"vault": vault},
                                     {"v": 1, "root": "aabbccdd", "folders": {}}, token)
        self.assertEqual(s, 200, b)

        s, b = await self.call_route("GET", room, vault, f"/api/rooms/{room}/manifest",
                                     {"vault": vault}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertNotIn("leaves", b)

    async def test_unauthorized_device_rejected(self):
        """Отказ чужому токену."""
        room, vault, own_tok = "ur-room", "ur-vault", "tok-ur-owner"
        self.setup_room_with_vault(room, vault, own_tok)
        other_tok = "tok-ur-other"
        s, b = await self.call_route("POST", room, vault, f"/api/rooms/{room}/manifest",
                                       {"vault": vault}, {"v": 1, "root": "abc", "folders": {}}, other_tok)
        self.assertIn(s, [401, 403])

    async def test_wrong_vault_room_mismatch(self):
        """Отказ при mismatch room-vault binding."""
        tok = "tok-wvr-owner"
        self.setup_room_with_vault("wvr-a", "wvr-v-a", tok)
        self.setup_room_with_vault("wvr-b", "wvr-v-b", tok)
        
        m = {"v": 1, "root": "abc", "folders": {}}
        s1, _ = await self.call_route("POST", "wvr-a", "wvr-v-a", "/api/rooms/wvr-a/manifest",
                                        {"vault": "wvr-v-a"}, m, tok)
        self.assertEqual(s1, 200)
        
        s2, _ = await self.call_route("POST", "wvr-b", "wvr-v-a", "/api/rooms/wvr-b/manifest",
                                        {"vault": "wvr-v-a"}, m, tok)
        self.assertEqual(s2, 403)

    async def test_too_large_body_returns_413(self):
        """413 на гигантский body > 128 КБ."""
        room, vault, token = "lg-room", "lg-vault", "tok-lg-dev"
        self.setup_room_with_vault(room, vault, token)
        
        # Нужно > 128*1024 = 131072 bytes
        huge = {f"f{i}": "abcd12345678" for i in range(6000)}
        s, b = await self.call_route("POST", room, vault, f"/api/rooms/{room}/manifest",
                                       {"vault": vault}, {"v": 1, "root": "12345678", "folders": huge}, token)
        self.assertEqual(s, 413, b)

    async def test_version_mismatch_returns_409(self):
        """409 при v != 1."""
        room, vault, token = "ver-r", "ver-v", "tok-ver-d"
        self.setup_room_with_vault(room, vault, token)
        s, b = await self.call_route("POST", room, vault, f"/api/rooms/{room}/manifest",
                                       {"vault": vault}, {"v": 2, "root": "x", "folders": {}}, token)
        self.assertEqual(s, 409, b)
        self.assertEqual(b, {"error": "unsupported_version"})

    async def test_missing_root_returns_400(self):
        """400 при отсутствии root."""
        room, vault, token = "nr-r", "nr-v", "tok-nr-d"
        self.setup_room_with_vault(room, vault, token)
        s, b = await self.call_route("POST", room, vault, f"/api/rooms/{room}/manifest",
                                       {"vault": vault}, {"v": 1, "folders": {}}, token)
        self.assertEqual(s, 400, b)

    async def test_invalid_fields_return_400(self):
        """400 при неверном типе полей."""
        room, vault, token = "type-r", "type-v", "tok-type-d"
        self.setup_room_with_vault(room, vault, token)
        s, _ = await self.call_route("POST", room, vault, "/api/rooms/type-r/manifest",
                                      {"vault": "type-v"}, {"v": 1, "root": 123, "folders": {}}, token)
        self.assertEqual(s, 400)
        s, _ = await self.call_route("POST", room, vault, "/api/rooms/type-r/manifest",
                                      {"vault": "type-v"}, {"v": 1, "root": "x", "folders": [1]}, token)
        self.assertEqual(s, 400)

    async def test_missing_vault_returns_400(self):
        """400 при отсутствии vault."""
        room, vault, token = "mv-r", "mv-v", "tok-mv-d"
        self.setup_room_with_vault(room, vault, token)
        s, b = await self.call_route("POST", room, "", "/api/rooms/mv-r/manifest", {}, 
                                      {"v": 1, "root": "x", "folders": {}}, token)
        self.assertEqual(s, 400, b)

    async def test_invalid_json_returns_400(self):
        """400 на невалидный JSON (list вместо dict)."""
        room, vault, token = "ij-r", "ij-v", "tok-ij-d"
        self.setup_room_with_vault(room, vault, token)
        s, b = await self.call_route("POST", room, vault, "/api/rooms/ij-r/manifest",
                                      {"vault": "ij-v"}, [1, 2, 3], token)
        self.assertEqual(s, 400, b)

    # --- Тесты GET ---

    async def test_since_future_returns_204(self):
        """since >= sync_id → 204 No Content."""
        room, vault, token = "s-r", "s-v", "tok-s-d"
        self.setup_room_with_vault(room, vault, token)
        
        await self.call_route("POST", room, vault, "/api/rooms/s-r/manifest",
                               {"vault": "s-v"}, {"v": 1, "root": "abcd", "folders": {}}, token)
        
        s, _ = await self.call_route("GET", room, vault, "/api/rooms/s-r/manifest",
                                      {"vault": "s-v", "since": "1"}, {}, token)
        self.assertEqual(s, 204)
        s, _ = await self.call_route("GET", room, vault, "/api/rooms/s-r/manifest",
                                      {"vault": "s-v", "since": "999"}, {}, token)
        self.assertEqual(s, 204)

    async def test_no_manifest_returns_404(self):
        """404 если манифест не создан."""
        room, vault, token = "nm-r", "nm-v", "tok-nm-d"
        self.setup_room_with_vault(room, vault, token)
        s, b = await self.call_route("GET", room, vault, "/api/rooms/nm-r/manifest",
                                      {"vault": "nm-v"}, {}, token)
        self.assertEqual(s, 404, b)
        self.assertEqual(b["error"], "manifest_not_found")

    async def test_repeated_write_updates_syncid(self):
        """Повторная запись обновляет syncId и тело."""
        room, vault, token = "upd-r", "upd-v", "tok-upd-d"
        self.setup_room_with_vault(room, vault, token)
        
        s1, r1 = await self.call_route("POST", room, vault, "/api/rooms/upd-r/manifest",
                                        {"vault": "upd-v"}, {"v": 1, "root": "aaaa", "folders": {"a": "1"}}, token)
        self.assertEqual(s1, 200, r1)
        self.assertEqual(r1["syncId"], 1)
        
        s2, r2 = await self.call_route("POST", room, vault, "/api/rooms/upd-r/manifest",
                                        {"vault": "upd-v"}, {"v": 1, "root": "bbbb", "folders": {"b": "2"}}, token)
        self.assertEqual(s2, 200, r2)
        self.assertEqual(r2["syncId"], 2)
        
        s, b = await self.call_route("GET", room, vault, "/api/rooms/upd-r/manifest",
                                      {"vault": "upd-v"}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["root"], "bbbb")
        self.assertEqual(b["syncId"], 2)
        
        s, r = await self.call_route("GET", room, vault, "/api/rooms/upd-r/manifest",
                                      {"vault": "upd-v", "since": "1"}, {}, token)
        self.assertEqual(s, 200, r)
        self.assertEqual(r["root"], "bbbb")
        
        s, _ = await self.call_route("GET", room, vault, "/api/rooms/upd-r/manifest",
                                      {"vault": "upd-v", "since": "2"}, {}, token)
        self.assertEqual(s, 204)

    # --- Тесты манифеста на устройство (?device=) ---

    async def test_devices_do_not_overwrite_each_other(self):
        """Два устройства пишут свои корни, GET отдаёт чужой и не отдаёт свой."""
        room, vault, token = "pd-r", "pd-v", "tok-pd-d"
        self.setup_room_with_vault(room, vault, token)
        path = f"/api/rooms/{room}/manifest"

        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault, "device": "A"},
                                      {"v": 1, "root": "aaaa", "folders": {"a": "1"}}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["syncId"], 1)

        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault, "device": "B"},
                                      {"v": 1, "root": "bbbb", "folders": {"b": "2"}}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["syncId"], 2)

        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "A"}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual([m["deviceId"] for m in b["manifests"]], ["B"])
        self.assertEqual(b["manifests"][0]["root"], "bbbb")
        self.assertEqual(b["manifests"][0]["folders"], {"b": "2"})
        self.assertEqual(b["manifests"][0]["syncId"], 2)
        self.assertIsNone(b["anonymous"])

        # Записи с device не создают legacy-строку: старый клиент по-прежнему видит 404.
        s, b = await self.call_route("GET", room, vault, path, {"vault": vault}, {}, token)
        self.assertEqual(s, 404, b)

    async def test_legacy_row_is_anonymous_for_device_reads(self):
        """POST без device пишет в старую таблицу, а GET с device зовёт её anonymous."""
        room, vault, token = "lga-r", "lga-v", "tok-lga-d"
        self.setup_room_with_vault(room, vault, token)
        path = f"/api/rooms/{room}/manifest"

        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault},
                                      {"v": 1, "root": "legacy01", "folders": {"l": "9"}}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["syncId"], 1)

        s, b = await self.call_route("GET", room, vault, path, {"vault": vault}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["root"], "legacy01")
        self.assertEqual(b["folders"], {"l": "9"})
        self.assertEqual(b["syncId"], 1)

        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "A"}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["manifests"], [])
        self.assertEqual(b["anonymous"]["root"], "legacy01")
        self.assertEqual(b["anonymous"]["folders"], {"l": "9"})
        self.assertEqual(b["anonymous"]["syncId"], 1)

        # И наоборот: запись с device не перетирает legacy-строку.
        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault, "device": "A"},
                                      {"v": 1, "root": "aaaa", "folders": {}}, token)
        self.assertEqual(s, 200, b)
        s, b = await self.call_route("GET", room, vault, path, {"vault": vault}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["root"], "legacy01")

    async def test_device_leaves_travel_back(self):
        """leaves доезжают в чужой элемент manifests[], а без них ключа нет."""
        room, vault, token = "pdl-r", "pdl-v", "tok-pdl-d"
        self.setup_room_with_vault(room, vault, token)
        path = f"/api/rooms/{room}/manifest"

        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault, "device": "A"},
                                      {"v": 1, "root": "aaaa", "folders": {},
                                       "leaves": {"item_1": "1111"}}, token)
        self.assertEqual(s, 200, b)
        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault, "device": "B"},
                                      {"v": 1, "root": "bbbb", "folders": {}}, token)
        self.assertEqual(s, 200, b)

        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "B"}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(len(b["manifests"]), 1)
        self.assertEqual(b["manifests"][0]["deviceId"], "A")
        self.assertEqual(b["manifests"][0]["leaves"], {"item_1": "1111"})

        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "A"}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertNotIn("leaves", b["manifests"][0])

    async def test_device_since_future_returns_204(self):
        """since >= максимального sync_id чужих записей → 204 и в новом режиме."""
        room, vault, token = "pds-r", "pds-v", "tok-pds-d"
        self.setup_room_with_vault(room, vault, token)
        path = f"/api/rooms/{room}/manifest"

        for dev in ("A", "B"):
            s, _ = await self.call_route("POST", room, vault, path,
                                          {"vault": vault, "device": dev},
                                          {"v": 1, "root": dev * 4, "folders": {}}, token)
            self.assertEqual(s, 200)

        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "A", "since": "2"}, {}, token)
        self.assertEqual(s, 204, b)
        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "A", "since": "999"}, {}, token)
        self.assertEqual(s, 204, b)
        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "A", "since": "1"}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertEqual(b["manifests"][0]["syncId"], 2)

    async def test_payload_carries_publication_time(self):
        """`at` — миллисекунды: целое больше нуля и не уменьшается при перезаписи."""
        room, vault, token = "pt-r", "pt-v", "tok-pt-d"
        self.setup_room_with_vault(room, vault, token)
        path = f"/api/rooms/{room}/manifest"

        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault},
                                      {"v": 1, "root": "legacy01", "folders": {}}, token)
        self.assertEqual(s, 200, b)
        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault, "device": "A"},
                                      {"v": 1, "root": "aaaa", "folders": {}}, token)
        self.assertEqual(s, 200, b)

        s, b = await self.call_route("GET", room, vault, path, {"vault": vault}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertIsInstance(b["at"], int)
        self.assertGreater(b["at"], 0)

        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "B"}, {}, token)
        self.assertEqual(s, 200, b)
        first_at = b["manifests"][0]["at"]
        self.assertIsInstance(first_at, int)
        self.assertGreater(first_at, 0)
        self.assertIsInstance(b["anonymous"]["at"], int)
        self.assertGreater(b["anonymous"]["at"], 0)

        time.sleep(0.01)
        s, b = await self.call_route("POST", room, vault, path,
                                      {"vault": vault, "device": "A"},
                                      {"v": 1, "root": "aaaa2", "folders": {}}, token)
        self.assertEqual(s, 200, b)
        s, b = await self.call_route("GET", room, vault, path,
                                      {"vault": vault, "device": "B"}, {}, token)
        self.assertEqual(s, 200, b)
        self.assertGreaterEqual(b["manifests"][0]["at"], first_at)

    async def test_without_folders_accepted(self):
        """leaves необязательны — принимаем без folders."""
        room, vault, token = "nl-r", "nl-v", "tok-nl-d"
        self.setup_room_with_vault(room, vault, token)
        s, b = await self.call_route("POST", room, vault, "/api/rooms/nl-r/manifest",
                                      {"vault": "nl-v"}, {"v": 1, "root": "fedcba09"}, token)
        self.assertEqual(s, 200, b)
        
        s, rb = await self.call_route("GET", room, vault, "/api/rooms/nl-r/manifest",
                                       {"vault": "nl-v"}, {}, token)
        self.assertEqual(s, 200, rb)
        self.assertEqual(rb["root"], "fedcba09")
        self.assertEqual(rb["folders"], {})


if __name__ == "__main__":
    unittest.main()
