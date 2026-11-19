#!/usr/bin/env python3
"""Страница бандлов ограничена байтами, а не количеством.

Один бандл с вложением — до 6 МБ (base64 в json — ~8 МБ), поэтому страница из 1000 штук
могла быть сотнями мегабайт, и клиент падал по `AbortSignal.timeout`, так и не дочитав
её. Здесь проверяем бюджет `maxBytes`, поле `bytes` в ответе и то, что курсор едет дальше.
"""

import json
import unittest

from test_relay import RelayTestCase

OTHER = "dev-1"  # отправитель
ME = "dev-2"     # получатель


class BundlePageBytesTest(RelayTestCase):
    def save_blob(self, room: str, bundle_id: str, blob_bytes: int) -> int:
        """Кладёт бандл с большим полем и возвращает фактический размер payload'а."""
        payload = json.dumps({"bundleId": bundle_id, "fromDeviceId": OTHER, "sequence": 1,
                              "changes": [], "blob": "x" * blob_bytes})
        self.assertTrue(self.server.db.save_bundle(room, bundle_id, OTHER, 1, "ts", payload))
        return len(payload.encode("utf-8"))

    def page_bytes(self, bundles: list) -> int:
        return sum(len(json.dumps(bundle["payload"]).encode("utf-8")) for bundle in bundles)

    async def test_page_is_cut_by_byte_budget(self):
        room = "bytes-cut-room"
        for index in range(3):
            self.save_blob(room, f"cut-{index}", 400_000)
        status, result = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}&maxBytes=1000000")
        self.assertEqual(status, 200)
        self.assertEqual(len(result["bundles"]), 2)
        self.assertLessEqual(result["bytes"], 1_000_000)
        self.assertEqual(result["bytes"], self.page_bytes(result["bundles"]))

        page, page_bytes = self.server.db.get_pending_bundles_page(room, ME, max_bytes=1_000_000)
        self.assertEqual([bundle["bundleId"] for bundle in page],
                         [bundle["bundleId"] for bundle in result["bundles"]])
        self.assertEqual(page_bytes, result["bytes"])

        # Legacy-ветка (без since, по ACK'ам) тоже уважает бюджет.
        first_id = result["bundles"][0]["bundleId"]
        status, acked = await self.http("POST", f"/api/rooms/{room}/ack",
                                        {"deviceId": ME, "bundleIds": [first_id]})
        self.assertEqual(status, 200)
        self.assertEqual(acked["acked"], 1)
        status, legacy = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}&maxBytes=1000000")
        self.assertEqual(status, 200)
        self.assertEqual(sorted(bundle["bundleId"] for bundle in legacy["bundles"]), ["cut-1", "cut-2"])
        self.assertLessEqual(legacy["bytes"], 1_000_000)
        self.assertEqual(legacy["bytes"], self.page_bytes(legacy["bundles"]))

    async def test_bundle_larger_than_budget_is_delivered_alone(self):
        room = "bytes-oversize-room"
        self.save_blob(room, "huge", 500_000)
        self.save_blob(room, "next", 10_000)
        status, result = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}&maxBytes=100000")
        self.assertEqual(status, 200)
        self.assertEqual(len(result["bundles"]), 1)
        self.assertEqual(result["bundles"][0]["bundleId"], "huge")
        self.assertGreater(result["bytes"], 100_000)

        # Курсор не застрял: следующий запрос отдаёт остаток, а не тот же бандл.
        cursor = result["bundles"][0]["syncId"]
        status, rest = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}&since={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual([bundle["bundleId"] for bundle in rest["bundles"]], ["next"])

    async def test_without_max_bytes_old_limit_behaviour(self):
        room = "bytes-legacy-page-room"
        for index in range(3):
            self.save_blob(room, f"plain-{index}", 400_000)
        status, result = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}")
        self.assertEqual(status, 200)
        self.assertEqual(len(result["bundles"]), 3)
        status, limited = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(len(limited["bundles"]), 2)
        self.assertEqual(len(self.server.db.get_pending_bundles(room, ME, 2)), 2)

    async def test_garbage_max_bytes_falls_back_to_default_budget(self):
        room = "bytes-garbage-room"
        self.save_blob(room, "half-1", 1_500_000)
        self.save_blob(room, "half-2", 1_500_000)
        status, result = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}&maxBytes=abc")
        self.assertEqual(status, 200)
        # Дефолт 2 МБ: первый (~1.5 МБ) влезает, второй уже нет.
        self.assertEqual(len(result["bundles"]), 1)
        self.assertLessEqual(result["bytes"], 2_000_000)
        # Без параметра действует тот же дефолт, а не «без ограничения».
        status, defaulted = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}")
        self.assertEqual(status, 200)
        self.assertEqual(len(defaulted["bundles"]), 1)

    async def test_max_bytes_is_clamped_to_bounds(self):
        room = "bytes-clamp-room"
        for index in range(3):
            self.save_blob(room, f"small-{index}", 40_000)
        status, result = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}&maxBytes=1")
        self.assertEqual(status, 200)
        # maxBytes=1 поднимается до минимума 100 000: влезают два бандла по ~40 КБ.
        self.assertEqual(len(result["bundles"]), 2)
        self.assertLessEqual(result["bytes"], 100_000)

    async def test_cursor_advances_after_budgeted_page(self):
        room = "bytes-cursor-room"
        for index in range(3):
            self.save_blob(room, f"cursor-{index}", 400_000)
        status, first = await self.http("GET", f"/api/rooms/{room}/bundles?device={ME}&maxBytes=1000000")
        self.assertEqual(status, 200)
        self.assertEqual(len(first["bundles"]), 2)
        cursor = first["bundles"][-1]["syncId"]
        self.assertEqual(cursor, 2)
        status, rest = await self.http("GET",
                                       f"/api/rooms/{room}/bundles?device={ME}&since={cursor}&maxBytes=1000000")
        self.assertEqual(status, 200)
        self.assertEqual([bundle["bundleId"] for bundle in rest["bundles"]], ["cursor-2"])
        self.assertEqual(rest["head"], 3)


if __name__ == "__main__":
    unittest.main()
