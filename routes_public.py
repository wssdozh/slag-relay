"""Публичные данные о тарифах: сайту нужны цены и лимиты без админского токена.

Цена живёт в `settings.PLANS` рядом с лимитами, чтобы лендинг, кабинет и MRR в админке не
разъезжались: одно место правки вместо трёх.
"""

from __future__ import annotations

from settings import PLANS
from router import _NEXT


class PublicRoutes:
    async def _route_public(self, method: str, path: str, query: dict, body: dict,
                            headers: dict, writer):
        if method == "GET" and path == "/api/plans":
            return {
                "plans": [
                    {
                        "id": plan_id,
                        "label": plan["label"],
                        "priceRub": plan["price_rub"],
                        "devices": plan["devices"],
                        "cacheMb": plan["cache_mb"],
                    }
                    for plan_id, plan in PLANS.items()
                ]
            }, 200
        return _NEXT
