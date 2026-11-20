"""Хранилище релея: `RelayDatabase` собирается из миксинов, по одному на таблицу.

Тесты и `server.py` видят один класс с прежним именем — разложено только по файлам.
"""

from __future__ import annotations

from store.base import StoreBase
from store.bundles import BundlesMixin
from store.accounts import AccountsMixin
from store.pairing import PairingMixin
from store.vaults import VaultsMixin
from store.notify import NotifyMixin
from store.assistant import AssistantMixin
from store.note_registry import NoteRegistryMixin


class RelayDatabase(StoreBase, BundlesMixin, AccountsMixin, PairingMixin,
                    VaultsMixin, NotifyMixin, AssistantMixin, NoteRegistryMixin):
    """SQLite persistence; all account-era schema changes are additive."""
