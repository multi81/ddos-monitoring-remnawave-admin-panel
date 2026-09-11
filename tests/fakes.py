"""Фейковый ctx плагина для тестов без панели."""
from __future__ import annotations

import asyncio
from typing import Any


class FakeDB:
    """Минимальный asyncpg-подобный фасад на словарях."""

    def __init__(self):
        self.tables: dict[str, list[dict]] = {}
        self.settings: dict[tuple, Any] = {}
        self.fail = False
        self._inserted_samples: list = []

    async def _guard(self):
        if self.fail:
            raise RuntimeError("db unavailable")
        await asyncio.sleep(0)

    async def fetch(self, query: str, *args):
        await self._guard()
        q = query.lower()
        if "from ddos_monitoring_node_state" in q:
            return [dict(r) for r in self.tables.get("ddos_monitoring_node_state", [])]
        if "from ddos_monitoring_attacks" in q and "ended_at is null" not in q.replace("\n", " "):
            return [dict(r) for r in self.tables.get("ddos_monitoring_attacks", [])]
        return []

    async def fetchrow(self, query: str, *args):
        await self._guard()
        if "returning id" in query.lower():
            rows = self.tables.setdefault("ddos_monitoring_attacks", [])
            pk = len(rows) + 1
            row = {"id": pk, "node_uuid": args[0], "attack_type": args[1],
                   "severity": args[2], "target": args[3], "reasons": args[4],
                   "started_at": None, "ended_at": None, "peak": "{}"}
            rows.append(row)
            return {"id": pk}
        return None

    async def fetchval(self, query: str, *args):
        await self._guard()
        if "plugin_settings" in query and "select value" in query.lower():
            return self.settings.get((args[0], args[1]))
        return None

    async def execute(self, query: str, *args):
        await self._guard()
        q = query.strip().lower()
        if q.startswith("insert into plugin_settings"):
            # Современная схема: args = (plugin_id, key, value[, value_type])
            # Устаревший формат: args = (plugin_id, value) с literal 'schema_version' в SQL
            if len(args) == 2:
                self.settings[(args[0], "schema_version")] = args[1]
            else:
                self.settings[(args[0], args[1])] = args[2]
        elif q.startswith("update ddos_monitoring_attacks"):
            pass  # достаточно отсутствия исключения
        elif q.startswith("insert into ddos_monitoring_events"):
            self.tables.setdefault("ddos_monitoring_events", []).append(
                {"node_uuid": args[0], "kind": args[1], "payload": args[2]})
        elif q.startswith("insert into ddos_monitoring_node_state"):
            self._inserted_samples.append(args)
        return "OK"


class FakeSettings:
    def __init__(self, db: FakeDB, values: dict | None = None):
        self._values = values or {}

    async def get(self, key: str, default=None):
        return self._values.get(key, default)


class FakeLogger:
    def warning(self, *a, **k): pass
    def info(self, *a, **k): pass
    def exception(self, *a, **k): pass


class FakeCtx:
    def __init__(self, values: dict | None = None):
        self.plugin_id = "ddos-monitoring"
        self.db = FakeDB()
        self.logger = FakeLogger()
        self.settings = FakeSettings(self.db, values)
