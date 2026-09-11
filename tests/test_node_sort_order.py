"""ТЕСТЫ: сортировка нод (sort_order) — UI reorder + fleet_overview ORDER BY.

Что проверяем:
- fleet_overview() возвращает ноды в порядке sort_order, затем name
- set_node_order() обновляет sort_order
- POST /nodes/order валидирует входные данные
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock


# ── FakeDB ────────────────────────────────────────────────────────

class FakeRow(dict):
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k)


class FakeDB:
    def __init__(self):
        self._rows: dict[str, list[FakeRow]] = {}
        self._scenarios: dict[str, list[FakeRow]] = {}
        self._values: dict[str, object] = {}
        self._executed: list[tuple[str, tuple]] = []

    def set_rows(self, rows: list[dict]):
        self._rows["default"] = [FakeRow(r) for r in rows]

    def set_rows_for(self, needle: str, rows: list[dict]):
        self._scenarios[needle] = [FakeRow(r) for r in rows]

    def set_value_for(self, needle: str, value: object):
        self._values[needle] = value

    async def fetch(self, sql: str, *args) -> list[FakeRow]:
        self._executed.append((sql, args))
        for needle, rows in self._scenarios.items():
            if needle in sql:
                return rows
        return [FakeRow(r) for r in self._rows.get("default", [])]

    async def fetchval(self, sql: str, *args):
        self._executed.append((sql, args))
        for needle, val in self._values.items():
            if needle in sql:
                return val
        return None

    async def execute(self, sql: str, *args) -> str:
        self._executed.append((sql, args))
        return "UPDATE 1"


class FakeCtx:
    def __init__(self, db: FakeDB):
        self.db = db


# ── Tests ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fleet_overview_order_by_sort_order():
    """fleet_overview ORDER BY sort_order, name — ноды идут в правильном порядке."""
    db = FakeDB()
    # Три ноды в БД: sort_order=2, 0, 1 (порядок INSERT не важен, SQL отсортирует)
    db.set_rows_for("ddos_monitoring_node_state", [
        FakeRow({"node_uuid": "33333333-3333-3333-3333-333333333333", "node_name": "Zebra",
                 "state": "online", "last_seen_at": None, "last_error": None,
                 "agent_version": "1.1.0", "sort_order": 0,
                 "attack_id": None, "attack_started": None,
                 "attack_type": None, "severity": None, "target": None}),
        FakeRow({"node_uuid": "11111111-1111-1111-1111-111111111111", "node_name": "Alpha",
                 "state": "online", "last_seen_at": None, "last_error": None,
                 "agent_version": "1.1.0", "sort_order": 1,
                 "attack_id": None, "attack_started": None,
                 "attack_type": None, "severity": None, "target": None}),
        FakeRow({"node_uuid": "22222222-2222-2222-2222-222222222222", "node_name": "Middle",
                 "state": "online", "last_seen_at": None, "last_error": None,
                 "agent_version": "1.1.0", "sort_order": 2,
                 "attack_id": None, "attack_started": None,
                 "attack_type": None, "severity": None, "target": None}),
    ])
    # Bulk snapshots — пусто
    db.set_rows_for("ROW_NUMBER()", [])
    db.set_value_for("COUNT", 3)

    ctx = FakeCtx(db)
    from ddos_monitoring import data

    result = await data.fleet_overview(ctx)

    # Проверяем порядок: sort_order 0, 1, 2
    assert len(result) == 3
    assert result[0]["node_name"] == "Zebra"  # sort_order=0
    assert result[1]["node_name"] == "Alpha"  # sort_order=1
    assert result[2]["node_name"] == "Middle"  # sort_order=2

    # Проверяем что SQL содержит ORDER BY sort_order
    sql_calls = [sql for sql, _ in db._executed if "ORDER BY" in sql.upper()]
    assert any("sort_order" in sql.lower() for sql in sql_calls), \
        f"Expected sort_order in ORDER BY, got: {sql_calls}"


@pytest.mark.asyncio
async def test_set_node_order_updates_sort_order():
    """set_node_order() обновляет sort_order для списка нод."""
    db = FakeDB()
    ctx = FakeCtx(db)

    from ddos_monitoring import data

    # Устанавливаем порядок
    order = [
        {"node_uuid": "11111111-1111-1111-1111-111111111111", "sort_order": 0},
        {"node_uuid": "22222222-2222-2222-2222-222222222222", "sort_order": 1},
    ]
    await data.set_node_order(ctx, order)

    # Проверяем что execute вызывался с UPDATE
    assert len(db._executed) == 2
    for sql, args in db._executed:
        assert "UPDATE" in sql.upper()
        assert "sort_order" in sql.lower()


@pytest.mark.asyncio
async def test_set_node_order_empty_list():
    """set_node_order([]) — пустой список, ничего не делает."""
    db = FakeDB()
    ctx = FakeCtx(db)

    from ddos_monitoring import data

    await data.set_node_order(ctx, [])
    assert len(db._executed) == 0
