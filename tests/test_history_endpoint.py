"""ТЕСТЫ: drill-down endpoint GET /history?node_uuid=...&range=1h (задача handoff.md #4).

Что проверяем:
- history_series() возвращает {node_uuid, range, step_s, series, ts}
- series: {cpu_pct, ram_pct, syn_recv, established, rx_mbps}
- ts: ISO 8601 строки
- range validation: невалидный range → ValueError
- отсутствие данных → пустые series

NOT WIRED: Нет routes.py, нет реальной БД.
"""
from __future__ import annotations

import pytest


def _row(**kwargs) -> dict:
    return FakeRow(kwargs)


class FakeRow(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class FakeDB:
    def __init__(self):
        self.calls: list[tuple[str, str, tuple]] = []
        self._scenarios: dict[str, list[FakeRow]] = {}

    def set_rows_for(self, sql_contains: str, rows: list[FakeRow]):
        self._scenarios[sql_contains] = rows

    async def fetch(self, sql: str, *args):
        self.calls.append(("fetch", sql[:80], args))
        for needle, rows in self._scenarios.items():
            if needle in sql:
                return rows
        return []


class FakeCtx:
    def __init__(self, db: FakeDB):
        self.db = db


# ────────────────────────────────────────────────────────────────────
# Тесты
# ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_history_series_returns_correct_structure():
    """history_series() возвращает полную структуру с series и ts."""
    db = FakeDB()
    node_uuid = "aaaaaaaa-1111-1111-1111-111111111111"

    # 3 снапшота за последний час (ts в миллисекундах)
    db.set_rows_for("agent_snapshots", [
        _row(ts=1700000000000, cpu_pct=22.5, ram_pct=41.0, syn_recv=124, established=840, rx_bps=312_700_000),
        _row(ts=1700000060000, cpu_pct=24.0, ram_pct=41.2, syn_recv=130, established=850, rx_bps=320_100_000),
        _row(ts=1700000120000, cpu_pct=23.1, ram_pct=41.5, syn_recv=128, established=845, rx_bps=315_000_000),
    ])

    ctx = FakeCtx(db)
    from ddos_monitoring import data

    result = await data.history_series(ctx, node_uuid, "1h")

    assert result["node_uuid"] == node_uuid
    assert result["range"] == "1h"
    assert result["step_s"] == 60  # интервал между снапшотами = 60s
    assert len(result["ts"]) == 3
    assert len(result["series"]["cpu_pct"]) == 3
    assert result["series"]["cpu_pct"][0] == 22.5
    assert result["series"]["rx_mbps"][0] == pytest.approx(312.7)


@pytest.mark.asyncio
async def test_history_series_empty_when_no_data():
    """Без снапшотов: пустые series."""
    db = FakeDB()
    db.set_rows_for("agent_snapshots", [])

    ctx = FakeCtx(db)
    from ddos_monitoring import data

    result = await data.history_series(ctx, "aaaaaaaa-1111-1111-1111-111111111111", "1h")

    assert result["series"]["cpu_pct"] == []
    assert result["ts"] == []


@pytest.mark.asyncio
async def test_history_series_invalid_range():
    """Невалидный range → ValueError."""
    from ddos_monitoring import data

    db = FakeDB()
    ctx = FakeCtx(db)

    with pytest.raises(ValueError, match="range"):
        await data.history_series(ctx, "aaaaaaaa-1111-1111-1111-111111111111", "bad")


@pytest.mark.asyncio
async def test_history_series_range_parsing():
    """Парсинг range: 1h=3600s, 24h=86400s."""
    from ddos_monitoring.data import _parse_range_seconds

    assert _parse_range_seconds("1h") == 3600
    assert _parse_range_seconds("6h") == 21600
    assert _parse_range_seconds("24h") == 86400
    assert _parse_range_seconds("7d") == 604800


@pytest.mark.asyncio
async def test_history_series_invalid_uuid():
    """Невалидный UUID → ValueError."""
    from ddos_monitoring import data

    db = FakeDB()
    ctx = FakeCtx(db)

    with pytest.raises(ValueError, match="node_uuid"):
        await data.history_series(ctx, "not-a-uuid", "1h")
