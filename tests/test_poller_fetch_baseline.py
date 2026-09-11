"""Тест _fetch_baseline: правильный SQL, обработка отсутствия контекста."""
from __future__ import annotations

import asyncio
import pytest


class FakeRow(dict):
    def __getattr__(self, k):
        return self.get(k)


class FakeDB:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    async def fetch(self, sql, *args):
        self.calls.append((sql, args))
        return self.rows


class FakeCtx:
    def __init__(self, rows):
        self.db = FakeDB(rows)


def test_fetch_baseline_returns_dict(monkeypatch):
    """_fetch_baseline должен вернуть {metric: value} dict."""
    import ddos_monitoring.poller as P

    rows = [
        FakeRow({"metric": "rx_bps", "baseline_value": 50_000_000.0}),
        FakeRow({"metric": "rx_pps", "baseline_value": 5000.0}),
    ]
    ctx = FakeCtx(rows)
    monkeypatch.setattr(P, "_ctx_ref", lambda: ctx)

    poller = P.DdosPoller()
    result = asyncio.run(poller._fetch_baseline("9167ddba-..."))

    assert result is not None
    assert result["rx_bps"] == 50_000_000.0
    assert result["rx_pps"] == 5000.0
    assert len(ctx.db.calls) == 1
    sql, args = ctx.db.calls[0]
    assert "ddos_monitoring_node_baseline" in sql
    assert args == ("9167ddba-...",)


def test_fetch_baseline_empty(monkeypatch):
    """Если ноды нет в baseline таблице — возвращает None."""
    import ddos_monitoring.poller as P
    ctx = FakeCtx([])
    monkeypatch.setattr(P, "_ctx_ref", lambda: ctx)

    poller = P.DdosPoller()
    result = asyncio.run(poller._fetch_baseline("00000000-..."))
    assert result is None


def test_fetch_baseline_no_ctx(monkeypatch):
    """Если ctx недоступен — возвращает None (не ломает tick)."""
    import ddos_monitoring.poller as P
    monkeypatch.setattr(P, "_ctx_ref", lambda: None)
    poller = P.DdosPoller()
    result = asyncio.run(poller._fetch_baseline("..."))
    assert result is None
