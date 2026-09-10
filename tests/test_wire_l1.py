"""Тесты wire L1: интеграция close_stale_attacks в poller tick.

Что проверяется:
- При attack_stale_ttl_s=0 (default, disabled) — close НЕ вызывается
- При attack_stale_ttl_s=7200 — close вызывается с правильным ttl
- При attack_stale_ttl_s=-1 (защита) — НЕ вызывается, не падает
- Закрытие происходит не каждый тик — есть rate-limit (раз в час)
- Тест считает сколько записей было закрыто (для логирования)
- При ошибке DB внутри close — tick не падает, ошибка логируется
"""
import asyncio
import importlib
import time

import pytest

# Гайки (анти-leak между тестами)
import ddos_monitoring.poller as poller_mod


def _make_poller():
    """Свежий DdosPoller — без __init__ side-effects."""
    return poller_mod.DdosPoller()


class _StubSettings:
    """Async-совместимый stub ctx.settings.get(key)"""
    def __init__(self, values: dict):
        self.values = values
        self.calls: list[str] = []
    async def get(self, key: str):
        self.calls.append(key)
        return self.values.get(key)


class _StubDB:
    """Async-совместимый stub ctx.db.fetchval(...)"""
    def __init__(self, closed_count: int = 0, raise_exc: bool = False):
        self.closed_count = closed_count
        self.raise_exc = raise_exc
        self.calls: list[tuple] = []
    async def fetchval(self, sql, *args):
        from unittest.mock import MagicMock
        self.calls.append((sql, args))
        if self.raise_exc:
            raise RuntimeError("simulated DB failure")
        # Возвращаем запись, которая попадёт в cnt в fetchrow
        return self.closed_count


class _StubCtx:
    def __init__(self, settings_vals: dict, closed_count: int = 0,
                 raise_exc: bool = False):
        self.settings = _StubSettings(settings_vals)
        self.db = _StubDB(closed_count=closed_count, raise_exc=raise_exc)


@pytest.mark.asyncio
async def test_wire_ttl_zero_disables_close(monkeypatch):
    """attack_stale_ttl_s=0 → close_stale_attacks НЕ вызывается."""
    p = _make_poller()
    # Ускоряем: ставим _last_stale_close в прошлое, чтобы rate-limit прошёл
    p._last_stale_close = 0.0
    ctx = _StubCtx({"attack_stale_ttl_s": 0})
    called = {"flag": False}

    async def fake_close(*args, **kwargs):
        called["flag"] = True
        return 0
    monkeypatch.setattr(poller_mod.data, "close_stale_attacks", fake_close)

    await p._maybe_close_stale(ctx, poller_mod.logger)
    assert called["flag"] is False, "close_stale_attacks не должен вызываться при ttl=0"


@pytest.mark.asyncio
async def test_wire_ttl_positive_calls_close(monkeypatch):
    """attack_stale_ttl_s=7200 → close вызывается с этим ttl."""
    p = _make_poller()
    p._last_stale_close = 0.0
    ctx = _StubCtx({"attack_stale_ttl_s": 7200})
    captured = {"ttl": None}

    async def fake_close(ctx, *, ttl_s):
        captured["ttl"] = ttl_s
        return 3
    monkeypatch.setattr(poller_mod.data, "close_stale_attacks", fake_close)

    await p._maybe_close_stale(ctx, poller_mod.logger)
    assert captured["ttl"] == 7200


@pytest.mark.asyncio
async def test_wire_ttl_negative_skips(monkeypatch):
    """attack_stale_ttl_s=-1 → защита, close НЕ вызывается."""
    p = _make_poller()
    p._last_stale_close = 0.0
    ctx = _StubCtx({"attack_stale_ttl_s": -1})
    called = {"flag": False}

    async def fake_close(*args, **kwargs):
        called["flag"] = True
        return 0
    monkeypatch.setattr(poller_mod.data, "close_stale_attacks", fake_close)

    await p._maybe_close_stale(ctx, poller_mod.logger)
    assert called["flag"] is False


@pytest.mark.asyncio
async def test_wire_ttl_missing_default_zero(monkeypatch):
    """Если attack_stale_ttl_s отсутствует в settings → дефолт 0 (disabled)."""
    p = _make_poller()
    p._last_stale_close = 0.0
    ctx = _StubCtx({})  # нет ключа вообще
    called = {"flag": False}

    async def fake_close(*args, **kwargs):
        called["flag"] = True
        return 0
    monkeypatch.setattr(poller_mod.data, "close_stale_attacks", fake_close)

    await p._maybe_close_stale(ctx, poller_mod.logger)
    assert called["flag"] is False


@pytest.mark.asyncio
async def test_wire_rate_limit(monkeypatch):
    """Rate-limit: второй вызов в течение часа НЕ выполняется."""
    p = _make_poller()
    # Имитируем что только что выполнили
    p._last_stale_close = time.time()
    ctx = _StubCtx({"attack_stale_ttl_s": 7200})
    called = {"flag": False}

    async def fake_close(*args, **kwargs):
        called["flag"] = True
        return 0
    monkeypatch.setattr(poller_mod.data, "close_stale_attacks", fake_close)

    await p._maybe_close_stale(ctx, poller_mod.logger)
    assert called["flag"] is False, "rate-limit должен блокировать"


@pytest.mark.asyncio
async def test_wire_db_error_doesnt_crash_tick(monkeypatch):
    """Если close упал с DB-ошибкой — tick НЕ падает, ошибка логируется."""
    p = _make_poller()
    p._last_stale_close = 0.0
    ctx = _StubCtx({"attack_stale_ttl_s": 7200})

    async def fake_close_raising(*args, **kwargs):
        raise RuntimeError("simulated DB failure")
    monkeypatch.setattr(poller_mod.data, "close_stale_attacks",
                        fake_close_raising)

    # Не должно бросить исключение
    await p._maybe_close_stale(ctx, poller_mod.logger)


@pytest.mark.asyncio
async def test_wire_returns_count_for_logging(monkeypatch):
    """_maybe_close_stale возвращает count для логирования."""
    p = _make_poller()
    p._last_stale_close = 0.0
    ctx = _StubCtx({"attack_stale_ttl_s": 7200})

    async def fake_close(*args, **kwargs):
        return 7
    monkeypatch.setattr(poller_mod.data, "close_stale_attacks", fake_close)

    n = await p._maybe_close_stale(ctx, poller_mod.logger)
    assert n == 7
