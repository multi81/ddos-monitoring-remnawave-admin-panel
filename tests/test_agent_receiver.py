"""Тесты для agent_receiver: replay-protection + instance-vs-class state.

Проверки:
- _check_replay: отклоняет уже виденный ts (async, lock-protected)
- _check_replay: НЕ отклоняет ts, отстоящий на > STALE_WINDOW_S (будущее)
- _check_replay: чистит устаревшие ts
- _check_replay: FIFO-eviction по uuid при _SEEN_MAX_UUIDS
- AgentReceiver._tables_ready: instance (не class) — per-request
- _last_report: FIFO cap при переполнении
"""
from __future__ import annotations

import asyncio
import importlib
import time

import pytest

ar = importlib.import_module("ddos_monitoring.agent_receiver")


def _reset_seen():
    """Изолированное состояние между тестами."""
    ar._seen_ts.clear()
    ar._last_report.clear()
    ar._REPLAY_LOCKS.clear()


@pytest.mark.asyncio
async def test_check_replay_new_uuid_first_ts():
    _reset_seen()
    ts = int(time.time())
    assert await ar._check_replay("uuid-new", ts) is False
    assert ts in ar._seen_ts.get("uuid-new", set())


@pytest.mark.asyncio
async def test_check_replay_duplicate_ts():
    _reset_seen()
    ts = int(time.time())
    await ar._check_replay("uuid-dup", ts)
    assert await ar._check_replay("uuid-dup", ts) is True


@pytest.mark.asyncio
async def test_check_replay_old_ts_not_counted_as_duplicate():
    """Старый ts в set'е чистится cutoff'ом — новый ts не считается дубликатом."""
    _reset_seen()
    old_ts = int(time.time()) - 1000
    new_ts = int(time.time())
    await ar._check_replay("uuid-clean", old_ts)
    assert await ar._check_replay("uuid-clean", new_ts) is False


@pytest.mark.asyncio
async def test_check_replay_future_ts_not_stored():
    """OOM-атака: ts = now + very_large. Не должны сохранять в set."""
    _reset_seen()
    far_future_ts = int(time.time()) + 10**9
    result = await ar._check_replay("uuid-future", far_future_ts)
    assert result is False
    s = ar._seen_ts.get("uuid-future", set())
    assert far_future_ts not in s
    assert await ar._check_replay("uuid-future", far_future_ts) is False


@pytest.mark.asyncio
async def test_check_replay_max_uuids_fifo_eviction():
    """Превышение _SEEN_MAX_UUIDS → вытеснение самого старого uuid."""
    _reset_seen()
    for i in range(ar._SEEN_MAX_UUIDS):
        await ar._check_replay(f"uuid-{i}", 0)
    assert len(ar._seen_ts) == ar._SEEN_MAX_UUIDS
    await ar._check_replay("uuid-new", 1)
    assert len(ar._seen_ts) == ar._SEEN_MAX_UUIDS
    assert "uuid-0" not in ar._seen_ts


@pytest.mark.asyncio
async def test_concurrent_replay_dedup():
    """50 одновременных запросов с одинаковым ts → только 1 проходит."""
    _reset_seen()
    ts = int(time.time())
    results = await asyncio.gather(
        *(ar._check_replay("concurrent-node", ts) for _ in range(50))
    )
    saved = sum(1 for r in results if not r)
    assert saved == 1, f"lock не сработал: {saved} прошло"


def test_node_secret_removed():
    """node_secret удалён из API."""
    assert not hasattr(ar, "node_secret"), "node_secret остался"


def test_receiver_tables_ready_is_instance_not_class():
    """_tables_ready должен быть instance-атрибутом."""
    assert not hasattr(ar.AgentReceiver, "_tables_ready") or \
        "_tables_ready" not in ar.AgentReceiver.__dict__, \
        "_tables_ready остался class-level"
    r1 = ar.AgentReceiver(ctx=None)
    r2 = ar.AgentReceiver(ctx=None)
    assert hasattr(r1, "_tables_ready")
    assert hasattr(r2, "_tables_ready")
    r1._tables_ready = True
    assert r2._tables_ready is False


def test_last_report_cap_at_max():
    """M2: _last_report cap при переполнении → FIFO eviction."""
    _reset_seen()
    # Заполним больше лимита
    for i in range(ar._LAST_REPORT_MAX + 100):
        ar._save_last_report(f"uuid-{i}", {"metrics": {}, "agent_version": "v"}, int(time.time()))
    assert len(ar._last_report) == ar._LAST_REPORT_MAX
    assert "uuid-0" not in ar._last_report
    assert f"uuid-{ar._LAST_REPORT_MAX + 99}" in ar._last_report
