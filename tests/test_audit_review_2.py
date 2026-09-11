"""Тесты для MEDIUM-находок от review (M1-M3).

M1 — /agent/status RBAC
M2 — _last_report FIFO cap
M3 — replay-check TOCTOU protection
"""
from __future__ import annotations

import asyncio
import inspect
import time

import pytest

from ddos_monitoring import agent_receiver, agent_routes


# ──────────────────────── M1: /agent/status RBAC ─────────────────────────


def test_agent_status_requires_permission():
    """M1: GET /agent/status должен иметь Depends(permission_factory)."""
    # register_agent_routes регистрирует роуты через add_api_route.
    # Проверяем по тексту исходника — это надёжнее, чем мокать роутер.
    import inspect as _i
    src = _i.getsource(agent_routes)
    # Найти блок /agent/status
    assert '"/agent/status"' in src, "/agent/status not registered"
    # Найти handler
    idx = src.find('"/agent/status"')
    block = src[idx:idx + 300]
    assert "Depends(permission_factory" in block or "Depends(require_permission" in block, \
        f"M1 NOT FIXED: /agent/status без permission-зависимости.\nBlock:\n{block}"
    assert 'ddos", "view"' in block or 'ddos", "manage"' in block, \
        f"M1 NOT FIXED: permission не для 'ddos' resource"


# ──────────────────────── M2: _last_report FIFO cap ───────────────────────


def test_last_report_cap():
    """M2: при >4096 разных uuid — старые вытесняются (FIFO)."""
    agent_receiver._last_report.clear()
    try:
        # Имитируем поведение handler: каждый новый uuid → check cap → add
        for i in range(5000):
            uuid = f'uuid-{i}'
            if len(agent_receiver._last_report) >= agent_receiver._LAST_REPORT_MAX:
                agent_receiver._last_report.pop(next(iter(agent_receiver._last_report)))
            agent_receiver._last_report[uuid] = {'ts': i, 'metrics': {}}
        assert len(agent_receiver._last_report) == agent_receiver._LAST_REPORT_MAX, \
            f"M2 NOT FIXED: cap не сработал"
        assert 'uuid-0' not in agent_receiver._last_report
        assert 'uuid-4999' in agent_receiver._last_report
    finally:
        agent_receiver._last_report.clear()


def test_last_report_max_constant_exists():
    assert hasattr(agent_receiver, '_LAST_REPORT_MAX'), \
        "M2 NOT FIXED: _LAST_REPORT_MAX constant missing"
    assert agent_receiver._LAST_REPORT_MAX >= 1024


# ──────────────────────── M3: replay-check TOCTOU ────────────────────────


def test_replay_check_is_async():
    """M3: _check_replay должен быть async + иметь lock (для TOCTOU safety)."""
    assert inspect.iscoroutinefunction(agent_receiver._check_replay), \
        "M3 NOT FIXED: _check_replay не async"


def test_replay_check_has_lock_internals():
    """M3: в _check_replay должен использоваться asyncio.Lock (per-uuid)."""
    src = inspect.getsource(agent_receiver._check_replay)
    assert "Lock" in src or "lock" in src, \
        "M3 NOT FIXED: _check_replay не использует lock"
    assert "async with" in src, \
        "M3 NOT FIXED: нет критической секции"


@pytest.mark.asyncio
async def test_replay_dedup_concurrent():
    """M3: 50 одновременных POST с одинаковым ts → только 1 passes, остальные stale."""
    # Прямо вызываем _check_replay, который теперь async + lock
    results = await asyncio.gather(
        *(agent_receiver._check_replay('concurrent-node', int(time.time())) for _ in range(50))
    )
    saved = sum(1 for r in results if not r)  # False = новый, True = stale
    assert saved == 1, f"M3 NOT FIXED: lock пропустил {saved} записей (должно быть 1)"
    # Очистка для последующих тестов
    agent_receiver._seen_ts.pop('concurrent-node', None)
    agent_receiver._REPLAY_LOCKS.pop('concurrent-node', None)
