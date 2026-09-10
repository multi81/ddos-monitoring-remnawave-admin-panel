"""T5: тесты для закрытия открытой атаки при offline transition.

Что проверяется:
- Если у ноды есть открытая атака (attack_id != None) и она становится offline
  — атака закрывается через data.close_attack()
- entry['attack_id'] сбрасывается в None после закрытия
- Если атаки не было — close_attack НЕ вызывается
- Если close_attack падает — tick не падает, attack_id всё равно сбрасывается
"""
from __future__ import annotations

import importlib
from unittest.mock import AsyncMock

poller_mod = importlib.import_module("ddos_monitoring.poller")


class _FakeCtx:
    """Minimal ctx с настройками для теста offline-attack."""
    settings = type("S", (), {"get": staticmethod(lambda k, default=None: default)})()


def _entry(verdict="attack", attack_id: int | None = 42, peak=None):
    return {
        "verdict": verdict,
        "candidate": "offline",
        "candidate_count": 3,  # >= OFFLINE_CONFIRMATIONS — сразу подтверждает
        "attack_id": attack_id,
        "last_alert": 0.0,
        "peak": peak or {"mbps": 100.0},
        "severity": "high",
    }


async def test_offline_with_open_attack_calls_close():
    # Готовим state: нода с открытой атакой
    p = poller_mod.DdosPoller()
    p._nodes["uuid-attacked"] = _entry(verdict="attack", attack_id=99, peak={"mbps": 250.0})

    # Мокаем data.close_attack и data.add_event и notify.send_state_change
    closed_attacks = []
    events = []
    notifications = []

    async def fake_close(ctx, attack_id, peak):
        closed_attacks.append((attack_id, peak))

    async def fake_add_event(ctx, kind, uuid, payload):
        events.append((kind, uuid))

    async def fake_send_state_change(ctx, uuid, name, *, previous, current, error=None):
        notifications.append((uuid, previous, current["state"]))

    poller_mod.data.close_attack = fake_close
    poller_mod.data.add_event = fake_add_event
    poller_mod.notify.send_state_change = fake_send_state_change

    await p._handle_offline(_FakeCtx(), poller_mod.logger, "uuid-attacked", "attacked-node", 1000.0)

    # 1. close_attack вызван с правильными аргументами
    assert closed_attacks == [(99, {"mbps": 250.0})]
    # 2. attack_id сброшен
    assert p._nodes["uuid-attacked"]["attack_id"] is None
    # 3. verdict = offline
    assert p._nodes["uuid-attacked"]["verdict"] == "offline"
    # 4. события и алерты дошли
    assert ("offline", "uuid-attacked") in events
    assert notifications[0] == ("uuid-attacked", "attack", "offline")


async def test_offline_without_open_attack_no_close():
    """Нода без открытой атаки — close_attack НЕ вызывается."""
    p = poller_mod.DdosPoller()
    p._nodes["uuid-stable"] = _entry(verdict="stable", attack_id=None, peak={"mbps": 5.0})

    closed_attacks = []

    async def fake_close(ctx, attack_id, peak):
        closed_attacks.append((attack_id, peak))

    async def fake_add_event(ctx, kind, uuid, payload):
        pass

    async def fake_send_state_change(ctx, uuid, name, *, previous, current, error=None):
        pass

    poller_mod.data.close_attack = fake_close
    poller_mod.data.add_event = fake_add_event
    poller_mod.notify.send_state_change = fake_send_state_change

    await p._handle_offline(_FakeCtx(), poller_mod.logger, "uuid-stable", "stable-node", 1000.0)

    assert closed_attacks == []  # close_attack НЕ вызван
    assert p._nodes["uuid-stable"]["verdict"] == "offline"


async def test_offline_close_attack_failure_does_not_crash_tick():
    """Если close_attack падает — tick не падает, attack_id всё равно сбрасывается."""
    p = poller_mod.DdosPoller()
    p._nodes["uuid-fail"] = _entry(verdict="attack", attack_id=77, peak={"mbps": 500.0})

    async def boom(ctx, attack_id, peak):
        raise RuntimeError("DB failure")

    async def ok_add_event(ctx, kind, uuid, payload):
        pass

    async def ok_send_state_change(ctx, uuid, name, *, previous, current, error=None):
        pass

    poller_mod.data.close_attack = boom
    poller_mod.data.add_event = ok_add_event
    poller_mod.notify.send_state_change = ok_send_state_change

    # НЕ должно возбуждать исключение
    await p._handle_offline(_FakeCtx(), poller_mod.logger, "uuid-fail", "fail-node", 1000.0)

    # attack_id всё равно сброшен, verdict = offline
    assert p._nodes["uuid-fail"]["attack_id"] is None
    assert p._nodes["uuid-fail"]["verdict"] == "offline"
