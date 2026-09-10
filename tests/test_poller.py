"""Тесты poller: tick-lock, backoff, сохранение среза при сбое, переходы атак."""
from __future__ import annotations

import asyncio
import time

import pytest

from ddos_monitoring.poller import ATTACK_CONFIRMATIONS, DdosPoller
from tests.fakes import FakeLogger


def _verdict(state="attack", severity="high"):
    return {"state": state, "attack_type": "TCP SYN-флуд" if state == "attack" else "",
            "severity": severity, "target": "node",
            "reasons": ["SYN cookies"] if state == "attack" else []}


# ── tick-lock и backoff ──────────────────────────────────────────

async def test_tick_skipped_while_previous_running(monkeypatch):
    p = DdosPoller()
    async with p._tick_lock:
        await p.tick()  # lock занят — тик обязан выйти сразу
    assert p.ticks_ok == 0
    assert p.failures == 0


async def test_backoff_after_failure_respects_next_allowed():
    p = DdosPoller()

    async def boom(log):
        raise RuntimeError("db down")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(p, "_tick_impl", boom)
    await p.tick()
    assert p.failures == 1
    assert p.error == "db_unavailable"
    assert p._next_allowed > time.time()
    # второй тик в окне backoff пропускается без вызова impl
    calls = p.failures
    await p.tick()
    assert p.failures == calls  # не вырос — тик пропущен
    monkeypatch.undo()


async def test_backoff_delay_is_exponential_and_capped():
    p = DdosPoller()
    delays = []
    for _ in range(10):
        p._fail("db_unavailable", FakeLogger(), "x")
        delays.append(p._next_allowed - time.time())
    assert delays[0] < delays[1] < delays[3]
    assert max(delays) <= 301.0  # cap


async def test_success_resets_error_state(monkeypatch):
    p = DdosPoller()
    p._fail("db_unavailable", FakeLogger(), "x")

    async def ok(log):
        p.as_of = time.time()
        p.error = None
        p.failures = 0
        p.ticks_ok += 1

    monkeypatch.setattr(p, "_tick_impl", ok)
    p._next_allowed = 0.0  # сбросить окно backoff
    await p.tick()
    st = p.public_state()
    assert st["error"] is None and not st["stale"]
    assert p.failures == 0


def test_public_state_stale_when_never_ticked():
    st = DdosPoller().public_state()
    assert st["stale"] is True and st["as_of"] is None


# ── переходы состояний ───────────────────────────────────────────

class _Recorder:
    def __init__(self):
        self.events: list[tuple] = []

    async def __call__(self, *a, **k):
        self.events.append(a)


async def _run_verdicts(poller, ctx, log, uuid, verdicts, metrics=None):
    metrics = metrics or {}
    for v in verdicts:
        await poller._apply_verdict(ctx, log, uuid, v, metrics, time.time())


async def test_attack_opens_after_confirmations():
    from tests.fakes import FakeCtx
    ctx = FakeCtx()
    p = DdosPoller()
    rec = _Recorder()
    import ddos_monitoring.data as data
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(data, "add_event", rec)

    async def fake_open(c, uuid, v):
        return 42
    monkeypatch.setattr(data, "open_attack", fake_open)

    await _run_verdicts(p, ctx, ctx.logger, "u1",
                        [_verdict("stable")] + [_verdict("attack")] * ATTACK_CONFIRMATIONS)
    assert len(rec.events) == 1  # открытие после подтверждений
    monkeypatch.undo()


async def test_single_spike_does_not_open_attack():
    from tests.fakes import FakeCtx
    ctx = FakeCtx()
    p = DdosPoller()
    rec = _Recorder()
    import ddos_monitoring.data as data
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(data, "add_event", rec)

    await _run_verdicts(p, ctx, ctx.logger, "u1", [_verdict("stable"), _verdict("attack")])
    assert rec.events == []  # 1 срез < ATTACK_CONFIRMATIONS
    monkeypatch.undo()


async def test_recovery_closes_attack():
    from tests.fakes import FakeCtx
    ctx = FakeCtx()
    p = DdosPoller()
    opened, closed = [], []

    async def fake_open(c, uuid, v):
        opened.append(uuid)
        return 42

    async def fake_close(c, aid, peak):
        closed.append(aid)

    import ddos_monitoring.data as data
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(data, "open_attack", fake_open)
    monkeypatch.setattr(data, "close_attack", fake_close)
    monkeypatch.setattr(data, "add_event", _Recorder())

    seq = [_verdict("stable")] + [_verdict("attack")] * ATTACK_CONFIRMATIONS \
        + [_verdict("stable")] * 3
    await _run_verdicts(p, ctx, ctx.logger, "u1", seq)
    assert opened == ["u1"] and closed == [42]
    assert p._nodes["u1"]["attack_id"] is None
    monkeypatch.undo()


async def _fake_open(ctx):
    async def f(c, uuid, v):
        return 42
    return f
