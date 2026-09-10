"""Фаза 2: интеграция notify в тик — алерты при сменах состояния, hourly summary."""

import pytest

from ddos_monitoring.poller import DdosPoller
from tests.fakes import FakeCtx, FakeLogger


class NotifySpyCtx(FakeCtx):
    def __init__(self):
        super().__init__()
        self.notifies = []

    async def panel_notify(self, **kwargs):
        self.notifies.append(kwargs)


def _mk_poller_with_rows(rows):
    p = DdosPoller()
    return p


@pytest.mark.asyncio
async def test_offline_transition_sends_alert_and_marks_entry(monkeypatch):
    """Нода пропала из срезов → после OFFLINE_CONFIRMATIONS тиков — offline-алерт."""
    from ddos_monitoring import poller as P

    ctx = NotifySpyCtx()
    log = FakeLogger()
    pol = DdosPoller()
    pol._nodes["n1"] = {"verdict": "stable", "candidate": "", "candidate_count": 0,
                        "attack_id": None, "last_alert": 0.0, "peak": {},
                        "severity": "normal"}
    sent = []

    async def fake_state_change(ctx_, uuid, name, **kw):
        sent.append((uuid, kw))

    monkeypatch.setattr(P.notify, "send_state_change", fake_state_change)
    await pol._handle_offline(ctx, log, "n1", "de2", now=100.0)
    assert sent == []  # первый тик — только счётчик

    # подтверждение за 2-й тик
    await pol._handle_offline(ctx, log, "n1", "de2", now=115.0)
    assert len(sent) == 1
    assert sent[0][1]["current"]["state"] == "offline"
    entry = pol._nodes["n1"]
    assert entry["verdict"] == "offline"
