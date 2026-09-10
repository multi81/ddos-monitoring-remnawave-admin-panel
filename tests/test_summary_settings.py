"""TDD: настройки авто-саммари (вкл/выкл + интервал в часах) из plugin_settings."""

import pytest

from ddos_monitoring.poller import DdosPoller


class S:
    def __init__(self, data):
        self._d = dict(data)

    async def get(self, k, default=None):
        return self._d.get(k, default)


class Ctx:
    def __init__(self, data=None):
        self.settings = S(data or {})


class Log:
    def warning(self, *a, **k):
        pass


def test_summary_defaults_hourly_enabled():
    p = DdosPoller()
    enabled, interval = p._summary_cfg({})
    assert enabled is True
    assert interval == 3600.0


def test_summary_disabled_via_settings():
    p = DdosPoller()
    enabled, interval = p._summary_cfg({"summary_enabled": False})
    assert enabled is False


def test_summary_interval_hours_from_settings():
    p = DdosPoller()
    enabled, interval = p._summary_cfg({"summary_interval_h": 6})
    assert enabled is True and interval == 6 * 3600.0


def test_summary_interval_invalid_falls_back():
    p = DdosPoller()
    enabled, interval = p._summary_cfg({"summary_interval_h": "abc"})
    assert interval == 3600.0
    enabled, interval = p._summary_cfg({"summary_interval_h": -2})
    assert interval == 3600.0


@pytest.mark.asyncio
async def test_maybe_summary_skips_when_disabled(monkeypatch):
    from ddos_monitoring import poller as P, notify

    called = []

    async def fake_send(ctx, rows):
        called.append(rows)

    monkeypatch.setattr(P.notify, "send_summary", fake_send)
    pol = DdosPoller()
    await pol._maybe_summary(Ctx({"summary_enabled": False}), Log(), {}, now=100.0)
    # первый тик, но summary_enabled=False → не отправляем
    assert called == []
    assert pol._startup_summary_sent is True
