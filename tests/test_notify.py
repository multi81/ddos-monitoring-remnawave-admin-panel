"""Фаза 2: отправка алертов через штатный notification_service панели."""

import pytest

from ddos_monitoring import notify


class FakeCtx:
    def __init__(self):
        self.sent = []
        self.settings = _Settings({})

    async def panel_notify(self, **kwargs):
        self.sent.append(kwargs)
        return True


class _Settings:
    def __init__(self, data):
        self._data = dict(data)

    async def get(self, key, default=None):
        return self._data.get(key, default)


def _assessment(state="attack", severity="critical", attack_type="TCP SYN-флуд",
                reasons=("входящий трафик", "SYN cookies"), metrics=None):
    return {
        "state": state, "severity": severity, "attack_type": attack_type,
        "reasons": list(reasons), "target": "node",
        "metrics": metrics or {"net_rx_bps": 900_000_000, "net_rx_pps": 120_000,
                               "conntrack_count": 50_000, "conntrack_max": 65_536},
    }


@pytest.mark.asyncio
async def test_attack_alert_sent_with_severity_and_metrics():
    ctx = FakeCtx()
    await notify.send_state_change(ctx, "node-1", "MTVPN · de2",
                                  previous="stable", current=_assessment())
    assert len(ctx.sent) == 1
    msg = ctx.sent[0]
    assert msg["severity"] == "critical"  # fallback передаёт исходный severity, маппинг — в tg_bot.send
    body = msg["body"]
    assert "DDoS" in body and "MTVPN · de2" in body
    assert "TCP SYN-флуд" in body
    assert "входящий трафик" in body


@pytest.mark.asyncio
async def test_recovery_message_includes_duration_and_peak():
    ctx = FakeCtx()
    peak = {"net_rx_bps": 1_500_000_000, "net_rx_pps": 200_000}
    await notify.send_state_change(ctx, "n", "nodeA", previous="attack",
                                   current={"state": "stable"},
                                   duration_s=125.0, peak=peak)
    body = ctx.sent[0]["body"]
    assert "завершилась" in body
    assert "2 мин" in body          # 125s ≈ 2 мин
    assert "1500" in body           # пиковый RX Мбит/с


@pytest.mark.asyncio
async def test_offline_and_online():
    ctx = FakeCtx()
    await notify.send_state_change(ctx, "n", "X", previous="stable",
                                   current={"state": "offline"}, error="no telemetry")
    assert "Нет связи" in ctx.sent[0]["body"]
    await notify.send_state_change(ctx, "n", "X", previous="offline",
                                   current={"state": "stable"})
    assert "восстановлена" in ctx.sent[1]["body"]


@pytest.mark.asyncio
async def test_load_and_health_states():
    ctx = FakeCtx()
    await notify.send_state_change(ctx, "n", "Y", previous="stable",
                                   current=_assessment(state="load",
                                                       reasons=["CPU", "RAM"]))
    assert "Высокая нагрузка" in ctx.sent[0]["body"]
    await notify.send_state_change(ctx, "n", "Y", previous="stable",
                                   current=_assessment(state="health",
                                                       reasons=["Диск"]))
    assert "требует внимания" in ctx.sent[1]["body"]


@pytest.mark.asyncio
async def test_stable_to_stable_notifies_nothing():
    ctx = FakeCtx()
    await notify.send_state_change(ctx, "n", "Z", previous="stable",
                                   current={"state": "stable"})
    assert ctx.sent == []


@pytest.mark.asyncio
async def test_notification_failure_is_swallowed():
    class FailingSettings:
        async def get(self, key, default=None):
            return None  # нет tg_bot_token → fallback

    class Failing:
        settings = FailingSettings()

        async def panel_notify(self, **kw):
            raise RuntimeError("tg down")

    # не должно бросить: буферизация/тихий отказ — лог в poller
    await notify.send_state_change(Failing(), "n", "Q", previous="stable",
                                   current=_assessment())


@pytest.mark.asyncio
async def test_summary_lists_all_nodes_with_counts():
    ctx = FakeCtx()
    rows = [
        ("a", "de2", "attack", "TCP SYN-флуд", ["входящий трафик"]),
        ("b", "nl3", "stable", "", []),
        ("c", "fr1", "load", "", ["CPU"]),
        ("d", "ru4", "offline", "", []),
    ]
    await notify.send_summary(ctx, rows)
    body = ctx.sent[0]["body"]
    assert "Состояние инфраструктуры" in body
    assert "de2" in body and "стабильно" in body and "нет связи" in body
    assert "Итого" in body


@pytest.mark.asyncio
async def test_repeated_attack_message():
    ctx = FakeCtx()
    await notify.send_state_change(ctx, "n", "R", previous="attack",
                                   current=_assessment(), repeated=True)
    assert "продолжается" in ctx.sent[0]["body"]
