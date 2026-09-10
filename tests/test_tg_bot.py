"""Фаза 2.5: свой Telegram-бот плагина (Bot API), fallback на panel_notify."""

import pytest

from ddos_monitoring import tg_bot
from ddos_monitoring.notify import send_state_change, send_summary


class SettingsFake:
    def __init__(self, data):
        self._data = dict(data)
        self.saved = {}

    async def get(self, key, default=None):
        return self._data.get(key, default)

    async def set(self, key, value):
        self._data[key] = value
        self.saved[key] = value


class CtxFake:
    def __init__(self, settings=None):
        self.settings = SettingsFake(settings or {})
        self.posted = []          # вызовы Bot API
        self.panel = []           # fallback panel_notify

    async def panel_notify(self, **kw):
        self.panel.append(kw)


@pytest.mark.asyncio
async def test_custom_bot_sends_via_bot_api(monkeypatch):
    ctx = CtxFake({"tg_bot_token": "123:ABC", "tg_chat_ids": "111,222"})
    seen = []

    async def fake_api(token, method, payload):
        seen.append((token, method, payload))
        return {"ok": True}

    monkeypatch.setattr(tg_bot, "_bot_api", fake_api)
    await tg_bot.send(ctx, "Тест <b>жирный</b>", severity="warning")
    assert len(seen) == 2  # два chat_id
    token, method, payload = seen[0]
    assert token == "123:ABC" and method == "sendMessage"
    assert payload["chat_id"] == 111 and "Тест" in payload["text"]
    assert ctx.panel == []  # fallback не нужен


@pytest.mark.asyncio
async def test_fallback_to_panel_notify_when_no_token():
    ctx = CtxFake({})
    await tg_bot.send(ctx, "Привет", severity="error")
    assert len(ctx.panel) == 1 and ctx.panel[0]["severity"] == "error"


@pytest.mark.asyncio
async def test_bot_failure_swallowed(monkeypatch):
    ctx = CtxFake({"tg_bot_token": "t", "tg_chat_ids": "1"})

    async def fail(*a, **kw):
        raise RuntimeError("network down")

    monkeypatch.setattr(tg_bot, "_bot_api", fail)
    await tg_bot.send(ctx, "x")  # не бросает


@pytest.mark.asyncio
async def test_notify_module_routes_through_custom_bot(monkeypatch):
    """send_state_change/send_summary используют tg_bot.send (свой бот)."""
    ctx = CtxFake({"tg_bot_token": "T", "tg_chat_ids": "9"})
    calls = []

    async def fake_send(ctx_, text, severity="info"):
        calls.append((text, severity))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    await send_state_change(ctx, "n", "NodeA", previous="stable",
                            current={"state": "offline"}, error="x")
    assert len(calls) == 1 and "NodeA" in calls[0][0]
    await send_summary(ctx, [("u", "de2", "stable", "", [])])
    assert "Состояние инфраструктуры" in calls[1][0]


def test_mask_token_for_ui():
    assert tg_bot.mask_token("123456:AAGAQ-xyz") == "123456:AAGAQ…"
    assert tg_bot.mask_token("") == ""
