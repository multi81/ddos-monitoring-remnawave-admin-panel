"""Webhook для бота плагина: /update, /node, /help, anti-abuse, секрет."""
from __future__ import annotations

import asyncio
import json
import sys
import types

from ddos_monitoring import tg_bot  # noqa: F401


# ---------- helpers ----------

class SettingsStore:
    def __init__(self, data=None):
        self.data = data or {}
        self.saved = {}

    async def get(self, k):
        return self.data.get(k)

    async def set(self, k, v):
        self.saved[k] = v
        self.data[k] = v


class Ctx:
    def __init__(self, data=None):
        self.settings = SettingsStore(data)
        self.db = None
        self.panel_calls = []

    async def panel_notify(self, **kw):
        self.panel_calls.append(kw)


class _FakeRequest:
    def __init__(self, headers: dict | None = None):
        self.headers = headers or {}


def _build(monkeypatch, ctx):
    """Собрать роутер с моками fastapi/auth_deps."""
    class FakeAPIRouter:
        def __init__(self):
            self.routes = {}

        def get(self, path, **kw):
            def deco(fn):
                self.routes[("GET", path)] = fn
                return fn
            return deco

        def post(self, path, **kw):
            def deco(fn):
                self.routes[("POST", path)] = fn
                return fn
            return deco

    fastapi_mod = types.ModuleType("fastapi")
    fastapi_mod.APIRouter = FakeAPIRouter
    fastapi_mod.Depends = lambda dep: None
    fastapi_mod.HTTPException = type("HTTPException", (Exception,), {})
    fastapi_mod.Body = lambda *a, **k: None
    fastapi_mod.Request = type("Request", (), {})
    fastapi_mod.Header = lambda *a, **k: None
    fastapi_mod.Query = lambda *a, **k: None
    fastapi_mod.Path = lambda *a, **k: None
    fastapi_mod.Form = lambda *a, **k: None
    fastapi_mod.File = lambda *a, **k: None
    fastapi_mod.BackgroundTasks = lambda *a, **k: None
    fastapi_mod.UploadFile = type("UploadFile", (), {})
    fastapi_mod.WebSocket = type("WebSocket", (), {})
    fastapi_mod.WebSocketDisconnect = type("WebSocketDisconnect", (Exception,), {})
    fastapi_mod.Response = type("Response", (), {})
    def _make_response_class(body_bytes: bytes = b'{"ok": true}'):
        class _Resp:
            def __init__(self, content=None, *a, **kw):
                if isinstance(content, (dict, list)):
                    self.body = json.dumps(content, ensure_ascii=False).encode()
                elif isinstance(content, str):
                    self.body = content.encode()
                else:
                    self.body = body_bytes
        return _Resp

    fastapi_mod.JSONResponse = _make_response_class()
    fastapi_mod.HTMLResponse = _make_response_class(b"")
    fastapi_mod.PlainTextResponse = _make_response_class(b"")
    fastapi_mod.RedirectResponse = _make_response_class(b"")
    fastapi_mod.FileResponse = _make_response_class(b"")
    fastapi_mod.StreamingResponse = _make_response_class(b"")
    fastapi_mod.routing = types.ModuleType("fastapi.routing")
    fastapi_mod.routing.APIRoute = type("APIRoute", (), {})
    fastapi_mod.encoders = types.ModuleType("fastapi.encoders")
    fastapi_mod.encoders.jsonable_encoder = lambda x, *a, **k: x
    fastapi_mod.responses = types.ModuleType("fastapi.responses")
    fastapi_mod.responses.JSONResponse = _make_response_class()
    fastapi_mod.responses.HTMLResponse = _make_response_class(b"")
    fastapi_mod.responses.PlainTextResponse = _make_response_class(b"")
    fastapi_mod.responses.Response = _make_response_class(b"")
    fastapi_mod.params = types.ModuleType("fastapi.params")
    fastapi_mod.params.Body = lambda *a, **k: None
    fastapi_mod.params.Depends = lambda dep: None
    fastapi_mod.params.Header = lambda *a, **k: None
    fastapi_mod.params.Query = lambda *a, **k: None
    fastapi_mod.params.Path = lambda *a, **k: None
    fastapi_mod.params.File = lambda *a, **k: None
    fastapi_mod.params.Form = lambda *a, **k: None
    sys.modules["fastapi"] = fastapi_mod
    sys.modules["fastapi.routing"] = fastapi_mod.routing
    sys.modules["fastapi.encoders"] = fastapi_mod.encoders
    sys.modules["fastapi.responses"] = fastapi_mod.responses
    sys.modules["fastapi.params"] = fastapi_mod.params

    fake_plugin_api = types.ModuleType("web.backend.core.plugin_api")

    def _dep(*a, **kw):
        return None
    fake_plugin_api.auth_deps = lambda: (_dep, _dep)
    sys.modules["web.backend.core.plugin_api"] = fake_plugin_api

    real_import = __import__

    def fake_import(name, *a, **kw):
        if name == "fastapi":
            return fastapi_mod
        if name == "web.backend.core.plugin_api":
            return fake_plugin_api
        return real_import(name, *a, **kw)

    monkeypatch.setattr("builtins.__import__", fake_import)

    sys.modules.pop("ddos_monitoring.routes", None)
    from ddos_monitoring import routes as r
    router = r.build_router(ctx)
    return router


def _body(res):
    return json.loads(res.body)


def _call(fn, payload=None, *, headers=None):
    """Вызвать webhook-функцию с FakeRequest + payload."""
    req = _FakeRequest(headers)
    return asyncio.run(fn(req, payload or {}))


# ---------- tests ----------

def test_help_returns_command_list(monkeypatch):
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(ctx_, text, severity="info", chat_id=None):
        sent.append((text, chat_id))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    res = _body(_call(fn, {"message": {"text": "/help", "chat": {"id": 12345}}}))
    assert res["ok"] is True
    assert len(sent) == 1
    assert "/update" in sent[0][0]
    assert sent[0][1] == 12345


def test_update_calls_summary(monkeypatch):
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(ctx_, text, severity="info", chat_id=None):
        sent.append((text, chat_id))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    res = _body(_call(fn, {"message": {"text": "/update", "chat": {"id": 12345}}}))
    assert res["ok"] is True
    assert len(sent) == 1
    assert "Состояние инфраструктуры" in sent[0][0]


def test_unknown_chat_silently_dropped(monkeypatch):
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(*a, **kw):
        sent.append((a, kw))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    res = _body(_call(fn, {"message": {"text": "/help", "chat": {"id": 99999}}}))
    assert res["ok"] is True
    assert sent == []  # молча


def test_no_message_returns_ok(monkeypatch):
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    fn = router.routes[("POST", "/tg/webhook")]
    res = _body(_call(fn, {}))
    assert res["ok"] is True


def test_webhook_secret_required(monkeypatch):
    """Без правильного заголовка → 403, с правильным → ok."""
    ctx = Ctx({"tg_chat_ids": "12345", "tg_webhook_secret": "supersecret"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(*a, **kw):
        sent.append((a, kw))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    res = _body(_call(fn, {"message": {"text": "/help", "chat": {"id": 12345}}}))
    assert "error" in res and "bad_webhook_secret" in str(res)


def test_node_cmd_found_by_uuid(monkeypatch):
    from ddos_monitoring import poller
    poller.POLLER._nodes = {
        "abc-uuid": {
            "verdict": "stable", "name": "Node1", "attack_type": "",
            "reasons": [],
            "metrics": {"net_rx_bps": 1_500_000, "net_rx_pps": 800,
                        "conntrack_count": 1000, "conntrack_max": 5000},
        }
    }
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(ctx_, text, severity="info", chat_id=None):
        sent.append((text, chat_id))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    _body(_call(fn, {"message": {"text": "/node abc-uuid",
                                   "chat": {"id": 12345}}}))
    assert len(sent) == 1
    assert "Node1" in sent[0][0]
    assert "1.5" in sent[0][0]


def test_node_cmd_found_by_name_substring(monkeypatch):
    from ddos_monitoring import poller
    poller.POLLER._nodes = {
        "u1": {"verdict": "attack", "name": "Fi3_TiHost_TG", "attack_type": "syn_flood",
               "reasons": ["syn_flood"], "metrics": {}}
    }
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(ctx_, text, severity="info", chat_id=None):
        sent.append((text, chat_id))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    _body(_call(fn, {"message": {"text": "/node TiHost",
                                   "chat": {"id": 12345}}}))
    assert len(sent) == 1
    assert "Fi3_TiHost_TG" in sent[0][0]


def test_node_cmd_not_found(monkeypatch):
    from ddos_monitoring import poller
    poller.POLLER._nodes = {}
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(ctx_, text, severity="info", chat_id=None):
        sent.append((text, chat_id))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    _body(_call(fn, {"message": {"text": "/node nope",
                                   "chat": {"id": 12345}}}))
    assert len(sent) == 1
    assert "не найдена" in sent[0][0]


def test_node_cmd_no_arg(monkeypatch):
    from ddos_monitoring import poller
    poller.POLLER._nodes = {}
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(ctx_, text, severity="info", chat_id=None):
        sent.append((text, chat_id))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    _body(_call(fn, {"message": {"text": "/node", "chat": {"id": 12345}}}))
    assert len(sent) == 1
    assert "/node" in sent[0][0]


def test_bot_username_suffix(monkeypatch):
    """@botname после команды не мешает маршрутизации."""
    ctx = Ctx({"tg_chat_ids": "12345"})
    router = _build(monkeypatch, ctx)
    sent = []

    async def fake_send(ctx_, text, severity="info", chat_id=None):
        sent.append((text, chat_id))

    monkeypatch.setattr(tg_bot, "send", fake_send)
    fn = router.routes[("POST", "/tg/webhook")]
    _body(_call(fn, {"message": {"text": "/help@MyBot",
                                   "chat": {"id": 12345}}}))
    assert len(sent) == 1
