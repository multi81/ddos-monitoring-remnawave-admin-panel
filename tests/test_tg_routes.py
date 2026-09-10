"""TDD: routes настроек TG — GET (маскированный токен), POST, /tg/test.

Вызов handlers напрямую (без TestClient): auth-Depends подменяются на no-op,
как в test_routes_rbac.py.
"""

import asyncio
import types

import ddos_monitoring.routes as routes
from ddos_monitoring import tg_bot


class SettingsStore:
    def __init__(self, data=None):
        self._data = dict(data or {})
        self.saved = {}

    async def get(self, key, default=None):
        return self._data.get(key, default)

    async def set(self, key, value):
        self._data[key] = value
        self.saved[key] = value


class Ctx:
    def __init__(self, data=None):
        self.settings = SettingsStore(data)
        self.panel_calls = []

    async def panel_notify(self, **kw):
        self.panel_calls.append(kw)


def _build(monkeypatch, ctx):
    """build_router с фейковым fastapi/auth_deps — возвращает {(path, method): fn}."""
    captured = {}

    class FakeAPIRouter:
        def __init__(self):
            self.routes = {}

        def __getitem__(self, key):
            return self.routes[key]

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

    fake_plugin_api = types.ModuleType("web.backend.core.plugin_api")

    def _dep(resource, action):
        return None
    fake_plugin_api.auth_deps = lambda: (_dep, _dep)

    real_import = __import__

    def fake_import(name, *a, **kw):
        if name == "fastapi":
            return fastapi_mod
        if name == "web.backend.core.plugin_api":
            return fake_plugin_api
        return real_import(name, *a, **kw)

    monkeypatch.setattr("builtins.__import__", fake_import)
    router = routes.build_router(ctx)
    return router


def _body(res):
    """_json() возвращает JSONResponse — достаём dict."""
    import json as _json
    return _json.loads(res.body)


def test_tg_get_masks_token(monkeypatch):
    ctx = Ctx({"tg_bot_token": "123456:AAGAQ-secret-xyz", "tg_chat_ids": "380424819"})
    r = _build(monkeypatch, ctx)
    res = _body(asyncio.run(r[("GET", "/tg")]()))
    import json as _json
    assert "AAGAQ-secret" not in _json.dumps(res)
    assert res["token_masked"].startswith("123456:")
    assert res["chat_ids"] == [380424819]


def test_tg_post_saves_to_settings(monkeypatch):
    ctx = Ctx()
    r = _build(monkeypatch, ctx)
    res = _body(asyncio.run(r[("POST", "/tg")]({"bot_token": "999:NEW", "chat_ids": "111,-100222"})))
    assert res["saved"] is True
    assert ctx.settings.saved["tg_bot_token"] == "999:NEW"
    assert ctx.settings.saved["tg_chat_ids"] == "111,-100222"


def test_tg_test_sends_and_counts(monkeypatch):
    ctx = Ctx({"tg_bot_token": "t", "tg_chat_ids": "1"})
    seen = []

    async def fake_api(token, method, payload):
        seen.append(payload)
        return {"ok": True}

    monkeypatch.setattr(tg_bot, "_bot_api", fake_api)
    r = _build(monkeypatch, ctx)
    res = _body(asyncio.run(r[("POST", "/tg/test")]({"text": "ping"})))
    assert res["sent"] == 1 and res["via"] == "bot"
    assert "ping" in str(seen)


def test_tg_test_falls_back_to_panel(monkeypatch):
    ctx = Ctx({})  # нет токена → panel_notify
    r = _build(monkeypatch, ctx)
    res = _body(asyncio.run(r[("POST", "/tg/test")]({"text": "hi"})))
    assert res["sent"] == 0 and res["via"] == "panel"
    assert len(ctx.panel_calls) == 1 and "hi" in ctx.panel_calls[0]["body"]
