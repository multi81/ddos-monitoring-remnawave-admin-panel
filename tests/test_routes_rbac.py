"""Тесты RBAC-контракта роутов: /data требует ddos:view, никаких открытых ручек.

Роутер строится с фейковыми auth_deps (панели нет в тестовом окружении) —
проверяем, что каждая ручка объявила зависимость require_permission.
"""
from __future__ import annotations

from ddos_monitoring import routes


class _Dep:
    """Маркер-заглушка вместо панельной зависимости."""

    def __init__(self, resource=None, action=None):
        self.resource = resource
        self.action = action


def _fake_auth_deps():
    def require_permission(resource, action):
        return _Dep(resource, action)

    return _Dep, require_permission


class _FakeAPIRouter:
    """Ловит декораторы роутера и запоминает пути + зависимости."""

    def __init__(self):
        self.routes = []

    def get(self, path, **kwargs):
        def deco(fn):
            self.routes.append((path, fn, kwargs.get("summary", "")))
            return fn
        return deco

    def post(self, path, **kwargs):  # фаза 2.5: TG-роуты
        def deco(fn):
            self.routes.append((path, fn, kwargs.get("summary", "")))
            return fn
        return deco


def _build_with_fake_deps(monkeypatch):
    captured = {}

    class FakeFastAPI:
        APIRouter = _FakeAPIRouter

        @staticmethod
        def Depends(dep):
            return ("dep", dep)

    import types
    fastapi_mod = types.ModuleType("fastapi")
    fastapi_mod.APIRouter = _FakeAPIRouter
    fastapi_mod.Depends = lambda dep: ("dep", dep)
    fastapi_mod.HTTPException = type("HTTPException", (Exception,), {})
    fastapi_mod.Body = lambda *a, **k: None  # фаза 2.5: TG-роуты
    enc_mod = types.ModuleType("fastapi.encoders")
    enc_mod.jsonable_encoder = lambda x: x
    resp_mod = types.ModuleType("fastapi.responses")
    resp_mod.JSONResponse = lambda content, status_code=200, headers=None: {"content": content}

    fake_plugin_api = types.ModuleType("web.backend.core.plugin_api")
    fake_plugin_api.auth_deps = _fake_auth_deps

    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name in ("fastapi", "web.backend.core.plugin_api") or name.startswith(("fastapi.", "web.backend.")):
            if name == "fastapi":
                return fastapi_mod
            if name == "fastapi.encoders":
                return enc_mod
            if name == "fastapi.responses":
                return resp_mod
            if name == "web.backend.core.plugin_api":
                return fake_plugin_api
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)

    ctx = object()
    return routes.build_router(ctx)  # _FakeAPIRouter instance


def test_every_route_declares_permission(monkeypatch):
    router = _build_with_fake_deps(monkeypatch)
    assert len(router.routes) >= 3
    for path, fn, _summary in router.routes:
        # зависимость — это default параметра-ручки (Depends(require_permission(...)))
        defaults = fn.__defaults__ or ()
        has_dep = any(isinstance(d, tuple) and d and d[0] == "dep"
                      and getattr(d[1], "resource", None) == "ddos"
                      for d in defaults)
        assert has_dep, f"ручка {path} без зависимости require_permission('ddos', ...)"


def test_view_ips_not_used_in_phase1(monkeypatch):
    """Фаза 1: IP атакующих нигде не отдаются — только ddos:view."""
    router = _build_with_fake_deps(monkeypatch)
    assert all("view_ips" not in (s or "") for _p, _f, s in router.routes)
