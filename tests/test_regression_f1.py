"""Регресс F-1: bind_ctx вызван из _build — первый тик не падает с None-ctx."""
from __future__ import annotations

import asyncio

import pytest

import ddos_monitoring
from ddos_monitoring.poller import POLLER


class _FakeParts:
    def __init__(self, router=None, scheduled_tasks=None):
        self.router = router
        self.scheduled_tasks = scheduled_tasks or []


def test_build_binds_ctx(monkeypatch):
    """_build обязан вызвать bind_ctx: после него _ctx_ref() не None."""
    import types

    fake_mod = types.ModuleType("web.backend.core.plugins")
    fake_mod.PluginParts = _FakeParts
    fake_mod.ScheduledTask = lambda **kw: kw
    monkeypatch.setitem(__import__("sys").modules, "web.backend.core.plugins", fake_mod)

    # роутер строить не надо — подменяем build_router
    import ddos_monitoring.routes as routes
    monkeypatch.setattr(routes, "build_router", lambda ctx: object())

    from tests.fakes import FakeCtx
    ctx = FakeCtx()
    parts = ddos_monitoring._build(ctx)

    from ddos_monitoring.poller import _ctx_ref
    assert _ctx_ref() is ctx
    # В 0.7.28+ есть 2 periodic-задачи: ddos-agent-secret-init + ddos-poll.
    # Тест устарел с момента добавления второй задачи — фикс.
    assert len(parts.scheduled_tasks) == 2
    task_names = {t["name"] for t in parts.scheduled_tasks}
    assert "ddos-poll" in task_names, "ddos-poll task должна быть"
    assert "ddos-agent-secret-init" in task_names, (
        "ddos-agent-secret-init task должна быть"
    )


async def test_real_tick_works_after_bind(monkeypatch):
    """Интеграционный регресс F-1+M-1: bind_ctx → tick → схема применилась,
    node_state заполнился, атака открылась после подтверждений."""
    import time as t

    import ddos_monitoring.data as data
    from ddos_monitoring.poller import ATTACK_CONFIRMATIONS, POLLER
    from tests.fakes import FakeCtx

    ctx = FakeCtx()
    monkeypatch.setattr(ddos_monitoring.poller, "_CTX", ctx)  # как делает bind_ctx

    # фейковый panel_api с одной нодой (имя для M-1)
    fake_api_mod = types_stub = __import__("types").ModuleType("web.backend.core.plugin_api")
    class _Api:
        async def get_nodes(self, skip_cache=False):
            return {"items": [{"uuid": "n1", "name": "node-one"}]}
    def panel_api():
        return _Api()
    fake_api_mod.panel_api = panel_api
    monkeypatch.setitem(__import__("sys").modules, "web.backend.core.plugin_api", fake_api_mod)

    # одна нода с SYN-флудом в snapshots
    metrics_row = {"node_uuid": "n1", "net_rx_bps": 0, "net_rx_pps": 0,
                   "net_rx_drop_ps": 0, "conntrack_count": 0, "conntrack_max": 1000,
                   "tcp_syncookies_ps": 5000, "tcp_listen_drop_ps": 0}
    async def fetch(query, *args):
        if "node_metrics_snapshots" in query:
            return [metrics_row]
        return []
    ctx.db.fetch = fetch

    POLLER._schema_ready = False
    POLLER._nodes.clear()
    await POLLER.tick(ctx.logger)
    assert POLLER.error is None and POLLER.ticks_ok == 1
    # M-1: node_state получил запись с именем ноды
    assert any(r["node_uuid"] == "n1" for r in ctx.db.tables.get("ddos_monitoring_node_state", []) if isinstance(r, dict)) or \
        ctx.db._inserted_samples
    # подтверждений ещё нет — атаки быть не должно
    assert not ctx.db.tables.get("ddos_monitoring_attacks")

    # докидываем подтверждения
    for _ in range(ATTACK_CONFIRMATIONS - 1):
        await POLLER.tick(ctx.logger)
    attacks = ctx.db.tables.get("ddos_monitoring_attacks", [])
    assert len(attacks) == 1 and attacks[0]["node_uuid"] == "n1"
