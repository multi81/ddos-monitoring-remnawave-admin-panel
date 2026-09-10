"""ddos-monitoring — DDoS-мониторинг для remnawave-admin (Plugin API v1).

Источник данных — телеметрия нод в БД панели (node_metrics_snapshots,
заполняется node-agent'ом через /collector). SSH и ключи старого
монитора не используются.
"""
from __future__ import annotations

import importlib.metadata

PLUGIN_ID = "ddos-monitoring"
PLUGIN_NAME = "DDoS Monitor"

try:
    __version__ = importlib.metadata.version("ddos-monitoring")
except importlib.metadata.PackageNotFoundError:  # dev-режим без установки wheel
    __version__ = "0.0.0.dev0"


def _build(ctx):
    from web.backend.core.plugins import PluginParts, ScheduledTask

    from .poller import INTERVAL_S, POLLER, bind_ctx
    from .routes import build_router
    from .secret import ensure_agent_secret

    # Контекст нужен poller'у до первого тика (F-1): без него тик падает
    # с AttributeError и плагин уходит в вечный backoff.
    bind_ctx(ctx)

    async def poll_tick() -> None:
        await POLLER.tick(ctx.logger)

    async def secret_init_tick() -> None:
        await ensure_agent_secret(ctx)

    return PluginParts(
        router=build_router(ctx),
        # startup не является штатной фазой PluginParts — схему применяем
        # лениво из первого тика poller'а (идемпотентный DDL).
        scheduled_tasks=[
            ScheduledTask(name="ddos-agent-secret-init", interval_seconds=60, coro=secret_init_tick),
            ScheduledTask(name="ddos-poll", interval_seconds=INTERVAL_S, coro=poll_tick),
        ],
    )


def manifest():
    from web.backend.core.plugins import NavEntry, PluginManifest

    return PluginManifest(
        id=PLUGIN_ID,
        name=PLUGIN_NAME,
        version=__version__,
        api_version=1,
        billing="free",
        build=_build,
        # view — атаки/нагрузка; view_ips — IP атакующих (не всем операторам)
        rbac_resources={"ddos": ["view", "view_ips"]},
        navigation=[
            # Панель ≥4.5.4: generic-маршрут /plugins/:pluginId — страница
            # рендерится внутри layout админки (сайдбар/шапка на месте).
            # На старых панелях (<4.5.4) пункт ведёт на standalone /ui.
            NavEntry(
                path="/plugins/ddos-monitoring",
                label_i18n="DDoS-монитор",
                icon="ShieldAlert",
                permission=("ddos", "view"),
                section_i18n="nav.sections.plugins",
            ),
        ],
        ui=_ui_obj(),
    )


def _ui_obj():
    """PluginUI появился в 4.5.4; на старых панелях класса нет — без UI."""
    try:
        from web.backend.core.plugins import PluginUI
    except ImportError:
        return None
    return PluginUI(kind="module", path="/ui-module")
