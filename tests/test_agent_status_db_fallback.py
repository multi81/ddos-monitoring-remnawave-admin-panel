"""Тест fallback: /agent/status должен включать ВСЕ ноды из БД, даже если
panel_api().get_nodes() их не возвращает.

Workaround: прямой SQL к public.nodes, merge с panel_api результатом.
"""
from __future__ import annotations

import asyncio
import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest


class FakeRecord(tuple):
    """Имитация asyncpg.Record: поддерживает row[col] и row[idx]."""
    def __getitem__(self, k):
        if isinstance(k, str):
            # column "uuid" → idx 0, "name" → idx 1
            idx = 0 if k == 'uuid' else 1
            return super().__getitem__(idx)
        return super().__getitem__(k)


def _install_fake_web_module():
    fake = types.ModuleType("web.backend.core.plugin_api")
    fake._nodes_response = {
        "response": [
            {"uuid": "3e10607a-5ac4-4bb6-adca-9baf6369534b", "name": "DE2"},
        ]
    }
    fake._db_rows = [
        FakeRecord(("3e10607a-5ac4-4bb6-adca-9baf6369534b", "DE2")),
        FakeRecord(("9167ddba-7e0c-444a-a1c7-95ebc7005c5d", "Hermes")),
    ]

    class _Panel:
        async def get_nodes(self):
            return fake._nodes_response

    fake.panel_api = lambda: _Panel()
    sys.modules["web.backend.core.plugin_api"] = fake
    sys.modules.setdefault("web", types.ModuleType("web"))
    sys.modules.setdefault("web.backend", types.ModuleType("web.backend"))
    sys.modules.setdefault("web.backend.core", types.ModuleType("web.backend.core"))


_install_fake_web_module()

from ddos_monitoring import agent_receiver as AR  # noqa: E402
from ddos_monitoring import agent_routes  # noqa: E402


@pytest.mark.asyncio
async def test_agent_status_merges_db_nodes():
    """panel_api возвращает 1 ноду, БД — 2. /agent/status должен вернуть обе."""
    AR._last_report.clear()

    fake_pool = MagicMock()
    fake_pool.fetch = AsyncMock(return_value=sys.modules["web.backend.core.plugin_api"]._db_rows)
    fake_ctx = MagicMock()
    fake_ctx.db = fake_pool

    result = await agent_routes.agent_status_impl(fake_ctx)
    nodes = result["nodes"]

    assert "3e10607a-5ac4-4bb6-adca-9baf6369534b" in nodes
    assert "9167ddba-7e0c-444a-a1c7-95ebc7005c5d" in nodes
    assert nodes["9167ddba-7e0c-444a-a1c7-95ebc7005c5d"]["name"] == "Hermes"
    assert nodes["9167ddba-7e0c-444a-a1c7-95ebc7005c5d"]["online"] is False


@pytest.mark.asyncio
async def test_agent_status_panel_only():
    """Если panel_api вернула все ноды — fallback не должен их дублировать."""
    fake = sys.modules["web.backend.core.plugin_api"]
    fake._nodes_response = {
        "response": [
            {"uuid": "3e10607a-5ac4-4bb6-adca-9baf6369534b", "name": "DE2"},
            {"uuid": "9167ddba-7e0c-444a-a1c7-95ebc7005c5d", "name": "Hermes"},
        ]
    }
    AR._last_report.clear()

    fake_pool = MagicMock()
    fake_pool.fetch = AsyncMock(return_value=[
        FakeRecord(("3e10607a-5ac4-4bb6-adca-9baf6369534b", "DE2")),
        FakeRecord(("9167ddba-7e0c-444a-a1c7-95ebc7005c5d", "Hermes")),
    ])
    fake_ctx = MagicMock()
    fake_ctx.db = fake_pool

    result = await agent_routes.agent_status_impl(fake_ctx)
    assert len(result["nodes"]) == 2


@pytest.mark.asyncio
async def test_agent_status_panel_fails_db_saves():
    """Если panel_api падает — fallback через БД всё равно работает."""
    fake = sys.modules["web.backend.core.plugin_api"]

    class _BadPanel:
        async def get_nodes(self):
            raise RuntimeError("upstream down")

    fake.panel_api = lambda: _BadPanel()

    AR._last_report.clear()
    fake_pool = MagicMock()
    fake_pool.fetch = AsyncMock(return_value=[
        FakeRecord(("9167ddba-7e0c-444a-a1c7-95ebc7005c5d", "Hermes")),
    ])
    fake_ctx = MagicMock()
    fake_ctx.db = fake_pool

    result = await agent_routes.agent_status_impl(fake_ctx)
    assert "9167ddba-7e0c-444a-a1c7-95ebc7005c5d" in result["nodes"]
    assert result["nodes"]["9167ddba-7e0c-444a-a1c7-95ebc7005c5d"]["name"] == "Hermes"
