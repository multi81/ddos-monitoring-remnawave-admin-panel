"""Тест _precheck_install_targets: NO_AGENT_TOKEN / FLEET_AGENT_OFFLINE / unknown."""
from __future__ import annotations
import asyncio
import sys
import types


def _install_fake_web_module():
    fake = types.ModuleType("web.backend.core.plugin_api")
    sys.modules["web.backend.core.plugin_api"] = fake
    sys.modules.setdefault("web", types.ModuleType("web"))
    sys.modules.setdefault("web.backend", types.ModuleType("web.backend"))
    sys.modules.setdefault("web.backend.core", types.ModuleType("web.backend.core"))


_install_fake_web_module()


class FakeRecord(tuple):
    def __getitem__(self, k):
        if isinstance(k, str):
            mapping = {"uuid": 0, "has_token": 1, "is_connected": 2}
            return super().__getitem__(mapping.get(k, 0))
        return super().__getitem__(k)


def test_precheck_function_exists():
    from ddos_monitoring import agent_routes
    assert hasattr(agent_routes, "_precheck_install_targets"), (
        "Agent install precheck must be a standalone function for unit tests")
    assert callable(agent_routes._precheck_install_targets)


def test_precheck_removes_no_token():
    from ddos_monitoring import agent_routes

    targets = [
        "c35bf1dc-6e2d-4df4-80e0-78a2ed9f606b",
        "3e10607a-5ac4-4bb6-adca-9baf6369534b",
    ]

    class FakeConn:
        async def fetch(self, sql, uuids):
            return [
                FakeRecord(("c35bf1dc-6e2d-4df4-80e0-78a2ed9f606b", False, True)),
                FakeRecord(("3e10607a-5ac4-4bb6-adca-9baf6369534b", True, True)),
            ]

    new_targets, errors = asyncio.run(
        agent_routes._precheck_install_targets(targets, FakeConn()))

    assert "c35bf1dc-6e2d-4df4-80e0-78a2ed9f606b" not in new_targets
    assert "3e10607a-5ac4-4bb6-adca-9baf6369534b" in new_targets
    assert "NO_AGENT_TOKEN" in errors["c35bf1dc-6e2d-4df4-80e0-78a2ed9f606b"]
    assert "3e10607a-5ac4-4bb6-adca-9baf6369534b" not in errors


def test_precheck_removes_offline():
    from ddos_monitoring import agent_routes

    targets = ["bb1f66ac-b87e-45f3-8a27-6628902eab6b"]

    class FakeConn:
        async def fetch(self, sql, uuids):
            return [
                FakeRecord(("bb1f66ac-b87e-45f3-8a27-6628902eab6b", True, False)),
            ]

    new_targets, errors = asyncio.run(
        agent_routes._precheck_install_targets(targets, FakeConn()))

    assert new_targets == []
    assert "FLEET_AGENT_OFFLINE" in errors["bb1f66ac-b87e-45f3-8a27-6628902eab6b"]


def test_precheck_keeps_healthy():
    from ddos_monitoring import agent_routes

    targets = ["3e10607a-5ac4-4bb6-adca-9baf6369534b"]

    class FakeConn:
        async def fetch(self, sql, uuids):
            return [
                FakeRecord(("3e10607a-5ac4-4bb6-adca-9baf6369534b", True, True)),
            ]

    new_targets, errors = asyncio.run(
        agent_routes._precheck_install_targets(targets, FakeConn()))

    assert new_targets == targets
    assert errors == {}


def test_precheck_handles_missing_uuid():
    from ddos_monitoring import agent_routes

    targets = [
        "c35bf1dc-6e2d-4df4-80e0-78a2ed9f606b",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ]

    class FakeConn:
        async def fetch(self, sql, uuids):
            return [
                FakeRecord(("c35bf1dc-6e2d-4df4-80e0-78a2ed9f606b", True, True)),
            ]

    new_targets, errors, unknown = asyncio.run(
        agent_routes._precheck_install_targets(
            targets, FakeConn(), return_unknown=True))

    assert "c35bf1dc-6e2d-4df4-80e0-78a2ed9f606b" in new_targets
    assert "ffffffff-ffff-ffff-ffff-ffffffffffff" not in new_targets
    assert "ffffffff-ffff-ffff-ffff-ffffffffffff" in unknown
