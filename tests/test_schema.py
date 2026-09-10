"""Схема: ensure_schema идемпотентен, версия фиксируется, DDL не падает дважды."""
from __future__ import annotations

import pytest

from ddos_monitoring.data import SCHEMA_VERSION, ensure_schema
from tests.fakes import FakeCtx


async def test_ensure_schema_applies_and_records_version():
    ctx = FakeCtx()
    executed = []
    orig = ctx.db.execute

    async def spy(query, *args):
        executed.append(query)
        return await orig(query, *args)

    ctx.db.execute = spy
    await ensure_schema(ctx)
    assert any("CREATE TABLE IF NOT EXISTS ddos_monitoring_attacks" in q for q in executed)
    assert ctx.db.settings.get(("ddos-monitoring", "schema_version")) == str(SCHEMA_VERSION)


async def test_ensure_schema_is_noop_when_current():
    ctx = FakeCtx()
    ctx.db.settings[("ddos-monitoring", "schema_version")] = str(SCHEMA_VERSION)
    executed = []
    async def spy(query, *args):
        executed.append(query)
    ctx.db.execute = spy
    await ensure_schema(ctx)
    assert not any("CREATE TABLE" in q for q in executed)


async def test_ensure_schema_reapplies_on_lower_recorded_version():
    ctx = FakeCtx()
    ctx.settings._values[("ddos-monitoring", "schema_version")] = "0"
    await ensure_schema(ctx)  # должен применить DDL без исключения


def test_ddl_is_idempotent_by_construction():
    from ddos_monitoring.data import _DDL
    import re
    flat = re.sub(r"\s+", " ", _DDL)
    creates = re.findall(r"CREATE (?:TABLE|INDEX)(?: IF NOT EXISTS)?", flat)
    if_not_exists = [c for c in creates if "IF NOT EXISTS" in c]
    assert creates == if_not_exists and len(creates) >= 5
