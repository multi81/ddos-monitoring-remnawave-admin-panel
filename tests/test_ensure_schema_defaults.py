"""Тест ensure_schema: дефолтные plugin_settings создаются на первом запуске.

Проверяем по SQL в calls, не по args — args структура различается между
schema_version (literal) и _ensure_plugin_setting (parameterized).
"""
from __future__ import annotations

import asyncio
import pytest


class FakeRow(dict):
    def __getattr__(self, k):
        return self.get(k)


class FakeDB:
    def __init__(self, schema_version=None):
        self.calls = []
        self.existing_keys = set()
        self._schema_version = schema_version

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", sql[:80], args))
        if "schema_version" in sql:
            v = self._schema_version
            if v is not None:
                return str(v) if isinstance(v, int) else v
            return None
        return None

    async def execute(self, sql, *args):
        # Полный SQL — обрезание в анализаторе делаем сами где нужно.
        self.calls.append(("execute", sql, args))
        return "INSERT 0 1"


class FakeCtx:
    def __init__(self, schema_version=None):
        self.plugin_id = "ddos-monitoring"
        self.db = FakeDB(schema_version=schema_version)


def _insert_calls_for_setting(ctx, setting_key):
    """Возвращает список execute-вызовов с INSERT для настройки setting_key.

    Ключ передаётся через $2 parameter, не literal — ищем в args[1].
    """
    return [
        c for c in ctx.db.calls
        if c[0] == "execute"
        and "INSERT INTO plugin_settings" in c[1]
        and len(c[2]) >= 2
        and c[2][1] == setting_key
    ]


def test_ensure_schema_creates_defaults():
    """Первая установка → создаются baseline_mode, window_days, baseline_p95."""
    from ddos_monitoring.data import ensure_schema
    ctx = FakeCtx(schema_version=None)  # первая установка
    asyncio.run(ensure_schema(ctx))

    # Проверяем что INSERT для всех 3 настроек был выполнен
    # Ищем по args[1] (key передаётся как $2 parameter, не literal)
    default_keys = {"baseline_mode", "baseline_window_days", "baseline_p95"}
    inserted = set()
    for c in ctx.db.calls:
        if (c[0] == "execute"
            and "INSERT INTO plugin_settings" in c[1]
            and len(c[2]) >= 2
            and c[2][1] in default_keys):
            inserted.add(c[2][1])
    assert inserted == default_keys, (
        f"Не все defaults созданы: ожидались {default_keys}, "
        f"созданы {inserted}"
    )

    # Также schema_version (передаётся как positional, не $N)
    schema_inserted = any(
        c[0] == "execute"
        and "INSERT INTO plugin_settings" in c[1]
        and "schema_version" in c[1]
        for c in ctx.db.calls
    )
    assert schema_inserted


def test_ensure_schema_idempotent():
    """Повторный вызов с существующим schema_version → DDL не выполняется."""
    from ddos_monitoring.data import ensure_schema

    class StrictDB(FakeDB):
        async def fetchval(self, sql, *args):
            self.calls.append(("fetchval", sql[:80], args))
            return 3  # simulating existing schema_version

    ctx = FakeCtx(schema_version=3)
    ctx.db = StrictDB()

    initial_calls = len(ctx.db.calls)
    asyncio.run(ensure_schema(ctx))

    # DDL не должен выполняться (schema_version=3 уже есть)
    new_ddl = [
        c for c in ctx.db.calls[initial_calls:]
        if c[0] == "execute" and "CREATE TABLE" in c[1]
    ]
    assert len(new_ddl) == 0, "DDL не должен выполняться при существующей версии"

    # Defaults upsert-ятся всегда (idempotent через ON CONFLICT DO NOTHING)
    new_default_inserts = []
    for c in ctx.db.calls[initial_calls:]:
        if (c[0] == "execute"
            and "INSERT INTO plugin_settings" in c[1]
            and len(c[2]) >= 2
            and c[2][1] in ("baseline_mode", "baseline_window_days", "baseline_p95")):
            new_default_inserts.append(c)
    assert len(new_default_inserts) >= 3


def test_ensure_schema_uses_on_conflict_do_nothing():
    """_ensure_plugin_setting использует ON CONFLICT DO NOTHING — не перезаписывает."""
    from ddos_monitoring.data import ensure_schema
    ctx = FakeCtx(schema_version=None)
    asyncio.run(ensure_schema(ctx))

    # Найти INSERT для baseline_mode и проверить ON CONFLICT DO NOTHING
    for c in ctx.db.calls:
        if (c[0] == "execute"
            and "INSERT INTO plugin_settings" in c[1]
            and len(c[2]) >= 2
            and c[2][1] == "baseline_mode"):
            assert "ON CONFLICT" in c[1]
            assert "DO NOTHING" in c[1], (
                "Если бы было DO UPDATE — плагин перезаписывал бы админские правки"
            )
            return
    raise AssertionError("INSERT для baseline_mode не найден")


def test_ensure_schema_length_cap_on_expression():
    """Smoke: если выражение > 256 символов, raise ValueError."""
    from ddos_monitoring.poller import _apply_expression
    long_expr = "value * 1" + " + 1" * 200
    assert len(long_expr) > 256
    with pytest.raises(ValueError, match="too long"):
        _apply_expression(1.0, long_expr)
