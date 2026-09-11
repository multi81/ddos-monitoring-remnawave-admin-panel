#!/usr/bin/env python3
"""Read-only smoke: проверить, что новый fleet_overview() работает на прод-схеме.

Подключается к БД, НЕ модифицирует данные, только читает.
Использует переменные окружения:
  SMOKE_DB_HOST, SMOKE_DB_PORT, SMOKE_DB_USER, SMOKE_DB_PASS, SMOKE_DB_NAME

Usage:
  python3 scripts/smoke_fleet_overview_metrics.py
"""
import asyncio
import os
import sys
import asyncpg


async def main():
    host = os.environ.get("SMOKE_DB_HOST", "localhost")
    port = int(os.environ.get("SMOKE_DB_PORT", "5432"))
    user = os.environ.get("SMOKE_DB_USER", "postgres")
    password = os.environ.get("SMOKE_DB_PASS", "")
    dbname = os.environ.get("SMOKE_DB_NAME", "postgres")

    conn = await asyncpg.connect(
        host=host, port=port, user=user, password=password, database=dbname,
    )
    try:
        # Проверяем наличие нужных таблиц и колонок
        for t in ("ddos_monitoring_node_state", "ddos_monitoring_agent_status",
                 "ddos_monitoring_agent_snapshots", "ddos_monitoring_attacks"):
            row = await conn.fetchrow(
                "SELECT to_regclass($1) AS r", f"public.{t}",
            )
            if row["r"] is None:
                print(f"FAIL: таблица {t} не существует")
                sys.exit(1)
        # Проверяем колонку node_uuid в каждой
        for t in ("ddos_monitoring_node_state", "ddos_monitoring_agent_status",
                 "ddos_monitoring_agent_snapshots"):
            col = await conn.fetchval(
                """SELECT data_type FROM information_schema.columns
                   WHERE table_name=$1 AND column_name='node_uuid'""",
                t,
            )
            if col != "uuid":
                print(f"FAIL: {t}.node_uuid is {col}, expected uuid")
                sys.exit(1)
        print("schema OK: 4 tables, 3 uuid columns")

        # Подключаем как StubCtx
        sys.path.insert(0, "/tmp/ddos-0728-src")
        from ddos_monitoring import data

        class StubCtx:
            def __init__(self, db): self.db = db
        class DBWrap:
            def __init__(self, c): self._c = c
            async def fetch(self, sql, *args):
                return await self._c.fetch(sql, *args)
            async def fetchval(self, sql, *args):
                return await self._c.fetchval(sql, *args)

        ctx = StubCtx(DBWrap(conn))
        nodes = await data.fleet_overview(ctx)
        total = await data.total_nodes_in_panel(ctx)
        print(f"total_nodes_in_panel: {total}")
        print(f"fleet_overview rows: {len(nodes)}")
        if nodes:
            sample = nodes[0]
            print(f"sample keys: {sorted(sample.keys())}")
            print(f"sample metrics: {sample.get('metrics')}")
            print(f"sample history: {sample.get('history')}")
            print(f"sample history len: {len(sample.get('history') or [])}")
        print("OK")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
