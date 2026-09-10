"""T4: интеграционные тесты на реальной Postgres.

Требуют: docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_DB=smoke \\
              -p 54321:5432 postgres:16-alpine
        + таблицы (см. /tmp/t3_init.sql)

Запуск: RUN_SLOW=1 pytest -m slow tests/test_t4_integration.py
По умолчанию SKIP — обычный `pytest` их не запускает.
"""
import os
import sys

import pytest

# Пропускаем всё если нет RUN_SLOW=1
pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not os.environ.get("RUN_SLOW"),
        reason="set RUN_SLOW=1 для запуска интеграционных тестов",
    ),
]


@pytest.fixture
async def pg_conn():
    """asyncpg-соединение к smoke-БД."""
    import asyncpg
    try:
        conn = await asyncpg.connect(
            host="localhost", port=54321, user="postgres",
            password="test", database="smoke",
        )
    except Exception as e:
        pytest.skip(f"не удалось подключиться к Postgres 54321: {e}")
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def clean_attacks(pg_conn):
    """Очищает таблицу attacks перед/после теста."""
    await pg_conn.execute("TRUNCATE ddos_monitoring_attacks RESTART IDENTITY")
    yield
    await pg_conn.execute("TRUNCATE ddos_monitoring_attacks RESTART IDENTITY")


class TestCloseStaleAttacksAsyncPG:
    """S.2 asyncpg round-trip — закрепляет production-ready."""

    async def test_closes_only_old_attacks(self, pg_conn, clean_attacks):
        sys.path.insert(0, "/tmp/ddos-0728-src")
        from ddos_monitoring.data import close_stale_attacks
        await pg_conn.execute(
            "INSERT INTO ddos_monitoring_attacks (node_uuid) "
            "VALUES ('old1'), ('old2'), ('fresh')"
        )
        await pg_conn.execute(
            "UPDATE ddos_monitoring_attacks "
            "SET started_at = NOW() - interval '3 hours' "
            "WHERE node_uuid IN ('old1', 'old2')"
        )

        class Ctx:
            db = pg_conn
        n = await close_stale_attacks(Ctx(), ttl_s=7200)
        assert n == 2
        rows = await pg_conn.fetch(
            "SELECT node_uuid, ended_at IS NOT NULL AS closed "
            "FROM ddos_monitoring_attacks ORDER BY id"
        )
        closed = {r["node_uuid"]: r["closed"] for r in rows}
        assert closed == {"old1": True, "old2": True, "fresh": False}

    async def test_negative_ttl_raises_before_db_hit(self, pg_conn):
        sys.path.insert(0, "/tmp/ddos-0728-src")
        from ddos_monitoring.data import close_stale_attacks

        class Ctx:
            db = pg_conn
        # Считаем атаки ДО
        before = await pg_conn.fetchval(
            "SELECT count(*) FROM ddos_monitoring_attacks"
        )
        with pytest.raises(ValueError, match="ttl_s must be > 0"):
            await close_stale_attacks(Ctx(), ttl_s=-1)
        # Должны быть равны — ничего не изменилось
        after = await pg_conn.fetchval(
            "SELECT count(*) FROM ddos_monitoring_attacks"
        )
        assert before == after

    async def test_idempotent_double_close(self, pg_conn, clean_attacks):
        """Двойной вызов close не закрывает повторно."""
        sys.path.insert(0, "/tmp/ddos-0728-src")
        from ddos_monitoring.data import close_stale_attacks
        await pg_conn.execute(
            "INSERT INTO ddos_monitoring_attacks (node_uuid) VALUES ('old')"
        )
        await pg_conn.execute(
            "UPDATE ddos_monitoring_attacks "
            "SET started_at = NOW() - interval '3 hours' "
            "WHERE node_uuid = 'old'"
        )

        class Ctx:
            db = pg_conn
        n1 = await close_stale_attacks(Ctx(), ttl_s=7200)
        n2 = await close_stale_attacks(Ctx(), ttl_s=7200)
        assert n1 == 1
        assert n2 == 0  # уже закрыто — ничего не делаем


class TestMaybeCloseStalePollerIntegration:
    """T4 wire L1: DdosPoller._maybe_close_stale с реальной PG."""

    async def test_full_cycle(self, pg_conn, clean_attacks):
        sys.path.insert(0, "/tmp/ddos-0728-src")
        from ddos_monitoring.poller import DdosPoller
        # Seed: 1 зависшая, 1 свежая
        await pg_conn.execute(
            "INSERT INTO ddos_monitoring_attacks (node_uuid) "
            "VALUES ('stale'), ('fresh')"
        )
        await pg_conn.execute(
            "UPDATE ddos_monitoring_attacks "
            "SET started_at = NOW() - interval '3 hours' "
            "WHERE node_uuid = 'stale'"
        )

        class Ctx:
            db = pg_conn

            class _S:
                def __init__(self, vals):
                    self.vals = vals
                async def get(self, key):
                    return self.vals.get(key)
            settings = _S({"attack_stale_ttl_s": 7200})

        import logging
        log = logging.getLogger("test")
        p = DdosPoller()
        n = await p._maybe_close_stale(Ctx(), log)
        assert n == 1

        # Проверка: stale закрыта, fresh жива
        rows = await pg_conn.fetch(
            "SELECT node_uuid, ended_at IS NOT NULL AS closed "
            "FROM ddos_monitoring_attacks ORDER BY id"
        )
        assert {r["node_uuid"]: r["closed"] for r in rows} == \
            {"stale": True, "fresh": False}

    async def test_settings_zero_keeps_attacks(self, pg_conn, clean_attacks):
        """attack_stale_ttl_s=0 → даже очень старые НЕ закрываются."""
        sys.path.insert(0, "/tmp/ddos-0728-src")
        from ddos_monitoring.poller import DdosPoller
        await pg_conn.execute(
            "INSERT INTO ddos_monitoring_attacks (node_uuid) VALUES ('old')"
        )
        await pg_conn.execute(
            "UPDATE ddos_monitoring_attacks "
            "SET started_at = NOW() - interval '5 hours' "
            "WHERE node_uuid = 'old'"
        )

        class Ctx:
            db = pg_conn

            class _S:
                def __init__(self, vals):
                    self.vals = vals
                async def get(self, key):
                    return self.vals.get(key)
            settings = _S({"attack_stale_ttl_s": 0})

        import logging
        log = logging.getLogger("test")
        p = DdosPoller()
        n = await p._maybe_close_stale(Ctx(), log)
        assert n == 0
        # Запись всё ещё открыта
        closed = await pg_conn.fetchval(
            "SELECT ended_at IS NOT NULL FROM ddos_monitoring_attacks "
            "WHERE node_uuid = 'old'"
        )
        assert closed is False
