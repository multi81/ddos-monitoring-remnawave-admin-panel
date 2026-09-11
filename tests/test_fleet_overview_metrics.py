"""ТЕСТЫ: расширение fleet_overview() — metrics, history, total_nodes_in_panel.

UI задачи #1, #2, #5 (handoff.md от Aria).

Что проверяем:
- nodes[].metrics: cpu_pct/ram_pct/swap_pct/disk_pct/syn_recv/established/rx_mbps/tx_mbps/syn_recv_delta_per_s
- nodes[].history: [float * 8] — sparkline 0..100
- total_nodes_in_panel: int (count из public.nodes)
- Один bulk-запрос (_bulk_snapshots) вместо N+1

NOT WIRED: Нет routes.py, нет реальной БД.
"""
from __future__ import annotations

import pytest

# ────────────────────────────────────────────────────────────────────
# Тестовые хелперы (минимальные фейки asyncpg)
# ────────────────────────────────────────────────────────────────────


def _row(**kwargs) -> dict:
    """Минимальный asyncpg Record-like объект."""
    return FakeRow(kwargs)


class FakeRow(dict):
    """Поддерживает и dict[key], и .key доступ."""
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class FakeDB:
    """Упрощённый asyncpg-like DB для тестирования data.py."""

    def __init__(self):
        self.calls: list[tuple[str, str, tuple]] = []
        self._scenarios: dict[str, list[FakeRow]] = {}
        self._values: dict[str, int | str | None] = {}

    # Тестовые helpers
    def set_rows_for(self, sql_contains: str, rows: list[FakeRow]):
        self._scenarios[sql_contains] = rows

    def set_value_for(self, sql_contains: str, value):
        self._values[sql_contains] = value

    async def fetch(self, sql: str, *args):
        self.calls.append(("fetch", sql[:80], args))
        # ROW_NUMBER() bulk-запрос (_bulk_snapshots) — имитируем LIMIT per node
        if "ROW_NUMBER()" in sql:
            rows = self._scenarios.get("ROW_NUMBER()", [])
            if not rows:
                return []
            # Имитируем WHERE rn <= $1: берём последние limit_per_node строк на ноду
            limit = int(args[0]) if args else 9
            by_uuid: dict[str, list] = {}
            for r in rows:
                uuid = str(r.get("node_uuid", ""))
                by_uuid.setdefault(uuid, []).append(r)
            result = []
            for uuid, snaps in by_uuid.items():
                # Сортируем по ts ASC, берём последние limit
                snaps_sorted = sorted(snaps, key=lambda x: int(x.get("ts", 0)))
                result.extend(snaps_sorted[-limit:])
            return result
        # node_state (fleet overview main query) — фолбэк
        for needle, rows in self._scenarios.items():
            if needle in sql:
                return rows
        return []

    async def fetchval(self, sql: str, *args):
        self.calls.append(("fetchval", sql[:80], args))
        for needle, val in self._values.items():
            if needle in sql:
                return val
        return None

    async def execute(self, sql: str, *args):
        self.calls.append(("execute", sql[:80], args))
        return "INSERT 0 0"


class FakeCtx:
    def __init__(self, db: FakeDB):
        self.db = db


# ────────────────────────────────────────────────────────────────────
# Задача #1: metrics{} в каждой ноде
# ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fleet_overview_includes_metrics_per_node():
    """Каждая нода имеет metrics{} со всеми UI-полями."""
    db = FakeDB()
    node_uuid = "aaaaaaaa-1111-1111-1111-111111111111"

    db.set_rows_for("ddos_monitoring_node_state", [
        _row(node_uuid=node_uuid, node_name="test-node",
             agent_version="1.1.0",
             last_seen_at=1700000000, last_error=None,
             attack_id=None, attack_started=None,
             attack_type=None, severity=None, target=None),
    ])
    # bulk_snapshots: 1 снапшот → snap[-1]=current, history=[]
    db.set_rows_for("ROW_NUMBER()", [
        _row(node_uuid=node_uuid, ts=1700000000,
             cpu_pct=42.5, ram_pct=67.0, swap_pct=10.0, disk_pct=80.0,
             syn_recv=200, established=1000,
             rx_bps=312_700_000, tx_bps=89_100_000),
    ])
    db.set_value_for("public.nodes", 12)

    ctx = FakeCtx(db)

    from ddos_monitoring import data

    nodes = await data.fleet_overview(ctx)
    assert len(nodes) == 1

    m = nodes[0].get("metrics")
    assert m is not None, "metrics must be present"
    assert m["cpu_pct"] == 42.5
    assert m["ram_pct"] == 67.0
    assert m["swap_pct"] == 10.0
    assert m["disk_pct"] == 80.0
    assert m["syn_recv"] == 200
    assert m["established"] == 1000
    assert m["rx_mbps"] == pytest.approx(312.7)
    assert m["tx_mbps"] == pytest.approx(89.1)
    assert m["syn_recv_delta_per_s"] == 0.0  # нет prev снапшота

    # history: нет prev → history=[]
    assert nodes[0].get("history") == []


# ────────────────────────────────────────────────────────────────────
# Задача #1b: syn_recv_delta_per_s
# ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fleet_overview_syn_delta_between_snapshots():
    """syn_recv_delta_per_s = (current_syn - prev_syn) / dt."""
    db = FakeDB()
    node_uuid = "aaaaaaaa-1111-1111-1111-111111111111"

    db.set_rows_for("ddos_monitoring_node_state", [
        _row(node_uuid=node_uuid, node_name="n", agent_version="1.1.0",
             last_seen_at=1000, last_error=None,
             attack_id=None, attack_started=None,
             attack_type=None, severity=None, target=None),
    ])
    # 2 снапшота: prev ts=990 syn=100, current ts=1000 syn=200
    db.set_rows_for("ROW_NUMBER()", [
        _row(node_uuid=node_uuid, ts=990,
             cpu_pct=10, ram_pct=20, swap_pct=5, disk_pct=50,
             syn_recv=100, established=500,
             rx_bps=0, tx_bps=0),
        _row(node_uuid=node_uuid, ts=1000,
             cpu_pct=10, ram_pct=20, swap_pct=5, disk_pct=50,
             syn_recv=200, established=500,
             rx_bps=0, tx_bps=0),
    ])
    db.set_value_for("public.nodes", 3)

    ctx = FakeCtx(db)
    from ddos_monitoring import data

    nodes = await data.fleet_overview(ctx)
    m = nodes[0]["metrics"]
    # delta = (200-100)/(1000-990) = 100/10 = 10.0
    assert m["syn_recv_delta_per_s"] == pytest.approx(10.0)


# ────────────────────────────────────────────────────────────────────
# Задача #1c: метрики отсутствуют
# ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fleet_overview_metrics_absent_when_no_snapshot():
    """Без снапшотов: metrics=None, history=[]."""
    db = FakeDB()
    node_uuid = "aaaaaaaa-1111-1111-1111-111111111111"

    db.set_rows_for("ddos_monitoring_node_state", [
        _row(node_uuid=node_uuid, node_name="n", agent_version="1.1.0",
             last_seen_at=1000, last_error=None,
             attack_id=None, attack_started=None,
             attack_type=None, severity=None, target=None),
    ])
    db.set_rows_for("ROW_NUMBER()", [])  # пусто
    db.set_value_for("public.nodes", 1)

    ctx = FakeCtx(db)
    from ddos_monitoring import data

    nodes = await data.fleet_overview(ctx)
    assert nodes[0].get("metrics") is None
    assert nodes[0].get("history") == []


# ────────────────────────────────────────────────────────────────────
# Задача #2: history[] — sparkline 8 точек
# ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fleet_overview_includes_history_of_load():
    """history = [float * N], load = max(cpu, syn/100, est/10000)."""
    db = FakeDB()
    node_uuid = "aaaaaaaa-1111-1111-1111-111111111111"

    db.set_rows_for("ddos_monitoring_node_state", [
        _row(node_uuid=node_uuid, node_name="n", agent_version="1.1.0",
             last_seen_at=2000, last_error=None,
             attack_id=None, attack_started=None,
             attack_type=None, severity=None, target=None),
    ])
    # 9 снапшотов: 8 для history + 1 current
    snaps = []
    for i, cpu in enumerate([10, 20, 30, 40, 50, 60, 70, 80]):
        snaps.append(_row(
            node_uuid=node_uuid, ts=1000 + i * 20,
            cpu_pct=float(cpu), ram_pct=10.0, swap_pct=0.0,
            disk_pct=10.0,
            syn_recv=10, established=200,
            rx_bps=1_000_000, tx_bps=1_000_000,
        ))
    # current (ts=1160, cpu=90) — самый новый
    snaps.append(_row(
        node_uuid=node_uuid, ts=1160,
        cpu_pct=90.0, ram_pct=10.0, swap_pct=0.0,
        disk_pct=10.0,
        syn_recv=10, established=200,
        rx_bps=1_000_000, tx_bps=1_000_000,
    ))
    db.set_rows_for("ROW_NUMBER()", snaps)
    db.set_value_for("public.nodes", 1)

    ctx = FakeCtx(db)
    from ddos_monitoring import data

    nodes = await data.fleet_overview(ctx)
    h = nodes[0].get("history")
    assert isinstance(h, list), "history must be list"
    assert len(h) == 8, f"history len = {len(h)}, expected 8"
    assert h[0] == pytest.approx(10.0)   # oldest: cpu=10
    assert h[-1] == pytest.approx(80.0)  # newest of history: cpu=80


# ────────────────────────────────────────────────────────────────────
# Задача #2b: syn_recv dominates load
# ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fleet_overview_history_load_uses_normalized_synrecv():
    """syn_recv=9000 → normalized 90 → dominates cpu=10."""
    db = FakeDB()
    node_uuid = "aaaaaaaa-1111-1111-1111-111111111111"

    db.set_rows_for("ddos_monitoring_node_state", [
        _row(node_uuid=node_uuid, node_name="n", agent_version="1.1.0",
             last_seen_at=1000, last_error=None,
             attack_id=None, attack_started=None,
             attack_type=None, severity=None, target=None),
    ])
    # 2 снапшота: history=1, current=1
    db.set_rows_for("ROW_NUMBER()", [
        _row(node_uuid=node_uuid, ts=990,
             cpu_pct=10.0, ram_pct=10.0, swap_pct=0.0, disk_pct=10.0,
             syn_recv=9000, established=100,
             rx_bps=0, tx_bps=0),
        _row(node_uuid=node_uuid, ts=1000,
             cpu_pct=10.0, ram_pct=10.0, swap_pct=0.0, disk_pct=10.0,
             syn_recv=9000, established=100,
             rx_bps=0, tx_bps=0),
    ])
    db.set_value_for("public.nodes", 1)

    ctx = FakeCtx(db)
    from ddos_monitoring import data

    nodes = await data.fleet_overview(ctx)
    h = nodes[0].get("history")
    assert len(h) == 1  # 1 снапшот для history (всего 2, 1 = current)
    assert h[0] == pytest.approx(90.0)  # syn_recv/100 = 90


# ────────────────────────────────────────────────────────────────────
# Задача #5: total_nodes_in_panel
# ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fleet_overview_exposes_total_nodes_separately():
    """total_nodes_in_panel ≠ len(nodes)."""
    db = FakeDB()

    db.set_rows_for("ddos_monitoring_node_state", [
        _row(node_uuid="a-1", node_name="a", agent_version="1.0",
             last_seen_at=1000, last_error=None,
             attack_id=None, attack_started=None,
             attack_type=None, severity=None, target=None),
        _row(node_uuid="a-2", node_name="b", agent_version="1.0",
             last_seen_at=1000, last_error=None,
             attack_id=None, attack_started=None,
             attack_type=None, severity=None, target=None),
    ])
    db.set_rows_for("ROW_NUMBER()", [])
    db.set_value_for("public.nodes", 10)

    ctx = FakeCtx(db)
    from ddos_monitoring import data

    nodes = await data.fleet_overview(ctx)
    assert len(nodes) == 2  # 2 ноды со срезами

    total = await data.total_nodes_in_panel(ctx)
    assert total == 10  # всего нод в панели
