"""Тест baseline mode: вычисление p95 из истории + per-node thresholds."""
from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta


def _install_fake_asyncpg():
    """Создаёт минимальный fake asyncpg с awaitable fetch, record_class."""
    fake = types.ModuleType("asyncpg")
    class _Record(dict):
        def __getattr__(self, k):
            return self.get(k)
    async def _respond(args=()):
        return []
    class _FakeConn:
        def __init__(self):
            self.responds = []
        async def fetch(self, sql, *args):
            return _respond(self.responds)
        async def fetchval(self, sql, *args):
            return None
        async def execute(self, sql, *args):
            return "INSERT 0 1"
        def add_response(self, rows):
            self.responds.append(rows)
    fake.Record = _Record
    fake.connect = lambda *a, **kw: _FakeConn()
    sys.modules["asyncpg"] = fake
    return fake


def test_baseline_p95_calculation():
    """p95 из 100 значений должен класть baseline примерно на 95-й позиции
    выборки, умноженный на 3 (default expression)."""
    fake = _install_fake_asyncpg()
    from ddos_monitoring.poller import _compute_baseline_from_samples
    # Несколько сэмплов на ОДИН uuid, чтобы p95 имело смысл.
    samples = [
        ("uuid-A", {"net_rx_bps": v * 1_000_000})
        for v in [1, 2, 3, 50, 51, 52, 100, 101, 102]
    ]
    out = _compute_baseline_from_samples(samples)
    assert "uuid-A" in out
    b = out["uuid-A"]
    # 9 сэмплов, p95 idx = 0.95*8 = 7.6 → 8 → sorted[8] = 102 Mbps.
    # 102 Mbps * 3 = 306 Mbps; MIN 20 Mbps → 306 Mbps.
    assert b["rx_bps"] > 280_000_000, f"p95 too low: {b['rx_bps']}"
    assert b["rx_bps"] < 320_000_000, f"p95 too high: {b['rx_bps']}"


def test_min_threshold_floor():
    """Min threshold должен быть нижней границей для tiny traffic."""
    fake = _install_fake_asyncpg()
    from ddos_monitoring.poller import _compute_baseline_from_samples
    samples = [("uuid-1", {"net_rx_bps": 1_000})]  # 1 kbps — tiny
    out = _compute_baseline_from_samples(
        samples,
        expressions={"rx_bps": "value * 3"},
        min_threshold={"rx_bps": 10_000_000},  # 10 Mbps floor
    )
    # value * 3 = 3000 → MIN → 10_000_000
    assert out["uuid-1"]["rx_bps"] == 10_000_000


def test_effective_thresholds_merge():
    """effective = max(default, baseline) per node per metric."""
    fake = _install_fake_asyncpg()
    from ddos_monitoring.poller import _effective_thresholds
    default = {"rx_bps": 200_000_000, "rx_pps": 30_000}
    baseline = {"rx_bps": 50_000_000, "rx_pps": 5_000}
    eff = _effective_thresholds(default, baseline)
    assert eff["rx_bps"] == 200_000_000  # max → default wins (200M > 50M)
    baseline2 = {"rx_bps": 500_000_000, "rx_pps": 100_000}
    eff2 = _effective_thresholds(default, baseline2)
    assert eff2["rx_bps"] == 500_000_000  # baseline wins (500M > 200M)


def test_empty_baseline_falls_back_to_default():
    """Если baseline нет — всё возвращает default."""
    fake = _install_fake_asyncpg()
    from ddos_monitoring.poller import _effective_thresholds
    default = {"rx_bps": 200_000_000}
    out = _effective_thresholds(default, {})
    assert out == default


if __name__ == "__main__":
    test_baseline_p95_calculation()
    test_min_threshold_floor()
    test_effective_thresholds_merge()
    test_empty_baseline_falls_back_to_default()
    print("[i] all 4 baseline tests passed")