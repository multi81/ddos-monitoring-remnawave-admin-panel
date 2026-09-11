"""Regression: cross-node threshold leak.

Если нода A имеет baseline {rx_bps: 500_000_000}, а нода B без baseline,
то нода B НЕ должна наследовать порог от A. Иначе:
- B пропустит атаку на 300 Mbps (порог наследован A=500M)
- False NEGATIVE на attack detection

Это критический баг — пропуск реальных DDoS.
"""
from __future__ import annotations

import asyncio
import pytest


class FakeRow(dict):
    def __getattr__(self, k):
        return self.get(k)


class FakeDB:
    def __init__(self):
        self.calls = []
        self.responses = {}

    async def fetch(self, sql, *args):
        self.calls.append((sql, args))
        # baseline_mode запрос возвращает True
        if "baseline_mode" in sql or "baseline" in sql.lower():
            if "node_baseline" in sql:
                uuid = args[0] if args else ""
                return self.responses.get(("baseline", uuid), [])
            return [True]
        # Другие запросы возвращают пусто (здесь не нужны)
        return []


class FakeCtx:
    def __init__(self):
        self.db = FakeDB()


def test_threshold_reset_per_node(monkeypatch):
    """Каждая нода должна начинать с DEFAULT_THRESHOLDS, не с предыдущей."""
    import ddos_monitoring.poller as P

    ctx = FakeCtx()
    # При запросе baseline для uuid-A → есть {rx_bps: 500_000_000}
    ctx.db.responses[("baseline", "uuid-A")] = [
        FakeRow({"metric": "rx_bps", "baseline_value": 500_000_000.0}),
    ]
    # При запросе baseline для uuid-B → пусто
    ctx.db.responses[("baseline", "uuid-B")] = []

    monkeypatch.setattr(P, "_ctx_ref", lambda: ctx)

    poller = P.DdosPoller()

    # Имитируем реальный tick без полного цикла — только `_thresholds` логика
    th_raw = None
    th_A = poller._thresholds(th_raw)
    th_A_with_baseline = poller._thresholds(
        th_raw,
        ctx.db.responses[("baseline", "uuid-A")][0] and {
            r["metric"]: float(r["baseline_value"])
            for r in ctx.db.responses[("baseline", "uuid-A")]
        },
    )

    # Reset для следующей ноды
    th_B_reset = poller._thresholds(th_raw)
    th_B_with_baseline = poller._thresholds(th_raw, None)  # НЕТ baseline

    # A имеет повышенный порог (baseline 500M)
    assert th_A_with_baseline["rx_bps"] >= 500_000_000.0

    # B начинает с reset (default 200M), НЕ наследует A
    assert th_B_with_baseline["rx_bps"] == 200_000_000.0, (
        f"BUG: нода B наследовала порог A. Получила {th_B_with_baseline['rx_bps']}, "
        f"должна быть 200_000_000.0 (DEFAULT_THRESHOLDS)"
    )


def test_apply_expression_zerodivision():
    """Деление на ноль → ValueError (не крашит tick)."""
    from ddos_monitoring.poller import _apply_expression
    with pytest.raises(ValueError):
        # value/(value-value) = 100/0 = ZeroDivisionError, ловится как ValueError через (Z, V, S)
        _apply_expression(100.0, "value / (value - value)")


def test_apply_expression_length_cap():
    """Выражение > 256 символов → ValueError."""
    from ddos_monitoring.poller import _apply_expression
    long_expr = "value * 1" + " + 1" * 200  # > 256 символов
    assert len(long_expr) > 256
    with pytest.raises(ValueError, match="too long"):
        _apply_expression(1.0, long_expr)


def test_apply_expression_empty():
    """Пустая строка → ValueError (нет 'value')."""
    from ddos_monitoring.poller import _apply_expression
    with pytest.raises(ValueError, match="must contain 'value'"):
        _apply_expression(1.0, "")


def test_apply_expression_no_value():
    """Выражение без 'value' → ValueError."""
    from ddos_monitoring.poller import _apply_expression
    with pytest.raises(ValueError, match="must contain 'value'"):
        _apply_expression(1.0, "100 + 200")
