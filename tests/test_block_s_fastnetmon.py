"""Тесты block S: применение идей fastnetmon.

S.1 — per-protocol thresholds (TCP/UDP/ICMP bandwidth + pps).
S.2 — TTL закрытие висящих записей атак.
S.3 — SYN-rate detector (рост syn_recv/sec).

Все тесты — pure functions, без БД/IO.
"""
from __future__ import annotations

import importlib

import pytest

poller = importlib.import_module("ddos_monitoring.poller")


# ── S.1 per-protocol thresholds ──────────────────────────────────

def _agent_with_protocols(tcp_mbps=0.0, udp_mbps=0.0, icmp_mbps=0.0,
                           tcp_pps=0, udp_pps=0, icmp_pps=0,
                           syn_recv=0, **extra):
    """Снимок агента с per-protocol метриками. Mbps — для удобства тестов;
    внутри переводится в байт/с, как передаёт реальный агент."""
    m = {
        "rx_bytes": 0, "tx_bytes": 0, "rx_pps": 0, "tx_pps": 0,
        "syn_recv": syn_recv, "rx_drop": 0, "tx_drop": 0,
        "cpu_pct": 0.0, "ram_pct": 0.0, "cores": 1, "load1": 0.0,
        "swap_pct": 0.0, "disk_pct": 0.0,
        "tcp_bytes": tcp_mbps * 125_000,        # Мбит/с → байт/с (делим на 8)
        "udp_bytes": udp_mbps * 125_000,
        "icmp_bytes": icmp_mbps * 125_000,
        "tcp_pps": tcp_pps, "udp_pps": udp_pps, "icmp_pps": icmp_pps,
        "failed_units": [], "ip_limit_breaches": [], "vpn_ips": [],
    }
    m.update(extra)
    return m


def test_s1_udp_flood_above_per_protocol_threshold_is_attack():
    """UDP-флуд 60 Мбит/с при дефолтном threshold_udp_mbps=50 → attack."""
    m = _agent_with_protocols(udp_mbps=60_000_000)
    v = poller.classify_agent(m)
    assert v["state"] == "attack"
    assert "UDP" in v["attack_type"] or "udp" in v["attack_type"].lower()


def test_s1_tcp_flood_above_per_protocol_threshold_is_attack():
    """TCP-флуд 120 Мбит/с при дефолтном threshold_tcp_mbps=100 → attack."""
    m = _agent_with_protocols(tcp_mbps=120_000_000)
    v = poller.classify_agent(m)
    assert v["state"] == "attack"
    assert "TCP" in v["attack_type"]


def test_s1_icmp_flood_above_per_protocol_threshold_is_attack():
    """ICMP-флуд 20 Мбит/с при дефолтном threshold_icmp_mbps=10 → attack."""
    m = _agent_with_protocols(icmp_mbps=20_000_000)
    v = poller.classify_agent(m)
    assert v["state"] == "attack"
    assert "ICMP" in v["attack_type"]


def test_s1_below_per_protocol_threshold_is_stable():
    """Все протоколы ниже своих порогов — stable."""
    m = _agent_with_protocols(tcp_mbps=10.0, udp_mbps=5.0, icmp_mbps=1.0)
    v = poller.classify_agent(m)
    assert v["state"] == "stable"


def test_s1_per_protocol_thresholds_are_configurable():
    """Кастомные пороги через параметр."""
    m = _agent_with_protocols(udp_mbps=15.0)
    # С дефолтным порогом 100 Мбит — stable
    v_default = poller.classify_agent(m)
    assert v_default["state"] == "stable"
    # С кастомным порогом 10 Мбит — attack (15 > 10)
    v_low = poller.classify_agent(m, udp_mbps_threshold=10.0)
    assert v_low["state"] == "attack"


def test_s1_severity_uses_configured_threshold_not_hardcoded():
    """Severity считается по ratio = actual/threshold, не hardcoded.
    При threshold=100 и actual=120 — medium (ratio=1.2 < 1.5)."""
    m = _agent_with_protocols(udp_mbps=120.0)
    v = poller.classify_agent(m, udp_mbps_threshold=100.0)
    assert v["severity"] == "medium"


def test_s1_severity_high_at_1_5x_threshold():
    """ratio >= 1.5 → high."""
    m = _agent_with_protocols(udp_mbps=180.0)
    v = poller.classify_agent(m, udp_mbps_threshold=100.0)
    assert v["severity"] == "high"


def test_s1_severity_critical_at_3x_threshold():
    """ratio >= 3.0 → critical."""
    m = _agent_with_protocols(udp_mbps=350.0)
    v = poller.classify_agent(m, udp_mbps_threshold=100.0)
    assert v["severity"] == "critical"


def test_s1_lowered_threshold_changes_severity():
    """Если admin снизил threshold — severity должна расти (не быть pinned)."""
    m = _agent_with_protocols(udp_mbps=180.0)
    # С дефолтным 100 Мбит → ratio=1.8 → high
    v_default = poller.classify_agent(m, udp_mbps_threshold=100.0)
    assert v_default["severity"] == "high"
    # С кастомным 50 Мбит → ratio=3.6 → critical
    v_low = poller.classify_agent(m, udp_mbps_threshold=50.0)
    assert v_low["severity"] == "critical"


def test_s1_no_protocol_metrics_means_stable():
    """Если per-protocol метрик нет вообще — никакой attack на них."""
    m = _agent_with_protocols()  # всё 0
    v = poller.classify_agent(m)
    assert v["state"] == "stable"


# ── S.2 TTL для висящих записей ──────────────────────────────────

def test_s2_stale_attack_closure_function_exists():
    """Должна быть функция close_stale_attacks(ctx, ttl_s=7200)."""
    data = importlib.import_module("ddos_monitoring.data")
    assert hasattr(data, "close_stale_attacks")
    assert callable(data.close_stale_attacks)


def test_s2_stale_attack_closure_default_ttl_2h():
    """TTL по умолчанию 7200 секунд (2 часа)."""
    import inspect
    data = importlib.import_module("ddos_monitoring.data")
    sig = inspect.signature(data.close_stale_attacks)
    assert "ttl_s" in sig.parameters
    assert sig.parameters["ttl_s"].default == 7200


def test_s2_negative_ttl_raises_value_error():
    """ttl_s <= 0 — ValueError (защита от mass-closing при NOW()+N)."""
    import asyncio
    data = importlib.import_module("ddos_monitoring.data")

    class _StubCtx:
        class db:
            @staticmethod
            async def fetchrow(*args, **kwargs):
                raise RuntimeError("should not reach DB")
    try:
        asyncio.run(data.close_stale_attacks(_StubCtx(), ttl_s=-100))
    except ValueError as e:
        assert "> 0" in str(e)
    else:
        raise AssertionError("ValueError expected")


def test_s2_zero_ttl_raises_value_error():
    """ttl_s=0 — ValueError (аналогично negative)."""
    import asyncio
    data = importlib.import_module("ddos_monitoring.data")

    class _StubCtx:
        class db:
            @staticmethod
            async def fetchrow(*args, **kwargs):
                raise RuntimeError("should not reach DB")
    try:
        asyncio.run(data.close_stale_attacks(_StubCtx(), ttl_s=0))
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError expected")


def test_s2_return_count_uses_count_aggregate():
    """SQL использует WITH closed AS (... RETURNING id) + count(*).
    Это гарантирует правильный count даже если несколько записей."""
    import inspect
    data = importlib.import_module("ddos_monitoring.data")
    src = inspect.getsource(data.close_stale_attacks)
    assert "count(*)" in src
    assert "WITH closed AS" in src
    # Не должно быть просто `RETURNING id` без count — это L2 из reviewer
    assert src.count("RETURNING id") <= 1, "RETURNING id должен быть внутри CTE"


# ── S.3 SYN-rate detector ─────────────────────────────────────────

def test_s3_syn_rate_function_exists():
    """Должна быть функция classify_syn_rate(prev_syn, cur_syn, interval_s)."""
    assert hasattr(poller, "classify_syn_rate")
    assert callable(poller.classify_syn_rate)


def test_s3_no_data_returns_nodata():
    """Без предыдущего значения — nodata."""
    v = poller.classify_syn_rate(None, 5000, 20)
    assert v["state"] == "nodata"


def test_s3_normal_rate_is_stable():
    """syn_recv растёт медленно (нормальный трафик) — stable."""
    v = poller.classify_syn_rate(1000, 1100, 20)  # +100 за 20 сек
    assert v["state"] == "stable"


def test_s3_slow_syn_attack_is_attack():
    """syn_recv растёт быстро при малом абсолютном значении — SYN-флуд.

    Критерий: rate/sec > SYN_RATE_THRESHOLD, даже если syn_recv < AGENT_SYN_RECV_LIMIT.
    """
    # syn_recv 800 (ниже AGENT_SYN_RECV_LIMIT=1000), но rate +200/сек за 20 сек = 200/sec
    v = poller.classify_syn_rate(0, 800, 4)  # 200/sec
    assert v["state"] == "attack"
    assert "SYN" in v["attack_type"]


def test_s3_high_syn_rate_is_critical():
    """Большой rate → critical severity."""
    v = poller.classify_syn_rate(0, 5000, 5)  # 1000/sec
    assert v["state"] == "attack"
    assert v["severity"] == "critical"


def test_s3_zero_interval_is_nodata():
    """interval_s == 0 — не делим на ноль."""
    v = poller.classify_syn_rate(0, 1000, 0)
    assert v["state"] == "nodata"


def test_s3_negative_rate_is_stable():
    """syn_recv упал (нормальное явление при легитимных соединениях) — stable."""
    v = poller.classify_syn_rate(2000, 1500, 20)
    assert v["state"] == "stable"
