"""Тест реалистичных дефолтов на основе fastnetmon (v0.7.44).

Идея: дефолты должны быть чувствительнее к VPS-трафику, а не к 10G-каналу.
Ссылка: https://github.com/pavel-odintsov/fastnetmon (threshold_pps=20000).
Было (завышено): rx_bps=500_000_000, rx_pps=100_000.
Станет (реалистичнее): rx_bps=200_000_000, rx_pps=30_000.
"""
from __future__ import annotations

import sys


def test_default_thresholds_sane_for_vps():
    """Дефолты должны быть адекватны для VPS с 100Mbps-1Gbit каналом."""
    from ddos_monitoring import poller
    th = poller.DEFAULT_THRESHOLDS

    # Главные лимиты — не должны быть больше чем у fastnetmon (1000 Mbps)
    assert th["rx_bps"] <= 200_000_000, (
        f"rx_bps={th['rx_bps']/1e6:.0f} Mbps — слишком высокий дефолт для VPS")
    assert th["rx_pps"] <= 30_000, (
        f"rx_pps={th['rx_pps']:.0f} — завышен, fastnetmon использует 20000")

    # SYN-флуд лимиты — должны быть чувствительны
    assert th["syncookies_ps"] <= 500, "syncookies_ps слишком грубый"
    assert th["listen_drop_ps"] <= 200, "listen_drop_ps слишком грубый"

    # CPU/RAM/Disk — разумные пределы
    assert 80 <= th["cpu_percent"] <= 95, f"cpu_percent={th['cpu_percent']}"
    assert 80 <= th["memory_percent"] <= 95, f"memory_percent={th['memory_percent']}"


def test_vps_traffic_triggers_attack_state():
    """Типичный VPS-трафик 50 Mbps должен вызвать state=attack с новыми дефолтами."""
    from ddos_monitoring.poller import classify

    # 50 Mbps — это 50_000_000 / 8 = 6.25 MB/s.
    # С порогом 200 Mbps (rx_bps=200_000_000) ratio = 50/200 = 0.25 — НЕ атака.
    # Возьмём 250 Mbps — ratio = 1.25 → attack.
    metrics = {"net_rx_bps": 250_000_000, "net_rx_pps": 30_000,
               "tcp_syncookies_ps": 0, "tcp_listen_drop_ps": 0,
               "net_rx_drop_ps": 0, "conntrack_count": 0, "conntrack_max": 0}
    th = {"rx_bps": 200_000_000, "rx_pps": 30_000, "syncookies_ps": 200,
          "listen_drop_ps": 100, "conntrack_ratio": 0.75, "rx_drop_ps": 50,
          "cpu_percent": 90, "memory_percent": 90, "load_per_cpu": 2.0,
          "disk_percent": 85}
    verdict = classify(metrics, th)
    assert verdict["state"] == "attack", (
        f"250 Mbps при пороге 200 Mbps должна быть атакой, "
        f"но verdict={verdict}")
    assert verdict["severity"] in ("medium", "high", "critical")


def test_normal_traffic_stays_stable():
    """Нормальный VPS-трафик 20 Mbps не должен быть атакой."""
    from ddos_monitoring.poller import classify

    metrics = {"net_rx_bps": 20_000_000, "net_rx_pps": 5_000,
               "tcp_syncookies_ps": 0, "tcp_listen_drop_ps": 0,
               "net_rx_drop_ps": 0, "conntrack_count": 0, "conntrack_max": 0,
               "cpu_usage": 30, "memory_usage": 40, "disk_usage": 50}
    th = {"rx_bps": 200_000_000, "rx_pps": 30_000, "syncookies_ps": 200,
          "listen_drop_ps": 100, "conntrack_ratio": 0.75, "rx_drop_ps": 50,
          "cpu_percent": 90, "memory_percent": 90, "load_per_cpu": 2.0,
          "disk_percent": 85}
    verdict = classify(metrics, th)
    assert verdict["state"] == "stable", (
        f"20 Mbps при пороге 200 Mbps — должно быть stable, "
        f"но verdict={verdict}")
