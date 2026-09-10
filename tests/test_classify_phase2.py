"""Фаза 2: состояния load / health / offline в classify()."""

from ddos_monitoring.poller import DEFAULT_THRESHOLDS, classify


def _th():
    return dict(DEFAULT_THRESHOLDS)


def test_load_cpu_high_returns_state_load():
    metrics = {"net_rx_bps": 1_000_000, "net_rx_pps": 100, "cpu_usage": 96.0,
               "memory_usage": 30.0}
    v = classify(metrics, _th())
    assert v["state"] == "load"
    assert "CPU" in v["reasons"]


def test_load_ram_high_returns_state_load():
    metrics = {"net_rx_bps": 1_000_000, "net_rx_pps": 100, "cpu_usage": 10.0,
               "memory_usage": 96.0}
    v = classify(metrics, _th())
    assert v["state"] == "load"
    assert "RAM" in v["reasons"]


def test_stable_when_all_normal():
    metrics = {"net_rx_bps": 1_000_000, "net_rx_pps": 100, "cpu_usage": 10.0,
               "memory_usage": 20.0, "disk_usage": 40.0,
               "net_rx_drop_ps": 0.0}
    v = classify(metrics, _th())
    assert v["state"] == "stable"


def test_health_disk_high():
    metrics = {"net_rx_bps": 1_000_000, "net_rx_pps": 100, "cpu_usage": 10.0,
               "memory_usage": 20.0, "disk_usage": 95.0}
    v = classify(metrics, _th())
    assert v["state"] == "health"
    assert "Диск" in v["reasons"]


def test_health_network_drops():
    th = _th()
    metrics = {"net_rx_bps": 1_000_000, "net_rx_pps": 100, "cpu_usage": 10.0,
               "memory_usage": 20.0, "net_rx_drop_ps": th["rx_drop_ps"] * 5}
    v = classify(metrics, th)
    assert v["state"] == "health"
    assert "Сеть" in v["reasons"]


def test_attack_beats_load_even_with_full_cpu():
    """Атака приоритетнее load: при флуде и CPU 100% вердикт attack."""
    th = _th()
    metrics = {"net_rx_bps": th["rx_bps"] * 5, "net_rx_pps": 100,
               "conntrack_count": 0, "conntrack_max": 0,
               "tcp_syncookies_ps": 0, "tcp_listen_drop_ps": 0,
               "cpu_usage": 100.0, "memory_usage": 90.0}
    v = classify(metrics, th)
    assert v["state"] == "attack"


def test_nodata_on_missing_metrics():
    v = classify(None, _th())
    assert v["state"] == "nodata"
