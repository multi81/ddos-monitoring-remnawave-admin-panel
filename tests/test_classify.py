"""Тесты classify: пороги, типы атак, severity. Перенос логики старого монитора."""
from __future__ import annotations

from ddos_monitoring.poller import DEFAULT_THRESHOLDS as TH
from ddos_monitoring.poller import classify


def _m(**kw):
    base = {"net_rx_bps": 0, "net_rx_pps": 0, "net_rx_drop_ps": 0,
            "conntrack_count": 0, "conntrack_max": 1_000_000,
            "tcp_syncookies_ps": 0, "tcp_listen_drop_ps": 0}
    base.update(kw)
    return base


def test_nodata_when_no_metrics():
    v = classify(None, TH)
    assert v["state"] == "nodata"
    v = classify({}, TH)
    assert v["state"] == "nodata"


def test_stable_on_quiet_node():
    assert classify(_m(), TH)["state"] == "stable"


def test_volume_flood_by_bps():
    v = classify(_m(net_rx_bps=600_000_000), TH)  # 600 Мбит/с > 500
    assert v["state"] == "attack"
    assert v["severity"] == "medium"
    assert "входящий трафик" in v["reasons"]


def test_syn_flood_by_syncookies():
    v = classify(_m(tcp_syncookies_ps=1_200), TH)
    assert v["state"] == "attack"
    assert v["attack_type"] == "TCP SYN-флуд"
    assert v["severity"] == "medium"


def test_critical_severity_at_3x():
    v = classify(_m(net_rx_pps=400_000), TH)  # 4x порога pps
    assert v["state"] == "attack"
    assert v["severity"] == "critical"


def test_conntrack_exhaustion():
    v = classify(_m(conntrack_count=980_000, conntrack_max=1_000_000), TH)
    assert v["state"] == "attack"
    assert v["attack_type"] == "conntrack-исчерпание"


def test_below_threshold_is_stable():
    v = classify(_m(net_rx_bps=100_000_000, net_rx_pps=10_000), TH)
    assert v["state"] == "stable"
    assert v["reasons"] == []


def test_garbage_values_do_not_crash():
    m = _m()
    m["net_rx_bps"] = None
    m["conntrack_max"] = 0  # деление на ноль в ratio
    v = classify(m, TH)
    assert v["state"] in {"stable", "attack"}
