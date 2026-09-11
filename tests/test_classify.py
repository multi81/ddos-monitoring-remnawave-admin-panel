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
    # 220 Mbps при дефолтном пороге 200 Mbps — ratio ~1.1, должно быть атакой.
    v = classify(_m(net_rx_bps=220_000_000), TH)
    assert v["state"] == "attack"
    assert v["severity"] in ("medium", "high")
    assert "входящий трафик" in v["reasons"]


def test_syn_flood_by_syncookies():
    # 250 syncookies/s при пороге 200 — атака, тип TCP SYN-флуд.
    v = classify(_m(tcp_syncookies_ps=250), TH)
    assert v["state"] == "attack"
    assert v["attack_type"] == "TCP SYN-флуд"
    assert v["severity"] in ("medium", "high")


def test_critical_severity_at_3x():
    # 4x порога pps (30_000*4 = 120_000) — должно быть critical.
    v = classify(_m(net_rx_pps=120_000), TH)
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
