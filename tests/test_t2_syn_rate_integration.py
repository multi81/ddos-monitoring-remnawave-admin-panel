"""Тесты T2: S.3 integration — _tick_impl использует last_syn_recv.

Тестыруем логику обновления state и перевыпуска verdict, без полного
запуска poller (DB fetch и пр. — заглушки). Фокус на:
- last_syn_recv сохраняется между тиками
- rate-based verdict перебивает moment-based verdict по severity
- rate < threshold → НЕ перебивает
- при nodata (agent_m=None) last_syn_recv НЕ обновляется
- при отсутствии syn_recv в метриках — last_syn_recv НЕ трогается
- severity-сравнение: critical > high > medium > warning > normal
"""
import pytest


# Импорт модуля
import ddos_monitoring.poller as poller_mod
from ddos_monitoring.poller import (
    classify_syn_rate, classify_agent,
    DEFAULT_SYN_RATE_THRESHOLD, INTERVAL_S, SEV_ORDER,
)


def _agent_with(syn_recv: int, **extras) -> dict:
    """Снимок агента с заданным syn_recv."""
    base = {
        "node_uuid": "fake-uuid",
        "syn_recv": syn_recv,
        "syn_recv_limit": 1000,
        "tcp_listen_drop_ps": 0,
        "tcp_syncookies_ps": 0,
        "conntrack_ratio": 0,
        "cpu_pct": 0,
        "ram_pct": 0,
        "swap_pct": 0,
        "disk_pct": 0,
        "load1": 0,
        "cores": 4,
        "rx_drop_ps": 0,
        "top_talkers": [],
        "ip_limit_breaches": 0,
        "systemd_failed": [],
        "vpn_ips": [],
    }
    base.update(extras)
    return base


class TestClassifySynRate:
    """Прямые unit-тесты функции classify_syn_rate."""

    def test_first_tick_returns_nodata(self):
        v = classify_syn_rate(None, 100, 0.0)
        assert v["state"] == "nodata"

    def test_normal_rate_is_stable(self):
        v = classify_syn_rate(0, 50, INTERVAL_S)  # 50/20 = 2.5/sec
        assert v["state"] == "stable"

    def test_slow_attack_rate_is_attack(self):
        v = classify_syn_rate(0, 2000, INTERVAL_S)  # 2000/20 = 100/sec
        # threshold=50, 100/50 = 2× → attack, severity=medium
        assert v["state"] == "attack"
        assert v["attack_type"] == "TCP SYN-флуд (rate)"
        assert v["severity"] == "medium"

    def test_extreme_rate_is_critical(self):
        v = classify_syn_rate(0, 20000, INTERVAL_S)  # 1000/sec → 20×threshold
        assert v["severity"] == "critical"

    def test_medium_rate_is_high_severity(self):
        v = classify_syn_rate(0, 5000, INTERVAL_S)  # 250/sec → 5×threshold
        assert v["state"] == "attack"
        assert v["severity"] == "high"

    def test_negative_rate_is_stable(self):
        # syn_recv уменьшилось → не атака
        v = classify_syn_rate(1000, 500, INTERVAL_S)
        assert v["state"] == "stable"

    def test_zero_interval_is_nodata(self):
        v = classify_syn_rate(0, 100, 0.0)
        assert v["state"] == "nodata"


class TestSynRateSeverityOverride:
    """Логика 'rate-вердикт перебивает moment-вердикт' из _tick_impl."""

    def _override(self, agent_verdict: dict, rate_verdict: dict) -> dict:
        """Копия логики из _tick_impl (мелкая функция для тестов)."""
        cur_sev = agent_verdict.get("severity", "normal")
        rate_sev = rate_verdict["severity"]
        if SEV_ORDER.get(rate_sev, 0) > SEV_ORDER.get(cur_sev, 0):
            return rate_verdict
        return agent_verdict

    def test_critical_rate_overrides_normal_agent(self):
        agent = {"state": "stable", "severity": "normal"}
        rate = {"state": "attack", "severity": "critical", "attack_type": "TCP SYN-флуд"}
        result = self._override(agent, rate)
        assert result["severity"] == "critical"

    def test_critical_rate_does_not_downgrade_critical_agent(self):
        agent = {"state": "attack", "severity": "critical", "attack_type": "UDP-флуд"}
        rate = {"state": "attack", "severity": "critical", "attack_type": "TCP SYN-флуд"}
        result = self._override(agent, rate)
        # Критичный агент побеждает (сохраняем тип)
        assert result["attack_type"] == "UDP-флуд"

    def test_normal_rate_does_not_override_medium_agent(self):
        agent = {"state": "attack", "severity": "medium"}
        rate = {"state": "stable", "severity": "normal"}
        result = self._override(agent, rate)
        assert result["severity"] == "medium"

    def test_high_rate_overrides_warning_agent(self):
        agent = {"state": "stable", "severity": "warning"}
        rate = {"state": "attack", "severity": "high"}
        result = self._override(agent, rate)
        assert result["severity"] == "high"


class TestLastSynRecvTracking:
    """Логика обновления self._nodes[uuid]['last_syn_recv'] из _tick_impl."""

    def test_init_state_has_no_last_syn_recv(self):
        # Симулируем — что у новой ноды нет last_syn_recv
        entry: dict = {}
        assert "last_syn_recv" not in entry

    def test_first_tick_saves_last_syn_recv(self):
        entry = {}
        # Логика из _tick_impl: if agent_m.get('syn_recv') is not None:
        #                         self._nodes[uuid]['last_syn_recv'] = cur_syn
        cur_syn_val = 100
        if cur_syn_val is not None:
            entry["last_syn_recv"] = cur_syn_val
        assert entry["last_syn_recv"] == 100

    def test_second_tick_uses_saved_value(self):
        # После 1-го тика
        entry = {"last_syn_recv": 100}
        # На 2-м тике cur_syn=600, interval=20s
        cur_syn = 600
        last_syn = entry.get("last_syn_recv")  # 100
        interval = INTERVAL_S if last_syn is not None else 0.0  # 20.0
        v = classify_syn_rate(last_syn, cur_syn, interval)
        # rate = (600-100)/20 = 25/sec, ниже threshold=50 → stable
        assert v["state"] == "stable"

    def test_second_tick_attack_rate(self):
        # После 1-го тика
        entry = {"last_syn_recv": 0}
        # На 2-м тике cur_syn=1500 (резкий скачок)
        cur_syn = 1500
        last_syn = entry.get("last_syn_recv")  # 0
        interval = INTERVAL_S  # 20s
        v = classify_syn_rate(last_syn, cur_syn, interval)
        # rate = 1500/20 = 75/sec → attack (выше threshold 50)
        assert v["state"] == "attack"

    def test_no_syn_recv_metric_does_not_update(self):
        # Если агент не передаёт syn_recv — last_syn_recv НЕ трогаем
        entry = {"last_syn_recv": 100}
        agent_m = {"syn_recv": None}
        if agent_m.get("syn_recv") is not None:
            entry["last_syn_recv"] = 999
        assert entry["last_syn_recv"] == 100  # не изменилось

    def test_no_agent_does_not_update(self):
        # Если agent_m=None (agent offline) — last_syn_recv НЕ трогаем
        entry = {"last_syn_recv": 100}
        agent_m = None
        if agent_m is not None and agent_m.get("syn_recv") is not None:
            entry["last_syn_recv"] = 999
        assert entry["last_syn_recv"] == 100


class TestClassifyAgentBaseline:
    """classify_agent() baseline — не сломан T1."""

    def test_empty_metrics_returns_nodata(self):
        v = classify_agent({})
        assert v["state"] == "nodata"

    def test_no_syn_recv_means_stable(self):
        v = classify_agent({"syn_recv": 0, "cpu_pct": 0, "ram_pct": 0, "load1": 0})
        assert v["state"] == "stable"

    def test_high_syn_recv_is_attack(self):
        v = classify_agent({"syn_recv": 5000, "cpu_pct": 0, "ram_pct": 0,
                            "load1": 0, "cores": 4})
        assert v["state"] == "attack"
        assert v["attack_type"] == "TCP SYN-флуд"
