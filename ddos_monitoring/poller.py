"""Poller: чтение телеметрии нод из БД панели + детект атак.

Перенос логики ddos-monitoring-monitor (classify/пороги/подтверждения) с
источником node_metrics_snapshots вместо SSH. Контракт как у live-flow:
tick-lock от наложения, общий таймаут тика + на запрос, экспоненциальный
backoff, при сбое прошлый срез сохраняется, наружу только код ошибки.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("plugin.ddos-monitoring")

from . import data, notify  # noqa: E402 — модульные зависимости

INTERVAL_S = 20
TICK_TIMEOUT_S = 15.0
REQUEST_TIMEOUT_S = 10.0
BACKOFF_BASE_S = 5.0
BACKOFF_MAX_S = 300.0

# Подтверждения (перенос из старого монитора)
ATTACK_CONFIRMATIONS = 2
RECOVERY_CONFIRMATIONS = 3
ALERT_COOLDOWN_S = 300.0
# Срез телеметрии считается свежим не дольше этого срока; дальше — stale.
STALE_AFTER_S = 120.0

# Пороги по умолчанию пересмотрены в v0.7.44 (на основе fastnetmon defaults):
#   - threshold_pps=20_000 (fastnetmon docs)
#   - threshold_mbps=1_000 (fastnetmon docs)
# Старые значения (500 Mbps / 100k pps) слишком грубые для VPS с 100Mbps-
# 1Gbit каналом. Эти дефолты дают разумный баланс: ловят заметные атаки,
# но не спамят алертами на легитимном трафике. Перекрываются через
# plugin_settings.thresholds.
DEFAULT_THRESHOLDS: dict[str, float] = {
    "rx_bps": 200_000_000.0,        # 200 Мбит/с входящий (было 500)
    "rx_pps": 30_000.0,             # 30k pps (было 100k)
    "syncookies_ps": 200.0,         # SYN cookies (было 1000)
    "listen_drop_ps": 100.0,        # listen drops (было 500)
    "conntrack_ratio": 0.75,
    "rx_drop_ps": 50.0,             # (было 100)
    # Фаза 2 (перенос Thresholds легаси-монитора) — снижены для раннего
    # детекта на VPS-каналах.
    "cpu_percent": 90.0,            # (было 95)
    "memory_percent": 90.0,         # (было 95)
    "load_per_cpu": 2.0,            # (было 3)
    "disk_percent": 85.0,           # (было 90)
}


def _num(value: Any, default: float = 0.0) -> float:
    try:
        f = float(value)
        return f if f == f else default  # NaN-защита
    except (TypeError, ValueError):
        return default


def classify(metrics: dict[str, Any] | None, th: dict[str, float]) -> dict[str, Any]:
    """Вердикт по одному срезу метрик ноды. Формат как в старом мониторе:
    {state: attack|stable|nodata, attack_type, severity, target, reasons}."""
    if not metrics:
        return {"state": "nodata", "attack_type": "", "severity": "normal",
                "target": "", "reasons": []}

    rx_bps = _num(metrics.get("net_rx_bps"))
    rx_pps = _num(metrics.get("net_rx_pps"))
    syncookies = _num(metrics.get("tcp_syncookies_ps"))
    listen_drop = _num(metrics.get("tcp_listen_drop_ps"))
    rx_drop = _num(metrics.get("net_rx_drop_ps"))
    conntrack = _num(metrics.get("conntrack_count"))
    conntrack_max = _num(metrics.get("conntrack_max"))

    conntrack_ratio = conntrack / conntrack_max if conntrack_max > 0 else 0.0
    checks = {
        "входящий трафик": rx_bps / th["rx_bps"] if th["rx_bps"] > 0 else 0.0,
        "пакеты в секунду": rx_pps / th["rx_pps"] if th["rx_pps"] > 0 else 0.0,
        "SYN cookies": syncookies / th["syncookies_ps"] if th["syncookies_ps"] > 0 else 0.0,
        "listen drop": listen_drop / th["listen_drop_ps"] if th["listen_drop_ps"] > 0 else 0.0,
        "conntrack": conntrack_ratio / th["conntrack_ratio"] if th["conntrack_ratio"] > 0 else 0.0,
    }
    reasons = [name for name, ratio in checks.items() if ratio >= 1.0]
    peak_ratio = max(checks.values(), default=0.0)

    if reasons and peak_ratio >= 1.0:
        if syncookies >= max(th["syncookies_ps"] * 0.5, listen_drop):
            attack_type = "TCP SYN-флуд"
        elif conntrack_ratio >= 0.9:
            attack_type = "conntrack-исчерпание"
        elif listen_drop >= th["listen_drop_ps"]:
            attack_type = "TCP-флуд (переполнение очереди)"
        elif rx_pps / th["rx_pps"] if th["rx_pps"] > 0 else False:
            attack_type = "пакетный флуд"
        else:
            attack_type = "объёмный флуд"

        if peak_ratio >= 3.0 or conntrack_ratio >= 0.95:
            severity = "critical"
        elif peak_ratio >= 1.5:
            severity = "high"
        else:
            severity = "medium"
        return {"state": "attack", "attack_type": attack_type, "severity": severity,
                "target": "node", "reasons": reasons}

    # Фаза 2: load (CPU/RAM/Load Average) и health (диск/ошибки сети).
    # Порядок как в легаси: attack > load > health > stable.
    load_reasons: list[str] = []
    cpu = _num(metrics.get("cpu_usage"))
    mem = _num(metrics.get("memory_usage"))
    cpus = max(int(_num(metrics.get("cpu_cores"), 1)) or 1, 1)
    if th["cpu_percent"] > 0 and cpu >= th["cpu_percent"]:
        load_reasons.append("CPU")
    if th["memory_percent"] > 0 and mem >= th["memory_percent"]:
        load_reasons.append("RAM")
    # load1 в телеметрии панели нет — считаем по CPU/RAM; поле load1
    # опционально принимаем, если агент его начнёт присылать.
    if th["load_per_cpu"] > 0 and _num(metrics.get("load1")) >= cpus * th["load_per_cpu"]:
        load_reasons.append("Load Average")
    if load_reasons:
        return {"state": "load", "attack_type": "", "severity": "warning",
                "target": "", "reasons": load_reasons}

    health_reasons: list[str] = []
    disk = _num(metrics.get("disk_usage"))
    if th["disk_percent"] > 0 and disk >= th["disk_percent"]:
        health_reasons.append("Диск")
    rx_drop = _num(metrics.get("net_rx_drop_ps"))
    tx_drop = _num(metrics.get("net_tx_drop_ps"))
    if th["rx_drop_ps"] > 0 and max(rx_drop, tx_drop) >= th["rx_drop_ps"]:
        health_reasons.append("Сеть")
    if health_reasons:
        return {"state": "health", "attack_type": "", "severity": "warning",
                "target": "", "reasons": health_reasons}

    return {"state": "stable", "attack_type": "", "severity": "normal",
            "target": "", "reasons": []}


OFFLINE_CONFIRMATIONS = 2
SUMMARY_INTERVAL_S = 3600.0

# Пороги агентских метрик
AGENT_SYN_RECV_LIMIT = 1000       # SYN_RECV в очереди — признак SYN-флуда

# Per-protocol пороги (идея fastnetmon conf: threshold_tcp_mbps / threshold_udp_mbps /
# threshold_icmp_mbps + per-protocol pps). Дефолты — мягкие, настраиваются через
# classify_agent(..., *_threshold=...).
DEFAULT_TCP_MBPS = 100.0     # 100 Мбит/с
DEFAULT_UDP_MBPS = 100.0
DEFAULT_ICMP_MBPS = 100.0
DEFAULT_TCP_PPS = 100_000
DEFAULT_UDP_PPS = 100_000
DEFAULT_ICMP_PPS = 100_000

# SYN-rate: рост syn_recv/sec выше порога = SYN-флуд даже при syn_recv < AGENT_SYN_RECV_LIMIT.
# (медленный DDoS: маленькое абсолютное значение, но быстро растёт)
DEFAULT_SYN_RATE_THRESHOLD = 50.0  # syn_recv/сек


def _mbps(value: Any) -> float:
    """Перевод байт/с (метрика агента) в Мбит/с для сравнения с порогом."""
    return _num(value) * 8.0 / 1_000_000.0


# Единый источник истины для severity ordering (используется и тестами).
SEV_ORDER: dict[str, int] = {"warning": 0, "normal": 1, "medium": 2, "high": 3, "critical": 4}


def classify_syn_rate(
    prev_syn: int | None,
    cur_syn: int,
    interval_s: float,
    *,
    threshold: float = DEFAULT_SYN_RATE_THRESHOLD,
) -> dict[str, Any]:
    """Вердикт по скорости роста SYN_RECV.

    Идея fastnetmon: ловить «медленный SYN-флуд», когда абсолютное значение
    syn_recv ещё ниже AGENT_SYN_RECV_LIMIT, но растёт аномально быстро.

    Возвращает {state, attack_type, severity, target, reasons}.
    """
    if prev_syn is None or interval_s <= 0:
        return {"state": "nodata", "attack_type": "", "severity": "normal",
                "target": "", "reasons": []}
    delta = float(cur_syn) - float(prev_syn)
    if delta <= 0:
        return {"state": "stable", "attack_type": "", "severity": "normal",
                "target": "", "reasons": []}
    rate = delta / interval_s
    if rate >= threshold:
        # severity: 3× порога → high, 10× → critical
        if rate >= threshold * 10:
            sev = "critical"
        elif rate >= threshold * 3:
            sev = "high"
        else:
            sev = "medium"
        return {"state": "attack",
                "attack_type": "TCP SYN-флуд (rate)",
                "severity": sev,
                "target": "node",
                "reasons": [f"SYN_RECV rate: {rate:.0f}/s (порог {threshold:.0f}/s)"]}
    return {"state": "stable", "attack_type": "", "severity": "normal",
            "target": "", "reasons": []}


def classify_agent(
    m: dict[str, Any],
    *,
    exclude_vpn: bool = False,
    tcp_mbps_threshold: float = DEFAULT_TCP_MBPS,
    udp_mbps_threshold: float = DEFAULT_UDP_MBPS,
    icmp_mbps_threshold: float = DEFAULT_ICMP_MBPS,
    tcp_pps_threshold: float = DEFAULT_TCP_PPS,
    udp_pps_threshold: float = DEFAULT_UDP_PPS,
    icmp_pps_threshold: float = DEFAULT_ICMP_PPS,
) -> dict[str, Any]:
    """Вердикт по срезу ddos-agent (полные данные: systemd/SYN/per-IP/swap).

    exclude_vpn: превышения по легальным VPN-клиентам (m["vpn_ips"]) не
    триггерят атаку — считаются только внешние источники.

    Порядок проверок:
      1a) per-protocol thresholds (TCP/UDP/ICMP, Мбит/с + pps) — если в
          метриках агента есть tcp_bytes/udp_bytes/icmp_bytes/tcp_pps/...
      1b) ip_limit_breaches (легаси) — НЕ атака, а «Лимит IP» в state=health
      2)  SYN_RECV > AGENT_SYN_RECV_LIMIT → TCP SYN-флуд
      3)  systemd / Load/RAM/CPU/Swap → state=load/health

    Per-protocol thresholds по умолчанию 100 Мбит/с / 100k pps. Severity
    считается по ratio = actual/threshold (НЕ hardcoded), так что кастомные
    пороги через plugin_settings работают корректно.
    """
    if not m:
        return {"state": "nodata", "attack_type": "", "severity": "normal",
                "target": "", "reasons": []}

    vpn_ips = set(m.get("vpn_ips") or [])

    # Калибровка по легаси: превышение лимита соединений per-IP —
    # НЕ атака, а «Лимит IP» в 🟡 (состояние требует внимания). Атака
    # определяется по трафику/SYN (см. ниже и базовый classify).
    breaches = m.get("ip_limit_breaches") or []
    if exclude_vpn and vpn_ips:
        breaches = [b for b in breaches if b.get("ip") not in vpn_ips]

    # 1a) Per-protocol thresholds (идея fastnetmon: threshold_tcp_mbps /
    # threshold_udp_mbps / threshold_icmp_mbps + per-protocol pps).
    # Если в метриках есть per-protocol данные — детектим точечно.
    # severity считается по ratio = actual/threshold (не hardcoded — учитывает
    # настройки из plugin_settings).
    proto_reasons: list[str] = []
    proto_ratios: list[float] = []
    tcp_mbps_v = _mbps(m.get("tcp_bytes"))
    udp_mbps_v = _mbps(m.get("udp_bytes"))
    icmp_mbps_v = _mbps(m.get("icmp_bytes"))
    tcp_pps_v = _num(m.get("tcp_pps"))
    udp_pps_v = _num(m.get("udp_pps"))
    icmp_pps_v = _num(m.get("icmp_pps"))
    # Проверяем bandwidth
    if udp_mbps_threshold > 0 and udp_mbps_v >= udp_mbps_threshold:
        proto_reasons.append(f"UDP flood: {udp_mbps_v:.0f} Мбит/с")
        proto_ratios.append(udp_mbps_v / udp_mbps_threshold)
    if tcp_mbps_threshold > 0 and tcp_mbps_v >= tcp_mbps_threshold:
        proto_reasons.append(f"TCP flood: {tcp_mbps_v:.0f} Мбит/с")
        proto_ratios.append(tcp_mbps_v / tcp_mbps_threshold)
    if icmp_mbps_threshold > 0 and icmp_mbps_v >= icmp_mbps_threshold:
        proto_reasons.append(f"ICMP flood: {icmp_mbps_v:.0f} Мбит/с")
        proto_ratios.append(icmp_mbps_v / icmp_mbps_threshold)
    # Проверяем pps
    if udp_pps_threshold > 0 and udp_pps_v >= udp_pps_threshold:
        proto_reasons.append(f"UDP flood: {udp_pps_v:.0f} pps")
        proto_ratios.append(udp_pps_v / udp_pps_threshold)
    if tcp_pps_threshold > 0 and tcp_pps_v >= tcp_pps_threshold:
        proto_reasons.append(f"TCP flood: {tcp_pps_v:.0f} pps")
        proto_ratios.append(tcp_pps_v / tcp_pps_threshold)
    if icmp_pps_threshold > 0 and icmp_pps_v >= icmp_pps_threshold:
        proto_reasons.append(f"ICMP flood: {icmp_pps_v:.0f} pps")
        proto_ratios.append(icmp_pps_v / icmp_pps_threshold)
    if proto_reasons:
        # severity по максимальному превышению порога (НЕ hardcoded divisors)
        max_ratio = max(proto_ratios)
        if max_ratio >= 3.0:
            proto_severity = "critical"
        elif max_ratio >= 1.5:
            proto_severity = "high"
        else:
            proto_severity = "medium"
        # Определяем основной тип
        if any("UDP" in r for r in proto_reasons):
            attack_type = "UDP-флуд"
        elif any("ICMP" in r for r in proto_reasons):
            attack_type = "ICMP-флуд"
        else:
            attack_type = "TCP-флуд"
        return {"state": "attack", "attack_type": attack_type,
                "severity": proto_severity, "target": "node",
                "reasons": proto_reasons}

    # 2) SYN_RECV — очередь полуоткрытых соединений
    syn = int(_num(m.get("syn_recv")))
    if syn >= AGENT_SYN_RECV_LIMIT:
        return {"state": "attack",
                "attack_type": "TCP SYN-флуд",
                "severity": "critical" if syn >= AGENT_SYN_RECV_LIMIT * 5 else "high",
                "target": "node",
                "reasons": [f"SYN_RECV: {syn}"]}

    # 3) Health-причины по легаси: systemd, Лимит IP, Load/RAM/CPU, Swap, Диск, Сеть
    health_early: list[str] = []
    failed = [u for u in (m.get("failed_units") or []) if u]
    if failed:
        health_early.append("systemd")
        health_early.append(", ".join(failed))
    if breaches:
        top = sorted(breaches, key=lambda b: -int(b.get("count", 0)))[:3]
        health_early.append("Лимит IP")
        health_early.append("превышение по IP: " + ", ".join(
            f"{b.get('ip')} ({b.get('count')} соед.)" for b in top))
    if health_early:
        return {"state": "health", "attack_type": "", "severity": "warning",
                "target": "", "reasons": health_early}

    # 4) Load/RAM/CPU как в базовом classify, но поля агента
    cpus = max(int(_num(m.get("cores"), 1)) or 1, 1)
    load_reasons: list[str] = []
    if _num(m.get("cpu_pct")) >= DEFAULT_THRESHOLDS["cpu_percent"]:
        load_reasons.append("CPU")
    if _num(m.get("ram_pct")) >= DEFAULT_THRESHOLDS["memory_percent"]:
        load_reasons.append("RAM")
    if _num(m.get("load1")) >= cpus * DEFAULT_THRESHOLDS["load_per_cpu"]:
        load_reasons.append("Load Average")
    swap = _num(m.get("swap_pct"))
    if load_reasons:
        return {"state": "load", "attack_type": "", "severity": "warning",
                "target": "", "reasons": load_reasons}
    if swap >= 90.0:
        return {"state": "health", "attack_type": "", "severity": "warning",
                "target": "", "reasons": [f"Swap {swap:.0f}%"]}

    health_reasons: list[str] = []
    if _num(m.get("disk_pct")) >= DEFAULT_THRESHOLDS["disk_percent"]:
        health_reasons.append("Диск")
    drops = max(_num(m.get("rx_drop")), _num(m.get("tx_drop")))
    if drops >= DEFAULT_THRESHOLDS["rx_drop_ps"]:
        health_reasons.append("Сеть")
    if health_reasons:
        return {"state": "health", "attack_type": "", "severity": "warning",
                "target": "", "reasons": health_reasons}

    return {"state": "stable", "attack_type": "", "severity": "normal",
            "target": "", "reasons": []}
SEND_STARTUP_SUMMARY = True


class DdosPoller:
    def __init__(self) -> None:
        # per-node состояние переходов (перенос state-entry старого монитора)
        self._nodes: dict[str, dict[str, Any]] = {}
        self.as_of: float | None = None          # время последнего удачного тика
        self.error: str | None = None            # код для API, детали — в лог
        self.truncated = False
        self.ticks_ok = 0
        self.failures = 0
        self._next_allowed = 0.0
        self._tick_lock = asyncio.Lock()
        self._baseline_lock = asyncio.Lock()
        self._baseline_computed_at = 0.0  # epoch когда последний раз считали
        self._baseline_interval_s = 3600.0  # пересчёт раз в час
        self._baseline_window_days = 7
        self._schema_ready = False
        self._open_attacks: dict[str, int] = {}  # node_uuid → attack_id
        self._last_summary: float = 0.0
        self._startup_summary_sent = False
        self._restored = False
        self._restore_task: Any = None
        self._last_stale_close: float = 0.0  # rate-limit для close_stale_attacks

    # ── публичное состояние для /data ────────────────────────────────
    def public_state(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "error": self.error,
            "truncated": self.truncated,
            "stale": self.as_of is None or (time.time() - self.as_of) > STALE_AFTER_S,
            "nodes_monitored": len(self._nodes),
        }

    # ── TTL-закрытие зависших атак (S.2) ─────────────────────────────
    # Wire L1: close_stale_attacks() теперь вызывается из _tick_impl()
    # с rate-limit (раз в час). Контролируется через plugin_settings →
    # attack_stale_ttl_s. Дефолт 0 = ВЫКЛЮЧЕНО (безопасный старт).
    STALE_CLOSE_INTERVAL_S = 3600.0

    async def _maybe_close_stale(self, ctx, log: Any) -> int:
        """TTL-закрытие висящих attacks. Защита от mass-close:
        - attack_stale_ttl_s=0/missing → НЕ вызывается
        - attack_stale_ttl_s<0 → НЕ вызывается (защита)
        - rate-limit: не чаще чем раз в STALE_CLOSE_INTERVAL_S
        - DB-ошибка НЕ валит tick
        Возвращает количество закрытых записей (для логирования)."""
        try:
            raw = await self._fetch(ctx.settings.get("attack_stale_ttl_s"))
        except Exception:  # noqa: BLE001 — tick не должен падать на сбое settings
            log.warning("ddos-monitoring: failed to read attack_stale_ttl_s", exc_info=True)
            return 0
        try:
            ttl = int(raw) if raw is not None and str(raw).strip() else 0
        except (TypeError, ValueError):
            log.warning("ddos-monitoring: attack_stale_ttl_s=%r не int — пропуск", raw)
            return 0
        if ttl <= 0:
            return 0
        if time.time() - self._last_stale_close < self.STALE_CLOSE_INTERVAL_S:
            return 0
        from . import data
        self._last_stale_close = time.time()
        try:
            n = await data.close_stale_attacks(ctx, ttl_s=ttl)
            if n:
                log.info("ddos-monitoring: closed %d stale attacks (ttl=%ds)", n, ttl)
            return n
        except Exception:  # noqa: BLE001 — tick не должен падать на DB-сбое
            log.warning("ddos-monitoring: close_stale_attacks failed", exc_info=True)
            return 0

    def _fail(self, code: str, log: Any, msg: str, *args: Any, exc_info: bool = False) -> None:
        self.failures += 1
        self.error = code
        delay = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** min(self.failures - 1, 6)))
        self._next_allowed = time.time() + delay
        log.warning(msg + " (failures=%d, next in %.0fs)", *args, self.failures, delay, exc_info=exc_info)

    async def tick(self, log: Any = None) -> None:
        log = log or logger
        if not self._restored:
            self._restored = True
            # L2: restore — последовательно ПЕРЕД первым тиком (без fire-and-forget).
            # Иначе restore и _tick_impl писали бы в self._nodes/_open_attacks
            # параллельно и могли бы рассинхронизировать состояние.
            await self._restore_states_safe(log)
        if self._tick_lock.locked():
            log.warning("ddos-monitoring: previous tick still running — skipped")
            return
        if time.time() < self._next_allowed:
            return
        async with self._tick_lock:
            try:
                await asyncio.wait_for(self._tick_impl(log), timeout=TICK_TIMEOUT_S)
            except (TimeoutError, asyncio.TimeoutError):
                self._fail("panel_timeout", log, "ddos-monitoring: tick timed out after %.0fs", TICK_TIMEOUT_S)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — прошлый срез сохраняется
                self._fail("db_unavailable", log, "ddos-monitoring: tick failed", exc_info=True)

    async def _fetch(self, coro):
        return await asyncio.wait_for(coro, timeout=REQUEST_TIMEOUT_S)

    def _thresholds(self, raw: Any, baseline: dict[str, float] | None = None) -> dict[str, float]:
        th = dict(DEFAULT_THRESHOLDS)
        if isinstance(raw, dict):
            for key in th:
                v = raw.get(key)
                if isinstance(v, (int, float)) and v > 0:
                    th[key] = float(v)
        # Merge с per-node baseline (адаптивные пороги).
        return _effective_thresholds(th, baseline or {})

    def _agent_snapshot(self, uuid: str, max_age_s: float = 90.0) -> dict | None:
        """Свежий агентский срез или None."""
        from . import agent_receiver as AR

        info = AR._last_report.get(uuid)
        if not info:
            return None
        if time.time() - info["ts"] > max_age_s:
            return None
        return info.get("metrics") or {}

    def _agent_to_panel(self, m: dict) -> dict:
        """Агентские имена → панельные (для record_sample/совместимости)."""
        out = {
            "net_rx_bps": m.get("rx_bps"),
            "net_rx_pps": m.get("rx_pps"),
            "net_tx_bps": m.get("tx_bps"),
            "conntrack_count": m.get("conntrack_count"),
            "conntrack_max": m.get("conntrack_max"),
            "cpu_usage": m.get("cpu_pct"),
            "memory_usage": m.get("ram_pct"),
            "cpu_cores": m.get("cores"),
            "load1": m.get("load1"),
            "disk_usage": m.get("disk_pct"),
            "swap_pct": m.get("swap_pct"),
            "syn_recv": m.get("syn_recv"),
        }
        return {k: v for k, v in out.items() if v is not None}

    def verdict_for_metrics(self, panel_metrics: dict,
                            agent_metrics: dict | None = None) -> dict:
        """Агент свежий → classify_agent, иначе panel classify."""
        th = self._thresholds(None)
        if agent_metrics is not None:
            return classify_agent(agent_metrics)
        return classify(panel_metrics or {}, th)

    async def _tick_impl(self, log: Any) -> None:
        from web.backend.core.plugin_api import panel_api
        from . import data
        from .data import ensure_schema

        if not self._schema_ready:
            ctx = _ctx_ref()
            await ensure_schema(ctx)
            self._schema_ready = True

        ctx = _ctx_ref()
        api = panel_api()

        # Пороги из настроек плагина (админ меняет без передеплоя)
        th_raw = await self._fetch(ctx.settings.get("thresholds"))
        # Per-node baseline (если включён) — вычитываем один раз на tick,
        # не на каждую ноду (экономит N DB reads на 11+ нод).
        baseline_enabled_raw = await self._fetch(ctx.settings.get("baseline_mode"))
        baseline_enabled = bool(baseline_enabled_raw)

        # Имена нод — из панели (для /data); uuid → name (M-1).
        # get_nodes() отдаёт {"response": [...]}; терпим и list на всякий случай.
        # Fallback на прямой SQL к public.nodes — ядро Remnawave /api/nodes
        # иногда возвращает не все ноды (особенность фильтрации по raw_data),
        # и без fallback'а Hermes (9167ddba-...) остаётся в ddos_monitoring_node_state
        # с node_name=NULL.
        node_names: dict[str, str] = {}
        try:
            nodes_raw = await self._fetch(api.get_nodes(skip_cache=True))
            if isinstance(nodes_raw, dict):
                items = nodes_raw.get("response") or nodes_raw.get("items") or []
            else:
                items = nodes_raw or []
            for n in (items or []):
                if isinstance(n, dict) and n.get("uuid"):
                    node_names[str(n["uuid"])] = str(n.get("name") or "")
        except Exception:  # noqa: BLE001 — имена косметика, срезу не мешают
            log.warning("ddos-monitoring: get_nodes failed — node names unavailable")

        # Fallback: имена ВСЕХ нод из public.nodes (даже если их имя уже
        # есть в node_state). Раньше fallback срабатывал только когда имя
        # было пустым — это приводило к race: после ручного UPDATE имя
        # заполнялось, но следующий tick видел непустое имя и пропускал
        # fallback, а panel_api не возвращал ноду → record_sample снова
        # писал пусто. Теперь ищем имена для ВСЕХ uuid'ов которых нет
        # в panel_api (т.е. которых не видели в этот тик).
        try:
            _state_rows = await self._fetch(ctx.db.fetch(
                "SELECT node_uuid::text FROM ddos_monitoring_node_state"))
            _missing = [str(r["node_uuid"]) for r in _state_rows
                        if str(r["node_uuid"]) not in node_names]
            if _missing:
                _name_rows = await self._fetch(ctx.db.fetch(
                    "SELECT uuid::text, name FROM public.nodes "
                    "WHERE uuid = ANY($1::uuid[])", _missing))
                for r in _name_rows:
                    uuid = str(r["uuid"])
                    nm = str(r["name"] or "")
                    if nm:
                        node_names[uuid] = nm
                        log.info("ddos-monitoring: node %s name from SQL: %s",
                                 uuid, nm)
        except Exception as _e:  # noqa: BLE001
            log.warning("ddos-monitoring: SQL name fallback failed: %s", _e)

        # Свежий срез каждой ноды: последний snapshot за окно
        rows = await self._fetch(ctx.db.fetch(
            """SELECT DISTINCT ON (node_uuid)
                      node_uuid, net_rx_bps, net_rx_pps, net_rx_drop_ps,
                      conntrack_count, conntrack_max,
                      tcp_syncookies_ps, tcp_listen_drop_ps, created_at
               FROM node_metrics_snapshots
               WHERE created_at > NOW() - interval '5 minutes'
               ORDER BY node_uuid, created_at DESC"""))

        now = time.time()
        seen: set[str] = set()

        # Фаза 2.5: карта VPN-IP — один запрос за тик (кэш на тик, не на алерт)
        exclude_vpn = str(await self._fetch(ctx.settings.get("exclude_vpn"))) in ("1", "true", "True", "on")
        vpn_window = int(await self._fetch(ctx.settings.get("vpn_window_s")) or data.VPN_WINDOW_S)
        try:
            vpn_map = await data.get_vpn_ip_map(ctx, window_s=vpn_window)
        except Exception:  # noqa: BLE001 — кросс-сверка не должна ломать тик
            vpn_map = {}
        self._vpn_map = vpn_map
        vpn_ips = set(vpn_map)

        for row in rows:
            uuid = str(row["node_uuid"])
            seen.add(uuid)
            # Reset `th` на КАЖДОЙ ноде — иначе предыдущая нода с baseline
            # «протечёт» в текущую, если у неё нет baseline row (только что
            # добавлена, INSERT в node_baseline упал, нет метрик за 7 дней).
            # Это CRITICAL FIX: иначе ноды без baseline получат ЛИБО СЛИШКОМ
            # ВЫСОКИЕ пороги → пропустим атаки (false NEGATIVE).
            th = self._thresholds(th_raw)
            if baseline_enabled:
                node_baseline = await self._fetch_baseline(uuid)
                if node_baseline:
                    th = self._thresholds(th_raw, node_baseline)
            agent_m = self._agent_snapshot(uuid)
            if agent_m is not None:
                # Приоритет: живой агент → полный classify
                if exclude_vpn:
                    agent_m["vpn_ips"] = vpn_ips
                verdict = classify_agent(agent_m, exclude_vpn=exclude_vpn)

                # S.3 — SYN-rate (идея fastnetmon: ловить медленный SYN-флуд,
                # когда абсолютное значение ещё ниже AGENT_SYN_RECV_LIMIT, но
                # быстро растёт). Использует прошлое значение из self._nodes.
                if agent_m.get("syn_recv") is not None:
                    cur_syn = int(_num(agent_m["syn_recv"]))
                    last_syn = self._nodes.get(uuid, {}).get("last_syn_recv")
                    interval = INTERVAL_S if last_syn is not None else 0.0
                    rate_verdict = classify_syn_rate(
                        last_syn, cur_syn, interval,
                        threshold=DEFAULT_SYN_RATE_THRESHOLD,
                    )
                    # Если SYN-rate детектит атаку, перебиваем verdict
                    # (но только если текущий вердикт НЕ атака с более высоким severity)
                    if rate_verdict["state"] == "attack":
                        cur_sev = verdict.get("severity", "normal")
                        rate_sev = rate_verdict["severity"]
                        if SEV_ORDER.get(rate_sev, 0) > SEV_ORDER.get(cur_sev, 0):
                            verdict = rate_verdict
                metrics = self._agent_to_panel(agent_m)
                metrics["source"] = "agent"
            else:
                metrics = {
                    "net_rx_bps": row["net_rx_bps"],
                    "net_rx_pps": row["net_rx_pps"],
                    "net_rx_drop_ps": row["net_rx_drop_ps"],
                    "conntrack_count": row["conntrack_count"],
                    "conntrack_max": row["conntrack_max"],
                    "tcp_syncookies_ps": row["tcp_syncookies_ps"],
                    "tcp_listen_drop_ps": row["tcp_listen_drop_ps"],
                }
                verdict = classify(metrics, th)
                metrics["source"] = "panel"
            if uuid in self._nodes:
                self._nodes[uuid]["name"] = node_names.get(uuid, "")
                # Сохраняем cur_syn для следующего тика (S.3 rate detection)
                if agent_m is not None and agent_m.get("syn_recv") is not None:
                    self._nodes[uuid]["last_syn_recv"] = int(_num(agent_m["syn_recv"]))
            agent_version = None
            if agent_m is not None:
                from . import agent_receiver as AR
                report = AR._last_report.get(uuid) or {}
                agent_version = str(report.get("agent_version") or "") or None
            await data.record_sample(ctx, uuid, node_names.get(uuid, ""),
                                     metrics if verdict["state"] != "nodata" else None,
                                     None, agent_version=agent_version)
            await self._apply_verdict(ctx, log, uuid, verdict, metrics, now,
                                      agent_m=agent_m)

        # Ноды, которые раньше отвечали, а теперь молчат
        for uuid in list(self._nodes.keys()):
            if uuid not in seen:
                entry = self._nodes[uuid]
                await self._handle_offline(ctx, log, uuid, entry.get("name") or node_names.get(uuid, ""), now)
                # entry["verdict"] уже обновлён в _handle_offline (offline или сохранён).
                # Здесь ничего не пишем — иначе перезатрём только что установленный verdict.
                await data.record_sample(ctx, uuid, node_names.get(uuid, ""), None,
                                         "no telemetry" if entry["verdict"] != "offline" else None)

        # TTL-закрытие зависших attacks (wire L1) — раз в час
        await self._maybe_close_stale(ctx, log)

        # Baseline mode (v0.7.47) — раз в час пересчитываем p95 из истории.
        await self._maybe_recompute_baseline(ctx, log)

        self.as_of = now
        self.error = None
        self.truncated = False
        self.failures = 0
        self._next_allowed = 0.0
        self.ticks_ok += 1

        # Ежечасный summary + стартовый (после первого полного тика)
        await self._maybe_summary(ctx, log, node_names, time.time())
    async def _handle_offline(self, ctx, log: Any, uuid: str, name: str, now: float) -> None:
        """Нода исчезла из свежих срезов: подтверждаем offline и алертим."""
        entry = self._nodes.setdefault(uuid, {
            "verdict": "unknown", "candidate": "", "candidate_count": 0,
            "attack_id": None, "last_alert": 0.0, "peak": {}, "severity": "normal",
        })
        if entry["verdict"] == "offline":
            entry["candidate"], entry["candidate_count"] = "", 0
            return
        if entry["candidate"] == "offline":
            entry["candidate_count"] += 1
        else:
            entry["candidate"], entry["candidate_count"] = "offline", 1
        if entry["candidate_count"] < OFFLINE_CONFIRMATIONS:
            return
        previous, entry["verdict"] = entry["verdict"], "offline"
        entry["candidate"], entry["candidate_count"] = "", 0
        # Закрыть открытую атаку (если была) — иначе БД-строка зависнет
        # до attack_stale_ttl_s. Это явный offline transition.
        attack_id = entry.get("attack_id")
        if attack_id is not None:
            from . import data
            try:
                await data.close_attack(ctx, attack_id, entry.get("peak") or {})
            except Exception:  # noqa: BLE001 — tick не должен падать на DB-сбое
                log.warning("ddos-monitoring: close_attack on offline failed", exc_info=True)
            entry["attack_id"] = None
        await notify.send_state_change(ctx, uuid, name or uuid,
                                       previous=previous,
                                       current={"state": "offline"},
                                       error="нет телеметрии")
        from . import data
        await data.add_event(ctx, "offline", uuid, {})

    def classify_agent(self, m):
        return classify_agent(m)

    async def _maybe_recompute_baseline(self, ctx, log: Any) -> None:
        """Раз в час пересчитывает per-node baseline из node_metrics_snapshots.

        Идея: fastnetmon baseline_magician. Берём историю за 7 дней, агрегируем
        p95, применяем формулу (value * 3), сохраняем в node_baseline.
        Защита: lock + try/except (не должен ломать tick).
        """
        now = time.time()
        if now - self._baseline_computed_at < self._baseline_interval_s:
            return
        if self._baseline_lock.locked():
            return
        async with self._baseline_lock:
            try:
                rows = await ctx.db.fetch(
                    """SELECT node_uuid::text,
                              percentile_cont(0.95) WITHIN GROUP (ORDER BY net_rx_bps) AS p95_bps,
                              COUNT(*)::int AS n_bps,
                              percentile_cont(0.95) WITHIN GROUP (ORDER BY net_rx_pps) AS p95_pps,
                              COUNT(*)::int AS n_pps,
                              percentile_cont(0.95) WITHIN GROUP (ORDER BY tcp_syncookies_ps) AS p95_syn,
                              COUNT(tcp_syncookies_ps)::int AS n_syn,
                              percentile_cont(0.95) WITHIN GROUP (ORDER BY tcp_listen_drop_ps) AS p95_ld,
                              COUNT(tcp_listen_drop_ps)::int AS n_ld,
                              percentile_cont(0.95) WITHIN GROUP (ORDER BY net_rx_drop_ps) AS p95_rxd,
                              COUNT(net_rx_drop_ps)::int AS n_rxd
                       FROM node_metrics_snapshots
                       WHERE created_at > NOW() - ($1::int * interval '1 day')
                       GROUP BY node_uuid""",
                    self._baseline_window_days)
                written = 0
                for r in rows:
                    uuid = str(r["node_uuid"])
                    samples = [
                        ("net_rx_bps", r["p95_bps"], r["n_bps"], "rx_bps"),
                        ("net_rx_pps", r["p95_pps"], r["n_pps"], "rx_pps"),
                        ("tcp_syncookies_ps", r["p95_syn"], r["n_syn"], "syncookies_ps"),
                        ("tcp_listen_drop_ps", r["p95_ld"], r["n_ld"], "listen_drop_ps"),
                        ("net_rx_drop_ps", r["p95_rxd"], r["n_rxd"], "rx_drop_ps"),
                    ]
                    for src_key, p95_v, n_v, bl_key in samples:
                        if p95_v is None or n_v == 0:
                            continue
                        try:
                            scaled = _apply_expression(float(p95_v),
                                                       _DEFAULT_EXPRESSIONS.get(bl_key, "value * 3"))
                        except (ValueError, SyntaxError, ZeroDivisionError):
                            continue
                        baseline_v = max(scaled, _DEFAULT_MIN.get(bl_key, 0.0))
                        await ctx.db.execute(
                            """INSERT INTO ddos_monitoring_node_baseline
                                  (node_uuid, metric, baseline_value, p95_value,
                                   samples_count, window_days, computed_at)
                               VALUES ($1::uuid, $2, $3, $4, $5, $6, NOW())
                               ON CONFLICT (node_uuid, metric) DO UPDATE
                                   SET baseline_value = EXCLUDED.baseline_value,
                                       p95_value = EXCLUDED.p95_value,
                                       samples_count = EXCLUDED.samples_count,
                                       computed_at = EXCLUDED.computed_at""",
                            uuid, bl_key, baseline_v, float(p95_v), int(n_v),
                            self._baseline_window_days)
                        written += 1
                self._baseline_computed_at = time.time()
                if written:
                    log.info("ddos-monitoring: baseline recomputed, %d rows written (window=%dd)",
                             written, self._baseline_window_days)
            except Exception as _e:  # noqa: BLE001
                log.warning("ddos-monitoring: baseline recompute failed: %s", _e)

    async def _recompute_baseline_one_off(self, ctx, log: Any) -> None:
        """Принудительный пересчёт baseline (для ручного триггера из API)."""
        self._baseline_computed_at = 0.0
        await self._maybe_recompute_baseline(ctx, log)

    async def _fetch_baseline(self, uuid: str) -> dict[str, float] | None:
        """Возвращает {metric: baseline_value} для uuid из node_baseline."""
        try:
            ctx = _ctx_ref()
            if not ctx or not getattr(ctx, "db", None):
                return None
            rows = await ctx.db.fetch(
                "SELECT metric, baseline_value FROM ddos_monitoring_node_baseline "
                "WHERE node_uuid = $1::uuid",
                uuid,
            )
            if not rows:
                return None
            return {str(r["metric"]): float(r["baseline_value"]) for r in rows}
        except Exception:  # noqa: BLE001
            return None

    async def _restore_states_safe(self, log: Any) -> None:
        """Обёртка: восстановление вердиктов после старта процесса."""
        try:
            ctx = _ctx_ref()
            await self._restore_states(ctx)
        except Exception:  # noqa: BLE001 — не должно ломать тики
            log.warning("ddos-monitoring: state restore failed", exc_info=True)

    async def _restore_states(self, ctx) -> None:
        """После рестарта панели восстановить вердикты нод из БД (иначе
        первое саммари показывает «всё зелёное», а атаки открываются заново)."""
        try:
            # 1) активные атаки (attack_start без recovery за последние 15 мин)
            rows = await ctx.db.fetch(
                """SELECT DISTINCT ON (node_uuid) node_uuid, kind, payload, created_at
                   FROM ddos_monitoring_events
                   WHERE kind IN ('attack_start', 'recovery', 'offline')
                   ORDER BY node_uuid, created_at DESC""")
            # Открытые атаки в БД (ended_at IS NULL): рестарт не должен их
            # забывать — иначе саммари рисует 🟢 при живой атаке.
            open_rows = await ctx.db.fetch(
                """SELECT DISTINCT ON (node_uuid) node_uuid
                   FROM ddos_monitoring_attacks WHERE ended_at IS NULL""")
            open_attack_uuids = {str(r["node_uuid"]) for r in open_rows}
            for r in rows:
                uuid = str(r["node_uuid"])
                entry = self._nodes.setdefault(uuid, {
                    "verdict": "unknown", "candidate": "", "candidate_count": 0,
                    "attack_id": None, "last_alert": 0.0, "peak": {}, "name": "",
                })
                if r["kind"] == "attack_start":
                    age = time.time() - r["created_at"].timestamp()
                    # Свежий attack_start или открытая атака в БД → attack
                    if age < 900 or uuid in open_attack_uuids:
                        entry["verdict"] = "attack"
                        entry["severity"] = (r["payload"] or {}).get("severity", "high")
                        entry["last_alert"] = r["created_at"].timestamp()
            # Привязываем открытые атаки из БД к attack_id: без этого
            # recovery не вызовет close_attack и атака останется
            # ended_at IS NULL навсегда (вечно 🔴 в restore-логике).
            if open_attack_uuids:
                id_rows = await ctx.db.fetch(
                    """SELECT DISTINCT ON (node_uuid) node_uuid, id
                       FROM ddos_monitoring_attacks WHERE ended_at IS NULL
                       ORDER BY node_uuid, started_at DESC""")
                for r in id_rows:
                    uuid = str(r["node_uuid"])
                    entry = self._nodes.get(uuid)
                    if entry and entry.get("verdict") == "attack" and not entry.get("attack_id"):
                        entry["attack_id"] = int(r["id"])
            # 2) все ноды из node_state (имена/last_seen) — заполняем пропуски
            state_rows = await ctx.db.fetch(
                "select node_uuid, node_name, last_seen_at from ddos_monitoring_node_state")
            for r in state_rows:
                uuid = str(r["node_uuid"])
                entry = self._nodes.setdefault(uuid, {
                    "verdict": "unknown", "candidate": "", "candidate_count": 0,
                    "attack_id": None, "last_alert": 0.0, "peak": {}, "name": "",
                })
                if not entry["name"]:
                    entry["name"] = r["node_name"] or uuid
                # offline если last_seen > 120 сек назад
                if r["last_seen_at"]:
                    age = time.time() - r["last_seen_at"].timestamp()
                    if entry["verdict"] == "unknown" and age > 120:
                        entry["verdict"] = "offline"
                        entry["reasons"] = ["нет связи"]
            # 2б) переклассификация по последнему снапшоту агента — чтобы
            # саммари после рестарта было РЕАЛЬНЫМ (systemd/Лимит IP/Load),
            # а не «всё зелёное» из-за unknown.
            snap_rows = await ctx.db.fetch(
                """SELECT DISTINCT ON (node_uuid) node_uuid, cpu_pct, ram_pct, load1,
                          cores, syn_recv, established, swap_pct, disk_pct,
                          failed_units, top_ips, unique_ips, ip_limit_breaches, ts
                   FROM ddos_monitoring_agent_snapshots
                   ORDER BY node_uuid, ts DESC""")
            for sr in snap_rows:
                uuid = str(sr["node_uuid"])
                age = time.time() - sr["ts"].timestamp()
                if age > 180:
                    continue  # снапшот протух — не классифицируем
                m: dict[str, Any] = {
                    "source": "agent",
                    "cpu_pct": float(sr["cpu_pct"] or 0),
                    "ram_pct": float(sr["ram_pct"] or 0),
                    "load1": float(sr["load1"] or 0),
                    "cores": int(sr["cores"] or 1),
                    "syn_recv": int(sr["syn_recv"] or 0),
                    "established": int(sr["established"] or 0),
                    "swap_pct": float(sr["swap_pct"] or 0),
                    "disk_pct": float(sr["disk_pct"] or 0),
                    "failed_units": json.loads(sr["failed_units"]) if isinstance(sr["failed_units"], str) else (sr["failed_units"] or []),
                    "top_ips": json.loads(sr["top_ips"]) if isinstance(sr["top_ips"], str) else (sr["top_ips"] or []),
                    "unique_ips": int(sr["unique_ips"] or 0),
                    "ip_limit_breaches": json.loads(sr["ip_limit_breaches"]) if isinstance(sr["ip_limit_breaches"], str) else (sr["ip_limit_breaches"] or []),
                }
                verdict = self.classify_agent(m)
                if verdict.get("state") in ("health", "load", "attack", "stable"):
                    entry = self._nodes.setdefault(uuid, {
                        "verdict": "unknown", "candidate": "", "candidate_count": 0,
                        "attack_id": None, "last_alert": 0.0, "peak": {}, "name": "",
                    })
                    if entry["verdict"] == "unknown":
                        entry["verdict"] = verdict["state"]
                        entry["reasons"] = list(verdict.get("reasons") or [])
                        entry["metrics"] = m
            # 3) все ноды из nodes-таблицы панели — чтобы саммари не пропускало
            nodes_rows = await ctx.db.fetch("select uuid, name from nodes")
            for r in nodes_rows:
                uuid = str(r["uuid"])
                entry = self._nodes.setdefault(uuid, {
                    "verdict": "unknown", "candidate": "", "candidate_count": 0,
                    "attack_id": None, "last_alert": 0.0, "peak": {}, "name": "",
                })
                if not entry["name"]:
                    entry["name"] = r["name"] or uuid
        except Exception:  # noqa: BLE001 — восстановление не должно ломать тик
            pass

    async def _summary_rows(self, ctx) -> list[tuple]:
        # Загружаем sort_order из БД для сортировки в TG-саммари
        sort_map: dict[str, int] = {}
        try:
            for r in await ctx.db.fetch(
                    "SELECT node_uuid::text, sort_order FROM ddos_monitoring_node_state"):
                sort_map[str(r["node_uuid"])] = r["sort_order"]
        except Exception:  # noqa: BLE001
            pass
        rows = []
        for uuid, e in sorted(self._nodes.items(),
                              key=lambda kv: (sort_map.get(kv[0], 0), kv[1].get("name") or "")):
            state = e.get("verdict", "unknown")
            # Кандидат в атаку ещё на подтверждении — в саммари честно показываем
            # атаку (лучше лишний раз предупредить, чем отчитаться «стабильно»
            # за 40 секунд до алерта).
            if state != "attack" and e.get("candidate") == "attack":
                state = "attack"
            if state == "nodata":
                state = "offline"
            # В саммари идут только короткие причины («systemd», «Лимит IP»),
            # развёрнутые списки остаются в алертах.
            short_reasons = [r for r in (e.get("reasons") or [])
                             if r in ("systemd", "Лимит IP", "CPU", "RAM",
                                      "Load Average", "Диск", "Сеть", "Swap")]
            rows.append((uuid, e.get("name") or uuid, state,
                         e.get("attack_type", ""), short_reasons))
        return rows

    def _summary_cfg(self, raw: Any) -> tuple[bool, float]:
        """(включено, интервал_сек). raw — settings плагина."""
        enabled = raw.get("summary_enabled", True)
        enabled = enabled if isinstance(enabled, bool) else str(enabled).lower() != "false"
        interval = SUMMARY_INTERVAL_S
        try:
            hours = float(raw.get("summary_interval_h", 1))
            if hours > 0:
                interval = hours * 3600.0
        except (TypeError, ValueError):
            pass
        return enabled, interval

    async def _maybe_summary(self, ctx, log: Any, node_names: dict[str, str], now: float) -> None:
        try:
            raw = {
                "summary_enabled": await ctx.settings.get("summary_enabled"),
                "summary_interval_h": await ctx.settings.get("summary_interval_h"),
            }
        except Exception:  # noqa: BLE001 — нет настроек → дефолт
            raw = {}
        enabled, interval = self._summary_cfg(raw)
        if not enabled:
            self._startup_summary_sent = True
            return
        first = not self._startup_summary_sent
        due = self._last_summary and (now - self._last_summary) >= interval
        if not (first or due):
            return
        for uuid, name in node_names.items():
            if uuid in self._nodes:
                self._nodes[uuid]["name"] = name
        try:
            await notify.send_summary(ctx, await self._summary_rows(ctx))
        except Exception:  # noqa: BLE001 — summary не роняет тик
            log.warning("ddos-monitoring: summary send failed", exc_info=True)
            return
        self._last_summary = now
        self._startup_summary_sent = True

    async def _apply_verdict(self, ctx, log: Any, uuid: str, verdict: dict,
                             metrics: dict, now: float,
                             agent_m: dict | None = None) -> None:
        from . import data

        entry = self._nodes.setdefault(uuid, {
            "verdict": "unknown", "candidate": "", "candidate_count": 0,
            "attack_id": None, "last_alert": 0.0, "peak": {}, "name": "",
        })
        committed = entry["verdict"]
        observed = verdict["state"]
        if observed == "nodata":
            return

        for key in ("net_rx_bps", "net_rx_pps"):
            entry["peak"][key] = max(float(entry["peak"].get(key, 0)), _num(metrics.get(key)))

        if observed == committed:
            entry["candidate"], entry["candidate_count"] = "", 0
            if observed == "attack" and entry.get("attack_id"):
                severity = verdict["severity"]
                order = {"medium": 1, "high": 2, "critical": 3}
                escalated = order.get(severity, 0) > order.get(entry.get("severity", "medium"), 0)
                cooldown_s = ALERT_COOLDOWN_S
                try:
                    cd_m = await ctx.settings.get("alert_cooldown_m")
                    if cd_m is not None:
                        cooldown_s = max(0.0, float(cd_m)) * 60.0
                except Exception:  # noqa: BLE001 — нет настройки → дефолт
                    pass
                cooled = now - entry["last_alert"] >= cooldown_s
                await data.update_attack(ctx, entry["attack_id"], severity, entry["peak"])
                if escalated or cooled:
                    entry["last_alert"] = now
                    await data.add_event(ctx, "attack_update", uuid,
                                         {"severity": severity, "escalated": escalated,
                                          "attack_type": verdict["attack_type"]})
                    try:
                        await notify.send_state_change(
                            ctx, uuid, entry.get("name") or uuid,
                            previous="attack", current=verdict, repeated=True,
                            metrics=metrics)
                    except Exception:  # noqa: BLE001
                        log.warning("ddos-monitoring: notify failed", exc_info=True)
            return

        # подтверждение кандидата
        need = (ATTACK_CONFIRMATIONS if observed == "attack"
                else RECOVERY_CONFIRMATIONS if committed in {"attack"}
                else 1)
        if entry["candidate"] == observed:
            entry["candidate_count"] += 1
        else:
            entry["candidate"], entry["candidate_count"] = observed, 1
        if entry["candidate_count"] < need:
            return

        previous, entry["verdict"] = committed, observed
        entry["candidate"], entry["candidate_count"] = "", 0
        # Причины сохраняем для саммари (короткие) и алертов (развёрнутые)
        entry["reasons"] = list(verdict.get("reasons") or [])
        entry["metrics"] = dict(metrics or {})

        if observed == "attack":
            entry["attack_id"] = await data.open_attack(ctx, uuid, verdict)
            entry["severity"] = verdict["severity"]
            entry["last_alert"] = now
            entry["peak"] = {}
            for key in ("net_rx_bps", "net_rx_pps"):
                entry["peak"][key] = _num(metrics.get(key))
            await data.add_event(ctx, "attack_start", uuid,
                                 {"attack_type": verdict["attack_type"],
                                  "severity": verdict["severity"],
                                  "reasons": verdict["reasons"],
                                  "top_ips": [
                                      {"ip": t.get("ip"), "count": t.get("count")}
                                      for t in (agent_m or {}).get("top_ips") or []
                                  ] if agent_m else []})
        elif previous == "attack":
            duration = None
            if entry.get("attack_started_at"):
                duration = now - entry["attack_started_at"]
            if entry.get("attack_id"):
                await data.close_attack(ctx, entry["attack_id"], entry["peak"])
                await data.add_event(ctx, "attack_end", uuid,
                                     {"duration_peak": entry["peak"]})
            entry["peak_for_notify"] = dict(entry["peak"])
            entry["duration_for_notify"] = duration
            entry["attack_id"], entry["peak"] = None, {}
            entry["attack_started_at"] = None

        # Фаза 2: алерты на любые смены состояния (кроме unknown→X при старте)
        if previous not in ("unknown",):
            try:
                kw: dict[str, Any] = {"metrics": metrics,
                                      "vpn_ips": set(getattr(self, "_vpn_map", {}) or ())}
                if previous == "attack":
                    kw["duration_s"] = entry.get("duration_for_notify")
                    kw["peak"] = entry.get("peak_for_notify") or {}
                await notify.send_state_change(
                    ctx, uuid, entry.get("name") or uuid,
                    previous=previous, current=verdict, **kw)
            except Exception:  # noqa: BLE001 — алерт не роняет тик
                log.warning("ddos-monitoring: notify failed", exc_info=True)
        entry.pop("peak_for_notify", None)
        entry.pop("duration_for_notify", None)
        if observed == "attack" and not entry.get("attack_started_at"):
            entry["attack_started_at"] = now


# ── Baseline mode (v0.7.47) — адаптивные пороги на основе истории трафика.
# ────────────────────────────────────────────────────────────────
# Идея из fastnetmon (baseline_magician + influxdb_baseline):
#   - берём историю `node_metrics_snapshots` за N дней (default 7)
#   - агрегируем p95 (или другая функция)
#   - применяем выражение: value * K, value + N
#   - ограничиваем снизу min_threshold
# Детекция использует max(DEFAULT_THRESHOLDS, baseline) — нижняя граница +
# адаптация под реальный профиль ноды.

_VALID_BASELINE_KEYS = ("rx_bps", "rx_pps", "syncookies_ps", "listen_drop_ps", "rx_drop_ps")
_DEFAULT_EXPRESSIONS = {
    "rx_bps": "value * 3",
    "rx_pps": "value * 2",
    "syncookies_ps": "value + 5",
    "listen_drop_ps": "value + 3",
    "rx_drop_ps": "value + 3",
}
_DEFAULT_MIN = {
    "rx_bps": 20_000_000.0,
    "rx_pps": 5_000.0,
    "syncookies_ps": 10.0,
    "listen_drop_ps": 5.0,
    "rx_drop_ps": 5.0,
}


def _apply_expression(value: float, expression: str) -> float:
    """Применяет формулу типа 'value * 3' или 'value + 200'. Защита от инъекций."""
    s = expression.strip()
    if len(s) > 256:
        raise ValueError(f"expression too long: {len(s)} > 256")
    if "value" not in s:
        raise ValueError(f"expression must contain 'value': {expression!r}")
    safe = s.replace("value", str(float(value)))
    # Разрешаем только [0-9+\-*/(). ]
    if not re.fullmatch(r"[\d+\-*/().\s]+", safe):
        raise ValueError(f"unsafe expression: {expression!r}")
    try:
        return float(eval(safe, {"__builtins__": {}}, {}))
    except ZeroDivisionError as e:
        raise ValueError(f"division by zero: {expression!r}") from e


def _compute_baseline_from_samples(
    samples: list[tuple[str, dict]],
    *,
    expressions: dict[str, str] | None = None,
    min_threshold: dict[str, float] | None = None,
) -> dict[str, dict[str, float]]:
    """Вычисляет per-uuid baseline из raw samples.

    :param samples: [(node_uuid, metrics_dict), ...]
    :param expressions: per-metric формула (default _DEFAULT_EXPRESSIONS)
    :param min_threshold: per-metric нижняя граница (default _DEFAULT_MIN)
    :returns: {node_uuid: {metric: baseline_value}}
    """
    exprs = {**_DEFAULT_EXPRESSIONS, **(expressions or {})}
    mn = {**_DEFAULT_MIN, **(min_threshold or {})}
    grouped: dict[str, list[float]] = {}
    key_to_metric = {
        "rx_bps": "net_rx_bps", "rx_pps": "net_rx_pps",
        "syncookies_ps": "tcp_syncookies_ps",
        "listen_drop_ps": "tcp_listen_drop_ps",
        "rx_drop_ps": "net_rx_drop_ps",
    }
    for uuid, m in samples:
        for bl_key, src_key in key_to_metric.items():
            v = m.get(src_key)
            if v is None:
                continue
            grouped.setdefault(f"{uuid}|{bl_key}", []).append(float(v))
    out: dict[str, dict[str, float]] = {}
    for k, vs in grouped.items():
        uuid, bl_key = k.split("|", 1)
        if not vs:
            continue
        sv = sorted(vs)
        p95_idx = max(0, int(round(0.95 * (len(sv) - 1))))
        p95 = sv[p95_idx]
        expr = exprs.get(bl_key, "value * 3")
        mn_v = mn.get(bl_key, 0.0)
        try:
            scaled = _apply_expression(p95, expr)
        except (ValueError, SyntaxError):
            continue
        out.setdefault(uuid, {})[bl_key] = max(scaled, mn_v)
    return out


def _effective_thresholds(
    default: dict[str, float],
    baseline: dict[str, float] | None,
) -> dict[str, float]:
    """Возвращает max(default[k], baseline[k] if any else default[k])."""
    if not baseline:
        return dict(default)
    eff = {}
    for k, dv in default.items():
        bv = baseline.get(k)
        eff[k] = max(dv, bv) if bv is not None else dv
    return eff


# Замыкание на контекст плагина: _build сохраняет ctx сюда до первого тика.
_CTX: Any = None


def bind_ctx(ctx) -> None:
    global _CTX
    _CTX = ctx


def _ctx_ref():
    return _CTX


POLLER = DdosPoller()
