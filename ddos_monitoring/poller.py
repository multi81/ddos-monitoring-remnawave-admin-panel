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
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("plugin.ddos-monitoring")

from . import notify  # noqa: E402 — алерты фазы 2

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

# Пороги по умолчанию (перенос Thresholds из ddos-monitoring-monitor). Значения
# из настроек плагина (plugin_settings, ключ thresholds) перекрывают их.
DEFAULT_THRESHOLDS: dict[str, float] = {
    "rx_bps": 500_000_000.0,        # 500 Мбит/с входящий
    "rx_pps": 100_000.0,
    "syncookies_ps": 1_000.0,
    "listen_drop_ps": 500.0,
    "conntrack_ratio": 0.75,
    "rx_drop_ps": 100.0,
    # Фаза 2 (перенос Thresholds легаси-монитора)
    "cpu_percent": 95.0,
    "memory_percent": 95.0,
    "load_per_cpu": 3.0,
    "disk_percent": 90.0,
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


def classify_agent(m: dict[str, Any], *, exclude_vpn: bool = False) -> dict[str, Any]:
    """Вердикт по срезу ddos-agent (полные данные: systemd/SYN/per-IP/swap).

    exclude_vpn: превышения по легальным VPN-клиентам (m["vpn_ips"]) не
    триггерят атаку — считаются только внешние источники.
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
        self._schema_ready = False
        self._open_attacks: dict[str, int] = {}  # node_uuid → attack_id
        self._last_summary: float = 0.0
        self._startup_summary_sent = False
        self._restored = False
        self._restore_task: Any = None

    # ── публичное состояние для /data ────────────────────────────────
    def public_state(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "error": self.error,
            "truncated": self.truncated,
            "stale": self.as_of is None or (time.time() - self.as_of) > STALE_AFTER_S,
            "nodes_monitored": len(self._nodes),
        }

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
            self._restore_task = asyncio.create_task(self._restore_states_safe(log))
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

    def _thresholds(self, raw: Any) -> dict[str, float]:
        th = dict(DEFAULT_THRESHOLDS)
        if isinstance(raw, dict):
            for key in th:
                v = raw.get(key)
                if isinstance(v, (int, float)) and v > 0:
                    th[key] = float(v)
        return th

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
        th = self._thresholds(th_raw)

        # Имена нод — из панели (для /data); uuid → name (M-1).
        # get_nodes() отдаёт {"response": [...]}; терпим и list на всякий случай.
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
            agent_m = self._agent_snapshot(uuid)
            if agent_m is not None:
                # Приоритет: живой агент → полный classify
                if exclude_vpn:
                    agent_m["vpn_ips"] = vpn_ips
                verdict = classify_agent(agent_m, exclude_vpn=exclude_vpn)
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
                entry["verdict"] = entry.get("verdict", "nodata")
                await data.record_sample(ctx, uuid, node_names.get(uuid, ""), None,
                                         "no telemetry" if entry["verdict"] != "offline" else None)

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
        await notify.send_state_change(ctx, uuid, name or uuid,
                                       previous=previous,
                                       current={"state": "offline"},
                                       error="нет телеметрии")
        from . import data
        await data.add_event(ctx, "offline", uuid, {})

    def classify_agent(self, m):
        return classify_agent(m)

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

    def _summary_rows(self) -> list[tuple]:
        rows = []
        for uuid, e in sorted(self._nodes.items(), key=lambda kv: kv[1].get("name") or ""):
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
            await notify.send_summary(ctx, self._summary_rows())
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


# Замыкание на контекст плагина: _build сохраняет ctx сюда до первого тика.
_CTX: Any = None


def bind_ctx(ctx) -> None:
    global _CTX
    _CTX = ctx


def _ctx_ref():
    return _CTX


POLLER = DdosPoller()
