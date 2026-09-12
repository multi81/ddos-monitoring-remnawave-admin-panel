"""Схема и доступ к данным плагина.

Свои таблицы — с префиксом ddos_monitoring_*. DDL идемпотентный (IF NOT EXISTS),
применяется самим плагином при первом тике: у панели Plugin API v1 нет
штатного механизма миграций плагинов. Версия схемы фиксируется в
ddos_monitoring_schema_version.
"""
from __future__ import annotations

import datetime
import json
import logging
import time
from typing import Any

SCHEMA_VERSION = 4

_DDL = """
CREATE TABLE IF NOT EXISTS ddos_monitoring_node_state (
    node_uuid UUID PRIMARY KEY,
    node_name TEXT NOT NULL DEFAULT '',
    agent_version TEXT,
    last_seen_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ddos_monitoring_node_baseline (
    node_uuid UUID NOT NULL,
    metric TEXT NOT NULL,
    baseline_value DOUBLE PRECISION NOT NULL,
    p95_value DOUBLE PRECISION NOT NULL,
    samples_count INT NOT NULL DEFAULT 0,
    window_days INT NOT NULL DEFAULT 7,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (node_uuid, metric)
);
CREATE INDEX IF NOT EXISTS idx_ddos_monitoring_node_baseline_computed
    ON ddos_monitoring_node_baseline(computed_at);

CREATE TABLE IF NOT EXISTS ddos_monitoring_attacks (
    id BIGSERIAL PRIMARY KEY,
    node_uuid UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    attack_type TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    target TEXT NOT NULL DEFAULT '',
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    peak JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_ddos_monitoring_attacks_node_started
    ON ddos_monitoring_attacks(node_uuid, started_at);

CREATE TABLE IF NOT EXISTS ddos_monitoring_strikes (
    id BIGSERIAL PRIMARY KEY,
    node_uuid UUID NOT NULL,
    attack_id BIGINT REFERENCES ddos_monitoring_attacks(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,               -- strike | quarantine | recover
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ddos_monitoring_strikes_node_created
    ON ddos_monitoring_strikes(node_uuid, created_at);

CREATE TABLE IF NOT EXISTS ddos_monitoring_events (
    id BIGSERIAL PRIMARY KEY,
    node_uuid UUID,
    kind TEXT NOT NULL,               -- attack_start | attack_end | load | health | offline | alert_failed...
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ddos_monitoring_events_created
    ON ddos_monitoring_events(created_at);

ALTER TABLE ddos_monitoring_node_state
    ADD COLUMN IF NOT EXISTS agent_version TEXT;
ALTER TABLE ddos_monitoring_node_state
    ADD COLUMN IF NOT EXISTS sort_order INT NOT NULL DEFAULT 0;
"""


VPN_WINDOW_S = 900  # окно «активного» VPN-IP: активная или свежая сессия


async def get_vpn_ip_map(ctx, window_s: int = VPN_WINDOW_S) -> dict:
    """Активные VPN-IP панели → {ip: is_vpn(True)}.

    Источник — user_connections (ConnectionReport нод-агентов): активные
    сессии (disconnected_at IS NULL) либо закрывшиеся недавно (окно).
    Значение — только булево: email пользователей наружу map не отдаётся
    (приватность; email нужен был только для факта «легальный клиент»).
    Ошибки БД глотаются → пустой map (фильтр просто не сработает).
    """
    try:
        rows = await ctx.db.fetch(
            """
            SELECT uc.ip_address
            FROM user_connections uc
            WHERE uc.ip_address IS NOT NULL AND uc.ip_address <> ''
              AND (uc.disconnected_at IS NULL
                   OR uc.disconnected_at > now() - make_interval(secs => $1))
            """,
            int(window_s),
        )
    except Exception:
        return {}
    out: dict = {}
    for r in rows or []:
        ip = (r.get("ip_address") if hasattr(r, "get") else r["ip_address"]) or ""
        if ip:
            out[ip] = True
    return out


async def top_sources(ctx, limit: int = 50,
                      window_s: int = VPN_WINDOW_S) -> list[dict]:
    """Топ источников атак (из payload.attack_start.top_ips) + vpn?/email.

    Email возвращается ТОЛЬКО для UI под ddos:view_ips — в TG не идёт.
    """
    try:
        rows = await ctx.db.fetch(
            """
            SELECT e->>'ip' AS ip_address, sum((e->>'count')::bigint) AS cnt,
                   min(ev.created_at) AS first_seen
            FROM ddos_monitoring_events ev,
                 jsonb_array_elements(ev.payload->'top_ips') e
            WHERE ev.kind = 'attack_start'
              AND ev.created_at > now() - make_interval(secs => $1)
            GROUP BY e->>'ip'
            ORDER BY cnt DESC
            LIMIT $2
            """,
            int(window_s), int(limit),
        )
    except Exception:
        return []
    vpn_map = await get_vpn_ip_map(ctx, window_s=window_s)
    out: list[dict] = []
    for r in rows or []:
        get = r.get if hasattr(r, "get") else (lambda k: r[k])
        ip = get("ip_address")
        if not ip:
            continue
        is_vpn = bool(vpn_map.get(ip))
        out.append({
            "ip": ip,
            "count": int(get("cnt") or 0),
            "vpn": is_vpn,
            "is_vpn": is_vpn,
            "email": None,
            "first_seen": str(get("first_seen") or ""),
        })
    return out


async def ensure_schema(ctx) -> None:
    """Идемпотентное применение DDL + журнал версии. Вызывается из тика.

    Также инициализирует дефолтные plugin_settings при первой установке —
    админу не нужно вручную делать INSERT в БД.
    """
    applied = await ctx.db.fetchval(
        "SELECT value FROM plugin_settings WHERE plugin_id = $1 AND key = $2",
        ctx.plugin_id, "schema_version",
    )
    if applied is None or int(applied) < SCHEMA_VERSION:
        await ctx.db.execute(_DDL)
        await ctx.db.execute(
            """INSERT INTO plugin_settings (plugin_id, key, value, updated_at)
               VALUES ($1, 'schema_version', $2::jsonb, NOW())
               ON CONFLICT (plugin_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()""",
            ctx.plugin_id, str(SCHEMA_VERSION),
        )

    # Дефолтные настройки плагина (idempotent — ON CONFLICT ничего не делает,
    # если значение уже есть; админ может поменять через UI/SQL позже).
    # baseline_mode выключен по умолчанию (opt-in), чтобы не ломать поведение
    # при апгрейде с v0.7.46.
    await _ensure_plugin_setting(ctx, "baseline_mode", "false")
    await _ensure_plugin_setting(ctx, "baseline_window_days", "7")
    await _ensure_plugin_setting(ctx, "baseline_p95", "0.95")


async def _ensure_plugin_setting(ctx, key: str, default_value: str) -> None:
    """Upsert настройки плагина с дефолтом. Не перезаписывает существующие.

    Используется при ensure_schema: первый запуск после установки wheel
    создаёт записи, последующие — no-op.

    value хранится как jsonb (true/false/7/0.95); value_type НЕ записывается —
    panel-provided таблица plugin_settings не имеет такой колонки.
    """
    await ctx.db.execute(
        """INSERT INTO plugin_settings
               (plugin_id, key, value, updated_at)
           VALUES ($1, $2, $3::jsonb, NOW())
           ON CONFLICT (plugin_id, key) DO NOTHING""",
        ctx.plugin_id, key, default_value,
    )


async def record_sample(ctx, node_uuid: str, node_name: str, snapshot: dict | None,
                        error: str | None, agent_version: str | None = None) -> None:
    await ctx.db.execute(
        """INSERT INTO ddos_monitoring_node_state
                    (node_uuid, node_name, agent_version, last_seen_at, last_error, updated_at)
           VALUES ($1, $2, $3, $4, $5, NOW())
           ON CONFLICT (node_uuid) DO UPDATE SET
               node_name = EXCLUDED.node_name,
               agent_version = COALESCE(EXCLUDED.agent_version,
                                        ddos_monitoring_node_state.agent_version),
               last_seen_at = EXCLUDED.last_seen_at,
               last_error = EXCLUDED.last_error,
               updated_at = NOW()""",
        node_uuid, node_name, agent_version,
        datetime.datetime.now(datetime.timezone.utc) if snapshot else None,
        error,
    )


async def open_attack(ctx, node_uuid: str, assessment: dict) -> int:
    # Закрываем висящие открытые атаки той же ноды (после рестартов панели
    # могли накапливаться дубли с ended_at IS NULL).
    await ctx.db.execute(
        "UPDATE ddos_monitoring_attacks SET ended_at = NOW() "
        "WHERE node_uuid = $1 AND ended_at IS NULL",
        node_uuid,
    )
    return int((await ctx.db.fetchrow(
        """INSERT INTO ddos_monitoring_attacks (node_uuid, attack_type, severity, target, reasons)
           VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id""",
        node_uuid, assessment["attack_type"], assessment["severity"],
        assessment["target"], _json_list(assessment.get("reasons")),
    ))["id"])


async def close_attack(ctx, attack_id: int, peak: dict) -> None:
    await ctx.db.execute(
        "UPDATE ddos_monitoring_attacks SET ended_at = NOW(), peak = $2::jsonb WHERE id = $1 AND ended_at IS NULL",
        attack_id, _json_obj(peak),
    )


async def close_stale_attacks(ctx, *, ttl_s: int = 7200) -> int:
    """TTL-закрытие зависших записей атак.

    Идея fastnetmon (ban_time=1900): если нода offline и poller не закрыл
    открытую атаку — закрыть её принудительно через ttl_s секунд, чтобы
    восстановление работало корректно (ended_at IS NULL != атака навсегда).

    Возвращает количество фактически закрытых записей.

    Wired: вызывается из poller._maybe_close_stale() в конце каждого тика.
    TTL берётся из settings["attack_stale_ttl_s"]. Дефолт в settings = 0
    (выключено, безопасный старт). Rate-limit 1/час.
    """
    if ttl_s <= 0:
        # Защита от отрицательного/нулевого ttl: NOW() + 100s (отрицательное
        # смещение) закрыло бы ВСЕ открытые записи. См. security review #S1.
        raise ValueError(f"ttl_s must be > 0 (got {ttl_s})")
    # Возвращаем именно количество закрытых записей (агрегация RETURNING).
    # ВАЖНО: в SQL ниже не должно быть `LIMIT` — иначе счётчик будет wrong.
    # ВАЖНО: TTL передаётся как int. asyncpg НЕ делает неявный int→text каст,
    # поэтому использовать `$1 || ' seconds'` нельзя — будет DataError.
    # Используем make_interval(secs => $1::int) — безопасный type-cast.
    # См. review S2-followup: cам бы упал на первом тике.
    row = await ctx.db.fetchrow(
        "WITH closed AS ("
        "  UPDATE ddos_monitoring_attacks "
        "  SET ended_at = NOW(), peak = COALESCE(peak, '{}'::jsonb) "
        "  WHERE ended_at IS NULL "
        "    AND started_at < NOW() - make_interval(secs => $1::int) "
        "  RETURNING id"
        ") SELECT count(*)::int AS cnt FROM closed",
        ttl_s,
    )
    return int(row["cnt"]) if row else 0


async def update_attack(ctx, attack_id: int, severity: str, peak: dict) -> None:
    await ctx.db.execute(
        "UPDATE ddos_monitoring_attacks SET severity = $2, peak = $3::jsonb WHERE id = $1",
        attack_id, severity, _json_obj(peak),
    )


async def add_event(ctx, kind: str, node_uuid: str | None, payload: dict) -> None:
    await ctx.db.execute(
        "INSERT INTO ddos_monitoring_events (node_uuid, kind, payload) VALUES ($1, $2, $3::jsonb)",
        node_uuid, kind, _json_obj(payload),
    )


def _json_obj(value: dict | None) -> str:
    return json.dumps(value or {}, ensure_ascii=False)


def _json_list(value: list | tuple | None) -> str:
    return json.dumps(list(value or []), ensure_ascii=False)


# ── чтение для /data ─────────────────────────────────────────────

async def total_nodes_in_panel(ctx) -> int:
    """Полное число нод, которые знает панель (Remnawave `public.nodes`).

    Не путать с `fleet_overview()` — здесь ноды со срезами от агентов
    (онлайн); здесь — все ноды в панели (включая те, что без агента).

    Используется UI KPI «Под наблюдением: N / M» (задача handoff.md #5).
    """
    db = getattr(ctx, "db", ctx)
    row = await db.fetchval(
        "SELECT COUNT(*)::int FROM public.nodes"
    )
    return int(row or 0)


# Задачи handoff.md #1 и #2 — добавляем в контекст джойн с agent_snapshots:
# (используется в fleet_overview ниже через LATERAL).
def _row_load_pct(cpu_pct: float, syn_recv: int, established: int) -> float:
    """Считаем "load" ноды по Aria's UI spec (handoff.md #2).

    load = max(cpu_pct, min(100, syn_recv/100), min(100, established/10000))

    Возвращает значение 0..100 (для sparkline).
    """
    cpu = float(cpu_pct or 0)
    syn = min(100.0, max(0.0, syn_recv / 100.0))
    est = min(100.0, max(0.0, (established or 0) / 10000.0))
    return round(max(cpu, syn, est), 1)


async def _bulk_snapshots(ctx, limit_per_node: int = 9) -> dict[str, list[dict]]:
    """Один bulk-запрос: последние `limit_per_node` снапшотов для КАЖДОЙ ноды.

    Возвращает {node_uuid_str: [snap_oldest, ..., snap_newest]} — ASC.
    Используется и для metrics (snap[-1] + snap[-2]), и для history (snap[:-1]).

    Один запрос вместо N+N запросов (N+1 optimization, reviewer suggestion #1).
    """
    rows = await ctx.db.fetch(
        """SELECT * FROM (
               SELECT node_uuid, ts,
                      cpu_pct, ram_pct, swap_pct, disk_pct,
                      syn_recv, established, rx_bps, tx_bps,
                      ROW_NUMBER() OVER (PARTITION BY node_uuid ORDER BY ts DESC) AS rn
               FROM ddos_monitoring_agent_snapshots
           ) sub
           WHERE rn <= $1::int
           ORDER BY node_uuid, ts ASC""",
        limit_per_node,
    )
    result: dict[str, list[dict]] = {}
    for r in rows:
        uuid_str = str(r["node_uuid"])
        result.setdefault(uuid_str, []).append(dict(r))
    return result


async def fleet_overview(ctx) -> list[dict[str, Any]]:
    """Список нод с присоединёнными снимками и историей для UI.

    Поля (UI ожидает — задачи handoff.md #1, #2, #5):
      - node_uuid, node_name, agent_version, last_seen_at, last_error
      - attack_id, attack_started, attack_type, severity, target
      - metrics: {cpu_pct, ram_pct, swap_pct, disk_pct, syn_recv, established,
                  syn_recv_delta_per_s, rx_mbps, tx_mbps}   — ТОЛЬКО если есть снапшот
      - history: [8 load_pct значений 0..100]                — ТОЛЬКО если есть >=1 снапшот
    """
    nodes = await ctx.db.fetch(
        """SELECT s.node_uuid, s.node_name,
                  COALESCE(NULLIF(st.agent_version, ''), s.agent_version) AS agent_version,
                  COALESCE(to_timestamp(st.last_seen), s.last_seen_at) AS last_seen_at,
                  s.last_error,
                  a.id AS attack_id, a.started_at AS attack_started, a.attack_type,
                  a.severity, a.target
           FROM ddos_monitoring_node_state s
           LEFT JOIN ddos_monitoring_agent_status st
             ON st.node_uuid = s.node_uuid
           LEFT JOIN LATERAL (
               SELECT id, started_at, attack_type, severity, target
               FROM ddos_monitoring_attacks
               WHERE node_uuid = s.node_uuid AND ended_at IS NULL
               ORDER BY started_at DESC LIMIT 1
           ) a ON TRUE
           ORDER BY s.sort_order, s.node_name, s.node_uuid""")
    if not nodes:
        return []
    # Один bulk-запрос вместо N+N (reviewer suggestion #1: N+1 optimization)
    # limit_per_node=9: 1 текущий + 1 для delta + 8 для history
    all_snaps = await _bulk_snapshots(ctx, limit_per_node=9)
    out = []
    for r in nodes:
        item = dict(r)
        uuid_str = str(item["node_uuid"])
        snaps = all_snaps.get(uuid_str, [])
        if snaps:
            snap = snaps[-1]  # newest (ASC order)
            prev = snaps[-2] if len(snaps) >= 2 else None
            metrics = {
                "cpu_pct": round(float(snap["cpu_pct"] or 0), 1),
                "ram_pct": round(float(snap["ram_pct"] or 0), 1),
                "swap_pct": round(float(snap["swap_pct"] or 0), 1),
                "disk_pct": round(float(snap["disk_pct"] or 0), 1),
                "syn_recv": int(snap["syn_recv"] or 0),
                "established": int(snap["established"] or 0),
                "rx_mbps": round(int(snap["rx_bps"] or 0) / 1_000_000, 1),
                "tx_mbps": round(int(snap["tx_bps"] or 0) / 1_000_000, 1),
            }
            # syn_recv_delta_per_s — prev уже есть в bulk-результате
            if prev is not None and int(snap["ts"]) > int(prev["ts"]):
                dt_s = int(snap["ts"]) - int(prev["ts"])
                if dt_s > 0:
                    delta = int(snap["syn_recv"] or 0) - int(prev["syn_recv"] or 0)
                    metrics["syn_recv_delta_per_s"] = round(delta / dt_s, 1)
                else:
                    metrics["syn_recv_delta_per_s"] = 0.0
            else:
                metrics["syn_recv_delta_per_s"] = 0.0
            item["metrics"] = metrics
            # history = все кроме самого нового (последнего) → load для sparkline
            history_snaps = snaps[:-1] if len(snaps) >= 2 else []
            item["history"] = [
                _row_load_pct(
                    float(s["cpu_pct"] or 0),
                    int(s["syn_recv"] or 0),
                    int(s["established"] or 0),
                )
                for s in history_snaps
            ]
        else:
            item["metrics"] = None
            item["history"] = []
        out.append(item)
    return out


async def set_node_order(ctx, order: list[dict]) -> None:
    """Обновить sort_order для списка нод.

    order: [{"node_uuid": "...", "sort_order": 0}, ...]
    """
    for item in order:
        await ctx.db.execute(
            """UPDATE ddos_monitoring_node_state
               SET sort_order = $1, updated_at = NOW()
               WHERE node_uuid = $2::uuid""",
            int(item["sort_order"]),
            str(item["node_uuid"]),
        )


# ── Задача #4: drill-down /history ────────────────────────────────

import re as _re
import time as _time
from datetime import datetime as _dt, timezone as _tz

_RANGE_MAP: dict[str, int] = {
    "1h": 3600,
    "6h": 21600,
    "24h": 86400,
    "7d": 604800,
}

_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    _re.IGNORECASE,
)


def _parse_range_seconds(range_str: str) -> int:
    """Парсинг range-строки (1h, 6h, 24h, 7d) → секунды.

    Raises ValueError при невалидном значении.
    """
    val = _RANGE_MAP.get(range_str)
    if val is None:
        raise ValueError(
            f"Invalid range: {range_str!r}. Allowed: {', '.join(sorted(_RANGE_MAP))}"
        )
    return val


def _ts_to_iso(ts_raw: int | float | str) -> str:
    """Конвертация ts (bigint ms или timestamptz) → ISO 8601 строка."""
    if isinstance(ts_raw, (int, float)):
        # ts_raw > 1e12 → milliseconds, иначе seconds
        ts_sec = ts_raw / 1000 if ts_raw > 1e12 else ts_raw
        return _dt.fromtimestamp(ts_sec, tz=_tz.utc).isoformat()
    return str(ts_raw)


def _compute_step_s(ts_list: list[str]) -> int:
    """Вычислить реальный step_s из интервалов между срезами.

    Возвращает медианный интервал в секундах, или 0 если < 2 точек.
    """
    if len(ts_list) < 2:
        return 0
    try:
        deltas = []
        for i in range(1, min(len(ts_list), 10)):  # до 9 интервалов
            t1 = _dt.fromisoformat(ts_list[i - 1])
            t2 = _dt.fromisoformat(ts_list[i])
            deltas.append(int((t2 - t1).total_seconds()))
        deltas.sort()
        return deltas[len(deltas) // 2]  # медиана
    except (ValueError, IndexError):
        return 0


async def history_series(
    ctx,
    node_uuid: str,
    range_str: str,
) -> dict[str, Any]:
    """Drill-down: срезы метрик ноды за указанный range.

    Возвращает:
        {
            "node_uuid": str,
            "range": "1h",
            "step_s": 60,
            "series": {"cpu_pct": [...], "ram_pct": [...], ...},
            "ts": ["ISO8601", ...],
        }

    Задача handoff.md #4.
    """
    node_uuid_str = str(node_uuid) if not isinstance(node_uuid, str) else node_uuid
    if not _UUID_RE.match(node_uuid_str):
        raise ValueError(f"Invalid node_uuid format: {node_uuid_str!r}")

    range_seconds = _parse_range_seconds(range_str)
    now_ms = int(_time.time() * 1000)
    since_ms = now_ms - range_seconds * 1000

    rows = await ctx.db.fetch(
        """SELECT ts, cpu_pct, ram_pct, syn_recv, established, rx_bps
           FROM ddos_monitoring_agent_snapshots
           WHERE node_uuid = $1::uuid AND ts >= $2::bigint
           ORDER BY ts ASC""",
        node_uuid_str, since_ms,
    )

    ts_list: list[str] = []
    cpu_pct: list[float] = []
    ram_pct: list[float] = []
    syn_recv: list[int] = []
    established: list[int] = []
    rx_mbps: list[float] = []

    for r in rows:
        ts_list.append(_ts_to_iso(r["ts"]))
        cpu_pct.append(round(float(r["cpu_pct"] or 0), 1))
        ram_pct.append(round(float(r["ram_pct"] or 0), 1))
        syn_recv.append(int(r["syn_recv"] or 0))
        established.append(int(r["established"] or 0))
        rx_mbps.append(round(int(r["rx_bps"] or 0) / 1_000_000, 1))

    return {
        "node_uuid": node_uuid_str,
        "range": range_str,
        "step_s": _compute_step_s(ts_list),
        "series": {
            "cpu_pct": cpu_pct,
            "ram_pct": ram_pct,
            "syn_recv": syn_recv,
            "established": established,
            "rx_mbps": rx_mbps,
        },
        "ts": ts_list,
    }


# ── Расшифровка для человека: известные systemd-юниты ────────────
UNIT_HINTS: dict[str, tuple[str, str]] = {
    "antiscan-move-rules.service": (
        "Анти-скан защита: переносит правила блокировки сканеров в firewall",
        "Юнит упал — правила сканеров могли не примениться. На ноде: "
        "`systemctl status antiscan-move-rules` → посмотреть причину, "
        "`systemctl restart antiscan-move-rules`. Если падает постоянно — "
        "проверить логи `journalctl -u antiscan-move-rules -n 50`."),
    "zramswap.service": (
        "Сжатый swap в RAM (zram) — ускоряет работу при нехватке памяти",
        "Юнит упал — zram-swap не создан, при пиках памяти возможны тормоза. "
        "На ноде: `systemctl restart zramswap`, проверить "
        "`journalctl -u zramswap -n 30`. Частая причина — модуль zram "
        "не загружен ядром (`modprobe zram`)."),
    "xray.service": (
        "Ядро Xray (прокси/транспорт VPN-трафика)",
        "КРИТИЧНО: без xray нода не обслуживает клиентов. "
        "`systemctl status xray`, `journalctl -u xray -n 50`. "
        "Частые причины: битый конфиг (xray -test -c …), занят порт, "
        "закончились ресурсы."),
    "fail2ban.service": (
        "Автобан перебора паролей/сканеров по логам",
        "Защита от брутфорса не работает. `systemctl restart fail2ban`; "
        "если падает — `journalctl -u fail2ban -n 30`, обычно проблема "
        "в конфиге jail или отсутствии log-файла."),
    "nginx.service": (
        "Веб-сервер/реверс-прокси на ноде",
        "Сайты/прокси на ноде недоступны. `nginx -t` (тест конфига), "
        "`systemctl restart nginx`, `journalctl -u nginx -n 30`."),
    "docker.service": (
        "Docker — контейнеры сервисов на ноде",
        "КРИТИЧНО: все контейнеры на ноде остановлены. "
        "`systemctl restart docker`, затем `docker ps` — проверить контейнеры."),
}


def unit_hint(name: str) -> dict[str, str]:
    """Человеческая расшифровка systemd-юнита; для неизвестных — общий совет."""
    base = name.removesuffix(".service")
    for key, (what, todo) in UNIT_HINTS.items():
        if name == key or base.startswith(key.removesuffix(".service")):
            return {"what": what, "todo": todo}
    return {
        "what": f"Системный сервис «{base}»",
        "todo": ("Юнит в статусе failed. На ноде: `systemctl status " + base +
                 "` и `journalctl -u " + base + " -n 30` — посмотреть причину; "
                 "`systemctl restart " + base + "` после исправления. "
                 "Если сервис не нужен — `systemctl disable --now " + base + "`."),
    }


# Расшифровка видов причин
REASON_HINTS = {
    "systemd": "Сбой системных сервисов",
    "ip_limit": "Один или несколько IP держат слишком много соединений",
    "syn": "Переполнена очередь полуоткрытых SYN-соединений (признак SYN-flood)",
    "load": "Нода перегружена",
    "disk": "Заканчивается место на диске",
    "swap": "Заканчивается swap",
    "offline": "Агент не присылает телеметрию",
}

VERDICT_HINTS = {
    "attack": ("🔴 Атака", "Обнаружен аномальный трафик (SYN-flood / объём). "
               "Проверить топ источников, при необходимости включить защиту на границе."),
    "load": ("🟠 Высокая нагрузка", "CPU/RAM/Load за порогом. Проверить процессы "
             "`top`, перезапустить тяжёлые сервисы, масштабировать ноду."),
    "health": ("🟡 Требует внимания", "Не атака, но есть сбои (упавшие сервисы, "
               "жадные IP). Разберитесь по пунктам ниже — каждый пункт содержит, "
               "что делать."),
    "offline": ("⚫️ Нет связи", "Агент на ноде молчит >1 мин: нода выключена, "
                "нет сети или агент остановлен. Проверить `systemctl status ddos-agent`."),
    "stable": ("🟢 Стабильно", "Все метрики в норме."),
}


async def node_details(ctx) -> list[dict[str, Any]]:
    """Расшифровка вердикта по каждой ноде: systemd-юниты, топ нарушителей
    лимита соединений, SYN/Load/RAM/Swap/Диск — из последнего снапшота."""
    from .poller import POLLER, DEFAULT_THRESHOLDS

    snaps = await ctx.db.fetch(
        """SELECT DISTINCT ON (node_uuid) node_uuid, ts, syn_recv, established,
                  cpu_pct, ram_pct, load1, cores, swap_pct, disk_pct,
                  failed_units, ip_limit_breaches
           FROM ddos_monitoring_agent_snapshots
           ORDER BY node_uuid, ts DESC""")
    verdicts = {str(u): v.get("verdict") for u, v in POLLER._nodes.items()}

    out = []
    for s in snaps:
        fu = s["failed_units"]
        if isinstance(fu, str):
            fu = json.loads(fu)
        br = s["ip_limit_breaches"]
        if isinstance(br, str):
            br = json.loads(br)
        top = sorted(br or [], key=lambda b: -int(b.get("count", 0)))[:10]
        reasons = []
        if fu:
            reasons.append({"kind": "systemd",
                            "text": "упавшие systemd-юниты",
                            "hint": REASON_HINTS["systemd"],
                            "items": [dict(unit_hint(u), unit=u) for u in fu if u]})
        if top:
            reasons.append({
                "kind": "ip_limit",
                "text": "Лимит IP: превышение соединений per-IP (НЕ атака)",
                "hint": REASON_HINTS["ip_limit"] + ". По калибровке это 🟡, "
                        "а не атака; при желании забанить — на ноде "
                        "`iptables -A INPUT -s <IP> -j DROP`.",
                "items": [f"{b.get('ip')} — {b.get('count')} соед." for b in top],
                "total_ips": len(br or []),
            })
        cpus = max(int(s["cores"] or 1), 1)
        metrics = {
            "syn_recv": int(s["syn_recv"] or 0),
            "established": int(s["established"] or 0),
            "cpu_pct": float(s["cpu_pct"] or 0),
            "ram_pct": float(s["ram_pct"] or 0),
            "swap_pct": float(s["swap_pct"] or 0),
            "disk_pct": round(float(s["disk_pct"] or 0), 1),
        }
        if metrics["syn_recv"] >= 1000:
            reasons.insert(0, {"kind": "syn", "text": "SYN-очередь переполнена",
                               "hint": REASON_HINTS["syn"],
                               "items": [f"SYN_RECV = {metrics['syn_recv']}. "
                                         "Проверить: `ss -s`; смягчить — включить "
                                         "syncookies (`sysctl net.ipv4.tcp_syncookies=1`)"]})
        for key, label, th in (("cpu_pct", "CPU", "cpu_percent"),
                               ("ram_pct", "RAM", "memory_percent")):
            if DEFAULT_THRESHOLDS[th] and metrics[key] >= DEFAULT_THRESHOLDS[th]:
                reasons.append({"kind": "load", "text": f"Высокая нагрузка · {label}",
                                "hint": REASON_HINTS["load"],
                                "items": [f"{label} = {metrics[key]:.0f}% (порог "
                                          f"{DEFAULT_THRESHOLDS[th]:.0f}%). На ноде: "
                                          "`top` → найти прожорливый процесс."]})
        if metrics["disk_pct"] >= 90:
            reasons.append({"kind": "disk", "text": "Диск почти заполнен",
                            "hint": REASON_HINTS["disk"],
                            "items": [f"Диск = {metrics['disk_pct']}%. На ноде: "
                                      "`df -h`, чистить логи (`journalctl --vacuum-size=100M`)"]})
        if metrics["swap_pct"] >= 90:
            reasons.append({"kind": "swap", "text": "Swap исчерпан",
                            "hint": REASON_HINTS["swap"],
                            "items": [f"Swap = {metrics['swap_pct']:.0f}%. Ноде не хватает "
                                      "памяти: проверить `free -h`, добавить RAM или zram"]})

        out.append({
            "node_uuid": str(s["node_uuid"]),
            "verdict": verdicts.get(str(s["node_uuid"]), "unknown"),
            "verdict_hint": VERDICT_HINTS.get(
                verdicts.get(str(s["node_uuid"]), ""), ("…", ""))[1],
            "snapshot_age_s": int(time.time() - s["ts"]),
            "reasons": reasons,
            "metrics": metrics,
        })
    # Ноды без снапшотов вообще → нет связи
    known = {r["node_uuid"] for r in out}
    states = await ctx.db.fetch("SELECT node_uuid FROM ddos_monitoring_node_state")
    for r in states:
        u = str(r["node_uuid"])
        if u not in known:
            out.append({"node_uuid": u, "verdict": "offline",
                        "snapshot_age_s": None, "reasons":
                        [{"kind": "offline", "text": "Нет связи",
                          "hint": REASON_HINTS["offline"],
                          "items": ["Агент не присылает телеметрию. На ноде: "
                                    "`systemctl status ddos-agent`; если остановлен — "
                                    "`systemctl restart ddos-agent`"]}],
                        "metrics": {}})
    return out


async def recent_attacks(ctx, limit: int = 50) -> list[dict[str, Any]]:
    rows = await ctx.db.fetch(
        """SELECT a.id, a.node_uuid, s.node_name, a.started_at, a.ended_at,
                  a.attack_type, a.severity, a.target, a.reasons, a.peak
           FROM ddos_monitoring_attacks a
           LEFT JOIN ddos_monitoring_node_state s ON s.node_uuid = a.node_uuid
           ORDER BY a.started_at DESC LIMIT $1""", limit)
    return [dict(r) for r in rows]


async def poller_status(ctx) -> dict[str, Any]:
    from .poller import POLLER
    return POLLER.public_state()


def monotonic_ts() -> float:
    return time.monotonic()


_log = logging.getLogger("ddos_monitoring.data")


async def active_ips_by_node(ctx) -> list[dict[str, Any]]:
    """Уникальные активные IP, сгруппированные по нодам.

    Источник — user_connections (disconnected_at IS NULL).
    Возвращает [{node_name, ips: [ip, ...]}].
    """
    try:
        rows = await ctx.db.fetch(
            """
            SELECT COALESCE(n.name, 'unknown') AS node_name,
                   host(uc.ip_address) AS ip
            FROM user_connections uc
            LEFT JOIN nodes n ON n.uuid = uc.node_uuid
            WHERE uc.ip_address IS NOT NULL
              AND uc.disconnected_at IS NULL
            ORDER BY node_name, ip
            """,
        )
    except Exception as exc:
        _log.debug("active_ips_by_node query failed: %s", exc)
        return []
    by_node: dict[str, list[str]] = {}
    seen: dict[str, set] = {}
    for r in rows or []:
        node = (r.get("node_name") if hasattr(r, "get") else r["node_name"]) or "unknown"
        ip = (r.get("ip") if hasattr(r, "get") else r["ip"]) or ""
        if ip:
            if node not in seen:
                seen[node] = set()
                by_node[node] = []
            if ip not in seen[node]:
                seen[node].add(ip)
                by_node[node].append(ip)
    return [{"node_name": n, "ips": ips} for n, ips in sorted(by_node.items())]
