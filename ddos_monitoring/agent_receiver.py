"""Приёмник срезов ddos-agent: HMAC-валидация + запись в БД панели.

Панель не трогаем — endpoint регистрируется роутером плагина.
"""

import hashlib
import hmac
import json
import time
from asyncio import Lock

# Окно свежести ts (сек) — защита от replay
STALE_WINDOW_S = 120
# Нода считается online, если рапортовала недавно
ONLINE_WINDOW_S = 90

# Реестр последних валидных репортов: uuid -> {ts, agent_version, metrics}
# Лимит защищает от распухания при спуфинге node_uuid (компрометация секрета).
_last_report: dict = {}
_LAST_REPORT_MAX = 4096
# Replay-защита: последние виденные ts per node (окно STALE_WINDOW_S).
# Лимит uuid защищает от распухания карты при спуфинге node_uuid.
_seen_ts: dict = {}
_SEEN_MAX_UUIDS = 4096

# Per-uuid lock для защиты от TOCTOU между check и add при конкурентных POST
# (M3). Имеет смысл только при concurrent requests с одинаковым ts+uuid.
_REPLAY_LOCKS: dict[str, Lock] = {}
_REPLAY_LOCKS_MAX = 4096


def _evict_oldest(d: dict) -> None:
    """FIFO eviction — вытеснить самый старый ключ (первый в insertion order)."""
    if d:
        d.pop(next(iter(d)), None)


def _lock_for(uuid: str) -> Lock:
    """Получить/создать per-uuid asyncio.Lock с FIFO cap."""
    lock = _REPLAY_LOCKS.get(uuid)
    if lock is None:
        if len(_REPLAY_LOCKS) >= _REPLAY_LOCKS_MAX:
            _evict_oldest(_REPLAY_LOCKS)
        lock = Lock()
        _REPLAY_LOCKS[uuid] = lock
    return lock


async def _check_replay(uuid: str, ts: int) -> bool:
    """True = дубликат. Async + per-uuid Lock → TOCTOU-safe (M3).

    Cutoff: храним только ts ∈ (now - STALE_WINDOW_S, now + STALE_WINDOW_S).
    Future ts (> now + STALE_WINDOW_S) — НЕ сохраняем, иначе set растёт бесконечно
    (OOM-атака при спуфинге секрета).
    """
    now = time.time()
    lock = _lock_for(uuid)
    async with lock:
        seen = _seen_ts.get(uuid)
        if seen is None:
            if len(_seen_ts) >= _SEEN_MAX_UUIDS:
                _evict_oldest(_seen_ts)
            _seen_ts[uuid] = set()
            seen = _seen_ts[uuid]
        lower = now - STALE_WINDOW_S
        upper = now + STALE_WINDOW_S
        _seen_ts[uuid] = {t for t in seen if lower < t < upper}
        if ts in _seen_ts[uuid]:
            return True
        # Future ts вне окна — не сохраняем (OOM protection)
        if ts <= lower or ts >= upper:
            return False
        _seen_ts[uuid].add(ts)
        return False


def _save_last_report(uuid: str, payload: dict, ts: int) -> None:
    """Сохранить последний репорт. FIFO cap при переполнении (M2)."""
    if len(_last_report) >= _LAST_REPORT_MAX:
        _evict_oldest(_last_report)
    _last_report[uuid] = {
        "ts": ts,
        "agent_version": str(payload.get("agent_version") or ""),
        "metrics": payload["metrics"],
    }


def sign_payload(secret: str, node_uuid: str, ts: int, metrics_json: str) -> str:
    msg = f"{node_uuid}|{ts}|{metrics_json}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


class AgentReceiver:
    """Обработка одного отчёта агента."""

    def __init__(self, ctx):
        self._ctx = ctx
        self._tables_ready = False  # instance-level (race-free)

    async def handle(self, payload: dict) -> dict:
        if not self._tables_ready:
            try:
                await ensure_tables(self._ctx)
                self._tables_ready = True
            except Exception:  # noqa: BLE001 — DDL идемпотентен, повторим на след. репорте
                pass
        uuid = str(payload.get("node_uuid") or "")
        try:
            ts = int(payload.get("ts") or 0)
        except (TypeError, ValueError):
            return {"saved": False, "error": "bad_ts"}
        if not uuid or not isinstance(payload.get("metrics"), dict):
            return {"saved": False, "error": "bad_payload"}

        from .secret import get_agent_secret
        try:
            secret = await get_agent_secret(self._ctx)
        except RuntimeError:
            return {"saved": False, "error": "not_configured"}
        if abs(time.time() - ts) > STALE_WINDOW_S:
            return {"saved": False, "error": "stale"}
        metrics_json = json.dumps(payload["metrics"], sort_keys=True)
        expect = sign_payload(secret, uuid, ts, metrics_json)
        got = str(payload.get("sig") or "")
        if not hmac.compare_digest(expect, got):
            return {"saved": False, "error": "bad_signature"}
        if await _check_replay(uuid, ts):
            return {"saved": False, "error": "replay"}

        await self._ctx.db.execute(
            """INSERT INTO ddos_monitoring_agent_snapshots
                 (node_uuid, ts, cpu_pct, ram_pct, load1, cores,
                  rx_bps, tx_bps, rx_pps, tx_pps, rx_drop, tx_drop,
                  syn_recv, established, conntrack_count, conntrack_max,
                  swap_pct, disk_pct, failed_units, top_ips, unique_ips,
                  ip_limit_breaches)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)""",
            uuid, ts,
            payload["metrics"].get("cpu_pct"),
            payload["metrics"].get("ram_pct"),
            payload["metrics"].get("load1"),
            payload["metrics"].get("cores"),
            payload["metrics"].get("rx_bps"),
            payload["metrics"].get("tx_bps"),
            payload["metrics"].get("rx_pps"),
            payload["metrics"].get("tx_pps"),
            payload["metrics"].get("rx_drop"),
            payload["metrics"].get("tx_drop"),
            payload["metrics"].get("syn_recv", 0),
            payload["metrics"].get("established", 0),
            payload["metrics"].get("conntrack_count"),
            payload["metrics"].get("conntrack_max"),
            payload["metrics"].get("swap_pct"),
            payload["metrics"].get("disk_pct"),
            json.dumps(payload["metrics"].get("failed_units", [])),
            json.dumps(payload["metrics"].get("top_ips", [])),
            payload["metrics"].get("unique_ips", 0),
            json.dumps(payload["metrics"].get("ip_limit_breaches", [])),
        )
        await self._ctx.db.execute(
            """INSERT INTO ddos_monitoring_agent_status (node_uuid, last_seen, agent_version)
               VALUES ($1, $2, $3)
               ON CONFLICT (node_uuid) DO UPDATE
                 SET last_seen = EXCLUDED.last_seen, agent_version = EXCLUDED.agent_version""",
            uuid, ts, str(payload.get("agent_version") or ""),
        )
        _save_last_report(uuid, payload, ts)
        return {"saved": True}


async def ensure_tables(ctx) -> None:
    """DDL само-миграция плагина (IF NOT EXISTS)."""
    await ctx.db.execute(
        """CREATE TABLE IF NOT EXISTS ddos_monitoring_agent_snapshots (
             id bigserial PRIMARY KEY,
             node_uuid uuid NOT NULL,
             ts bigint NOT NULL,
             cpu_pct real, ram_pct real, load1 real, cores int,
             rx_bps bigint, tx_bps bigint, rx_pps bigint, tx_pps bigint,
             rx_drop bigint, tx_drop bigint,
             syn_recv int, established int,
             conntrack_count bigint, conntrack_max bigint,
             swap_pct real, disk_pct real,
             failed_units jsonb DEFAULT '[]',
             top_ips jsonb DEFAULT '[]',
             unique_ips int DEFAULT 0,
             ip_limit_breaches jsonb DEFAULT '[]',
             created_at timestamptz DEFAULT now()
           )"""
    )
    await ctx.db.execute(
        """CREATE INDEX IF NOT EXISTS idx_dmas_node_ts
             ON ddos_monitoring_agent_snapshots (node_uuid, ts DESC)"""
    )
    await ctx.db.execute(
        """CREATE TABLE IF NOT EXISTS ddos_monitoring_agent_status (
             node_uuid uuid PRIMARY KEY,
             last_seen bigint NOT NULL,
             agent_version text DEFAULT '',
             installed_at timestamptz,
             install_params jsonb
           )"""
    )


def generate_secret() -> str:
    import secrets as _s

    return _s.token_hex(32)
