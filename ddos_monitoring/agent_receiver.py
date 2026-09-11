"""Приёмник срезов ddos-agent: HMAC-валидация + запись в БД панели.

Панель не трогаем — endpoint регистрируется роутером плагина.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

# Окно свежести ts (сек) — защита от replay
STALE_WINDOW_S = 120
# Нода считается online, если рапортовала недавно
ONLINE_WINDOW_S = 90

# Реестр последних валидных репортов: uuid -> {ts, agent_version, metrics}
_last_report: dict = {}
# Replay-защита: последние виденные ts per node (окно STALE_WINDOW_S).
# Лимит uuid защищает от распухания карты при спуфинге node_uuid.
# set-значение ограничено: вытесняем ts, которые (a) устарели (old than cutoff)
# или (b) слишком в будущем (future drift ≥ STALE_WINDOW_S — защита от OOM-атаки).
_seen_ts: dict = {}
_SEEN_MAX_UUIDS = 4096
# Лимит размера set'a per uuid (защита от долгоживущих future ts)
_SEEN_MAX_TS_PER_UUID = 256


def _check_replay(uuid: str, ts: int) -> bool:
    """True = дубликат. Защита от будущих ts (OOM-вектор):
    ts дальше чем now + STALE_WINDOW_S считаем уже валидным, не храним.
    """
    now = time.time()
    seen = _seen_ts.get(uuid)
    if seen is None:
        # Лимит количества uuid: вытесняем самый старый ключ (FIFO по вставке)
        if len(_seen_ts) >= _SEEN_MAX_UUIDS:
            oldest = next(iter(_seen_ts))
            _seen_ts.pop(oldest, None)
        _seen_ts[uuid] = set()
        seen = _seen_ts[uuid]
    # чистка устаревших + future-drift
    cutoff_old = now - STALE_WINDOW_S
    cutoff_future = now + STALE_WINDOW_S
    _seen_ts[uuid] = {t for t in seen if cutoff_old <= t <= cutoff_future}
    # Лимит размера set'а per uuid (на случай ОЧЕНЬ долгой жизни ключа)
    if len(_seen_ts[uuid]) >= _SEEN_MAX_TS_PER_UUID:
        # Вытесняем самый старый ts (FIFO). set в Python сохраняет insertion order
        oldest = next(iter(_seen_ts[uuid]))
        _seen_ts[uuid].discard(oldest)
    seen = _seen_ts[uuid]
    if ts in seen:
        return True
    # Защита: не сохраняем future-ts дальше cutoff_future
    if ts > cutoff_future:
        return False  # считаем валидным (он вне окна stale → будет отвергнут выше), но не храним
    seen.add(ts)
    return False


def sign_payload(secret: str, node_uuid: str, ts: int, metrics_json: str) -> str:
    msg = f"{node_uuid}|{ts}|{metrics_json}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


class AgentReceiver:
    """Обработка одного отчёта агента. DDL идемпотентен (IF NOT EXISTS),
    поэтому каждый Receiver пытается ensure_tables при первом репорте —
    нет необходимости в class-level mutable state."""
    def __init__(self, ctx):
        self._ctx = ctx
        self._tables_ready = False

    async def _ensure_tables_once(self) -> None:
        if self._tables_ready:
            return
        try:
            await ensure_tables(self._ctx)
            self._tables_ready = True
        except Exception:  # noqa: BLE001 — DDL идемпотентен, повторим на след. репорте
            self._tables_ready = False

    async def handle(self, payload: dict) -> dict:
        await self._ensure_tables_once()
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
        if _check_replay(uuid, ts):
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
        _last_report[uuid] = {
            "ts": ts,
            "agent_version": str(payload.get("agent_version") or ""),
            "metrics": payload["metrics"],
        }
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
