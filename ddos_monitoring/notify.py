"""Фаза 2: алерты в ТГ/панель через штатный notification_service панели.

Сообщения повторяют формат легаси-монитора (легаси): эмодзи-статусы,
московское время, метрики среза. Отправка — ctx.panel_notify(...) (Plugin API
v1, панель ≥4.6); при недоступности — тихий отказ, лог пишет poller.
"""
from __future__ import annotations

import datetime
import typing

from .tg_bot import escape

SEVERITY_MAP = {"critical": "error", "high": "warning", "warning": "warning",
                "medium": "warning", "normal": "info"}

STATE_TITLE = {
    "attack": "🚨 <b>DDoS-атака обнаружена</b>",
    "load": "🟠 <b>Высокая нагрузка без признаков DDoS</b>",
    "health": "🟡 <b>Состояние ноды требует внимания</b>",
    "stable": "",  # формируется по previous
    "offline": "⚫️ <b>Нет связи с мониторингом</b>",
}

SEVERITY_RU = {"critical": "КРИТИЧЕСКИЙ", "high": "ВЫСОКИЙ", "medium": "СРЕДНИЙ"}


def _msk_time() -> str:
    msk = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=3)))
    return msk.strftime("%d.%m.%Y %H:%M:%S МСК")


def _rate(v: typing.Any) -> str:
    try:
        mbps = float(v) / 1_000_000
    except (TypeError, ValueError):
        return "0.0"
    if mbps >= 100:
        return f"{mbps:.0f}"
    return f"{mbps:.1f}"


def _count(v: typing.Any) -> str:
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        return "0"
    return f"{n:,}".replace(",", " ")


def _duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds >= 3600:
        h, rest = divmod(seconds, 3600)
        m = rest // 60
        return f"{h} ч {m} мин"
    if seconds >= 60:
        return f"{seconds // 60} мин {seconds % 60} с"
    return f"{seconds} с"


def _agent_source_line(metrics: dict) -> str:
    if (metrics or {}).get("source") == "agent":
        return "📡 Источник: ddos-agent"
    return ""


def _agent_metric_lines(m: dict, vpn_map: dict | None = None) -> list[str]:
    """Дополнительные строки легаси-формата для агентских метрик.

    Внешние данные (IP из /proc, имена юнитов) экранируются — parse_mode=HTML.
    vpn_map: {ip: email} — легальные клиенты помечаются [vpn]; email в TG
    НЕ попадает (приватность).
    """
    if not m or m.get("source") != "agent":
        return []
    from .tg_bot import escape

    vpn = vpn_map or {}
    lines = []
    syn = m.get("syn_recv")
    est = m.get("established")
    if syn is not None or est is not None:
        lines.append(f"🔗 Соединения: SYN_RECV: {int(syn or 0)} · EST: {int(est or 0)}")
    uniq = m.get("unique_ips")
    if uniq is not None:
        top = m.get("top_ips") or []
        parts = []
        for t in top[:10]:
            ip_s = escape(t.get("ip"))
            mark = " [vpn]" if t.get("ip") in vpn else ""
            parts.append(f"{ip_s} ({int(t.get('count') or 0)}){mark}")
        line = f"👥 Уникальные IP: {int(uniq)}"
        if parts:
            line += " · " + ", ".join(parts)
        lines.append(line)
    failed = [u for u in (m.get("failed_units") or []) if u]
    if failed:
        lines.append("⚙️ systemd: " + ", ".join(escape(u) for u in failed[:5]))
    # Лимит IP: легаси-детализация — топ-10 нарушителей с числом соединений
    breaches = m.get("ip_limit_breaches") or []
    if breaches:
        top_b = sorted(breaches, key=lambda b: -int(b.get("count") or 0))[:10]
        parts = []
        for b in top_b:
            ip_s = escape(str(b.get("ip")))
            mark = " [vpn]" if b.get("ip") in vpn else ""
            parts.append(f"{ip_s} ({int(b.get('count') or 0)} соед.){mark}")
        lines.append("⚠️ Лимит IP: превышение по " + ", ".join(parts))
    swap = m.get("swap_pct")
    disk = m.get("disk_pct")
    if swap is not None and float(swap) > 50:
        lines.append(f"💾 Swap: {float(swap):.0f}%")
    if disk is not None and float(disk) >= 80:
        lines.append(f"🗄 Диск: {float(disk):.0f}%")
    return lines


def _metric_lines(metrics: dict) -> list[str]:
    if not metrics:
        return []
    # Панельные и агентские срезы используют разные имена полей.
    # Нормализуем только формат уведомления; классификатор и payload не меняем.
    rx_bps = metrics.get("net_rx_bps", metrics.get("rx_bps"))
    rx_pps = metrics.get("net_rx_pps", metrics.get("rx_pps"))
    tx_bps = metrics.get("net_tx_bps", metrics.get("tx_bps"))
    tx_pps = metrics.get("net_tx_pps", metrics.get("tx_pps"))
    lines = [
        f"📥 RX: {_rate(rx_bps)} Мбит/с · "
        f"{_count(rx_pps)} пак/с",
        f"📤 TX: {_rate(tx_bps)} Мбит/с · "
        f"{_count(tx_pps)} пак/с",
    ]
    cc = metrics.get("conntrack_count")
    cm = metrics.get("conntrack_max")
    if cc and cm:
        pct = float(cc) / float(cm) * 100 if float(cm) else 0.0
        lines.append(f"🧱 Conntrack: {_count(cc)} / {_count(cm)} ({pct:.1f}%)")
    else:
        lines.append(f"🧱 Conntrack: {_count(cc)}")
    cpu = metrics.get("cpu_usage", metrics.get("cpu_pct"))
    mem = metrics.get("memory_usage", metrics.get("ram_pct"))
    load = metrics.get("load1")
    if cpu is not None or mem is not None or load is not None:
        parts = []
        if cpu is not None:
            parts.append(f"CPU {float(cpu):.1f}%")
        if mem is not None:
            parts.append(f"RAM {float(mem):.1f}%")
        if load is not None:
            parts.append(f"Load {float(load):.1f}")
        lines.append("🧠 Ресурсы: " + " · ".join(parts))
    return lines


async def _send(ctx, title: str, body_lines: list[str], severity: str) -> None:
    body = "\n".join([title, ""] + body_lines)
    from . import tg_bot
    await tg_bot.send(ctx, body, severity=severity)


async def send_state_change(ctx, node_uuid: str, node_name: str, *,
                            previous: str, current: dict,
                            repeated: bool = False,
                            duration_s: float | None = None,
                            peak: dict | None = None,
                            metrics: dict | None = None,
                            error: str = "",
                            vpn_ips: set | None = None) -> None:
    state = current.get("state", "stable")
    if metrics and not current.get("metrics"):
        current = {**current, "metrics": metrics}

    if state == "stable":
        if previous == "attack":
            lines = ["✅ <b>Атака завершилась</b>", ""]
            if duration_s is not None:
                lines.append(f"⏱ <b>Продолжительность:</b> {_duration(duration_s)}")
            pk = peak or {}
            lines += [
                f"📈 <b>Пиковый RX:</b> {_rate(pk.get('net_rx_bps'))} Мбит/с",
                f"📦 <b>Пиковый PPS:</b> {_count(pk.get('net_rx_pps'))} пак/с",
                "",
                "🟢 Показатели вернулись в норму.",
            ]
            await _send(ctx, lines[0], lines[1:], "info")
        elif previous == "offline":
            lines = [
                "🟢 <b>Связь с мониторингом восстановлена</b>",
                "",
                f"🖥 <b>Сервер:</b> {escape(node_name)}",
                f"🕒 {_msk_time()}",
            ]
            await _send(ctx, lines[0], lines[1:], "info")
        return

    if state == "offline":
        await _send(ctx, STATE_TITLE["offline"],
                    [f"🖥 <b>Сервер:</b> {escape(node_name)}",
                     f"🕒 {_msk_time()}",
                     f"🧩 <b>Причина:</b> {escape((error or 'нет телеметрии')[:200])}"], "warning")
        return

    reasons = escape(", ".join(current.get("reasons") or []))
    metrics = current.get("metrics") or {}
    src_line = _agent_source_line(metrics)
    agent_extra = _agent_metric_lines(metrics, vpn_map={ip: "" for ip in (vpn_ips or ())})
    lines = [
        f"🖥 <b>Сервер:</b> {escape(node_name)}",
        f"🕒 Время: {_msk_time()}",
    ]
    if src_line:
        lines.append(src_line)
    if state == "attack":
        if repeated:
            title = "🚨 <b>DDoS-атака продолжается</b>"
        else:
            title = STATE_TITLE["attack"]
        lines += [
            f"💥 <b>Тип:</b> {current.get('attack_type', '')}",
            f"🔴 <b>Уровень:</b> {SEVERITY_RU.get(current.get('severity'), '?')}",
            f"📌 <b>Сработало:</b> {reasons}",
            "",
] + _metric_lines(metrics) + agent_extra
        sev = current.get("severity", "medium")
    else:
        title = STATE_TITLE[state]
        lines += [f"📌 <b>Сработало:</b> {reasons}", ""] \
            + _metric_lines(metrics) + agent_extra
        sev = "warning"

    await _send(ctx, title, lines, sev)


async def send_summary(ctx, rows: list[tuple]) -> None:
    """rows: [(uuid, name, state, attack_type, reasons), ...]"""
    counts: dict[str, int] = {}
    lines = ["🛡 <b>Состояние инфраструктуры</b>", f"🕒 {_msk_time()}", ""]
    for _uuid, name, state, attack_type, reasons in rows:
        name = escape(name)
        attack_type = escape(attack_type)
        # Причины по легаси: только короткие имена («systemd», «Лимит IP»),
        # без развёрнутых списков — детали уходят в алерты.
        short = [r for r in (reasons if isinstance(reasons, list) else [reasons or ""]) if r]
        reasons = escape(", ".join(short))
        counts[state] = counts.get(state, 0) + 1
        if state == "attack":
            lines.append(f"🔴 <b>{name}:</b> атакуют" + (f" · {attack_type}" if attack_type else ""))
        elif state == "load":
            lines.append(f"🟠 <b>{name}:</b> высокая нагрузка" + (f" · {reasons}" if reasons else ""))
        elif state == "health":
            lines.append(f"🟡 <b>{name}:</b> состояние требует внимания" + (f" · {reasons}" if reasons else ""))
        elif state == "offline":
            lines.append(f"⚫️ <b>{name}:</b> нет связи")
        else:
            lines.append(f"🟢 <b>{name}:</b> стабильно")
    total = ("Итого: 🔴 %d · 🟢 %d · 🟠 %d · 🟡 %d · ⚫️ %d" %
             (counts.get("attack", 0), counts.get("stable", 0),
              counts.get("load", 0), counts.get("health", 0),
              counts.get("offline", 0)))
    lines += ["", total]
    await _send(ctx, lines[0], lines[1:], "info")
