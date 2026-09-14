"""Свой Telegram-бот плагина: Bot API sendMessage, fallback на panel_notify.

Токен и chat_id — только в settings БД панели. В коде/гите их нет.
"""
from __future__ import annotations

import html
import json
import logging
import typing

import aiohttp

logger = logging.getLogger("plugin.ddos-monitoring")

BOT_API_BASE = "https://api.telegram.org/bot{token}/{method}"


async def _bot_api(token: str, method: str, payload: dict) -> dict:
    url = BOT_API_BASE.format(token=token, method=method)
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload) as resp:
            return await resp.json(content_type=None)


def _chat_ids(raw: typing.Any) -> list[int]:
    if not raw:
        return []
    out = []
    for part in str(raw).split(","):
        part = part.strip()
        try:
            out.append(int(part))
        except ValueError:
            continue
    return out


def _as_str(raw: typing.Any) -> str:
    """jsonb-значение из settings может прийти str, {'': str} или с кавычками."""
    if raw is None:
        return ""
    if isinstance(raw, dict):
        raw = raw.get("") or next(iter(raw.values()), "")
    s = str(raw).strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s.strip()


async def send(ctx, text: str, severity: str = "info",
               chat_id: int | None = None) -> None:
    """Отправка через свой бот (если настроен), иначе fallback panel_notify.

    chat_id: если задан — отправляем ТОЛЬКО в этот чат (для ответов на команды);
    иначе — рассылка по всем chat_ids из settings.
    """
    token = _as_str(await ctx.settings.get("tg_bot_token"))
    if not token:
        panel_notify = getattr(ctx, "panel_notify", None)
        if not callable(panel_notify):
            logger.warning("ddos-monitoring: panel_notify unavailable; notification skipped")
            return
        try:
            await panel_notify(title="DDoS-мониторинг", body=text,
                               severity=severity, plugin_id="ddos-monitoring")
        except Exception:  # noqa: BLE001
            logger.warning("ddos-monitoring: panel_notify failed", exc_info=True)
        return
    chats = _chat_ids(_as_str(await ctx.settings.get("tg_chat_ids")))
    targets = [chat_id] if chat_id is not None else chats
    if not targets:
        logger.warning("ddos-monitoring: tg send_to_chat(%s) skipped — no chat_ids", chat_id)
        return
    payload_base = {
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    for cid in targets:
        try:
            data = await _bot_api(token, "sendMessage",
                                  {**payload_base, "chat_id": cid})
            if not data.get("ok"):
                logger.warning("ddos-monitoring: tg send to %s failed: %s",
                               cid, json.dumps(data)[:200])
        except Exception:  # noqa: BLE001 — алерт не роняет тик
            logger.warning("ddos-monitoring: tg send failed for %s", cid, exc_info=True)


def mask_token(token: str) -> str:
    """Для показа в UI: первые 12 символов + многоточие."""
    if not token:
        return ""
    return token[:12] + "…"


def escape(text: str) -> str:
    return html.escape(str(text), quote=False)
