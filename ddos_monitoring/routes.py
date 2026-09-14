"""Роуты плагина. Авторизация — только зависимости панели (auth_deps).

ddos:view — атаки и нагрузка; ddos:view_ips — IP атакующих (фаза 2+).
JSON — с no-store, через jsonable_encoder.
"""

import hmac
import hashlib
import time
import logging

from .tg_bot import _chat_ids, _as_str  # единые helpers с tg_bot

from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

_log = logging.getLogger("ddos_monitoring.routes")

_NO_STORE = {"Cache-Control": "private, no-store", "Pragma": "no-cache"}


def _hmac_eq(a: str, b: str) -> bool:
    """constant-time сравнение (timing-safe)."""
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


async def _handle_node_cmd(ctx, *, chat_id: int, arg: str) -> None:
    """/node <имя_or_uuid> — статус конкретной ноды.

    Поиск: точное совпадение по uuid, потом по name (case-insensitive prefix),
    потом substring. Если нода не найдена — сообщение об ошибке.
    """
    from . import tg_bot, notify, poller
    arg = (arg or "").strip()
    if not arg:
        await tg_bot.send(
            ctx,
            "❓ <b>/node</b> — укажи имя или uuid ноды.\n"
            "Например: <code>/node Fi3_TiHost_TG</code>",
            severity="info", chat_id=chat_id,
        )
        return
    poller_inst = getattr(poller, "POLLER", None)
    nodes = getattr(poller_inst, "_nodes", {}) or {}
    # 1) uuid
    found = nodes.get(arg)
    arg_lower = arg.lower()
    node_uuid = arg if found is not None else None
    # 2) name case-insensitive
    if not found:
        for uuid, n in nodes.items():
            if (n.get("name") or "").lower() == arg_lower:
                found, node_uuid = n, uuid
                break
    # 3) substring по name
    if not found:
        for uuid, n in nodes.items():
            if arg_lower in (n.get("name") or "").lower():
                found, node_uuid = n, uuid
                break
    if not found:
        await tg_bot.send(
            ctx,
            f"❌ Нода <b>{tg_bot.escape(arg)}</b> не найдена. "
            "Проверь имя или uuid.",
            severity="warning", chat_id=chat_id,
        )
        return
    # copy-on-read: не мутируем poller._nodes
    found = {**found, "uuid": found.get("uuid") or node_uuid or arg}
    # последний срез метрик (если есть)
    metrics = found.get("metrics") or {}
    body = notify.build_node_status_text(found, metrics)
    await tg_bot.send(ctx, body, severity="info", chat_id=chat_id)


def _json(payload: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(jsonable_encoder(payload), status_code=status, headers=_NO_STORE)


def build_router(ctx):
    from fastapi import APIRouter, Depends, HTTPException, Body, Request

    from web.backend.core.plugin_api import auth_deps

    from . import data
    from .poller import POLLER, STALE_AFTER_S

    AdminUser, require_permission = auth_deps()
    router = APIRouter()

    @router.post("/agent/report", summary="Срез ddos-agent: HMAC, без админ-сессии",
                 include_in_schema=False)
    async def agent_report(request=None, payload: dict = None):
        """Публичный endpoint для агентов. Авторизация — только HMAC-подпись."""
        from .agent_receiver import AgentReceiver
        if payload is None:
            try:
                payload = await request.json()
            except Exception:
                return _json({"saved": False, "error": "bad_payload"}, status=400)
        res = await AgentReceiver(ctx).handle(payload)
        return _json(res, status=200 if res.get("saved") else 400)

    @router.get("/agent/config", summary="Агент: динамическая конфигурация (HMAC, без сессии)",
                include_in_schema=False)
    async def agent_config(request: Request):
        """Аутентификация агента: HMAC SHA256 над `node_uuid|ts`, секрет — `agent_secret`.

        Headers:
            X-Node-Uuid: UUID ноды
            X-Ts: unix timestamp (сек)
            X-Sig: hex(HMAC-SHA256(secret, f"{node_uuid}|{ts}"))

        Stale-window 60 сек (см. agent_receiver.STALE_WINDOW_S).
        Ответ: {"top_ips_n": N} где N — настройка из plugin_settings, fallback 0.
        """
        from .secret import get_agent_secret
        from .agent_receiver import STALE_WINDOW_S

        node_uuid = (request.headers.get("X-Node-Uuid") or "").strip()
        ts_raw = (request.headers.get("X-Ts") or "").strip()
        sig = (request.headers.get("X-Sig") or "").strip().lower()
        if not node_uuid or not ts_raw or not sig:
            return _json({"error": "missing_auth_headers"}, status=401)
        try:
            ts = int(ts_raw)
        except (TypeError, ValueError):
            return _json({"error": "bad_ts"}, status=401)
        if abs(int(time.time()) - ts) > STALE_WINDOW_S:
            return _json({"error": "stale"}, status=401)
        try:
            secret = await get_agent_secret(ctx)
        except RuntimeError:
            return _json({"error": "not_configured"}, status=503)
        msg = f"{node_uuid}|{ts}".encode()
        expect = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return _json({"error": "bad_sig"}, status=401)
        try:
            row = await ctx.db.fetchrow(
                "SELECT value FROM plugin_settings WHERE key = 'top_ips_n'"
            )
            n = int(row["value"]) if row else 0
        except Exception as e:
            _log.warning("agent_config: read top_ips_n failed: %s", e)
            n = 0
        return _json({"top_ips_n": n})

    @router.get("/data", summary="Флот: состояние нод, активные атаки, статус poller (ddos:view)")
    async def data_route(_admin: AdminUser = Depends(require_permission("ddos", "view"))):
        state = POLLER.public_state()
        payload = {
            "poller": state,
            "nodes": await data.fleet_overview(ctx),
            "attacks_recent": await data.recent_attacks(ctx, limit=50),
            "total_nodes_in_panel": await data.total_nodes_in_panel(ctx),
        }
        # IP атакующих в /data не попадают: отдельное право с фазы 2.
        return _json(payload)

    @router.get("/details", summary="Расшифровка вердикта по нодам: systemd, Лимит IP топ, метрики (ddos:view)")
    async def details_route(_admin: AdminUser = Depends(require_permission("ddos", "view"))):
        names = {str(r["uuid"]): r["name"] for r in await ctx.db.fetch("select uuid, name from nodes")}
        out = []
        for d in await data.node_details(ctx):
            d["node_name"] = names.get(d["node_uuid"], d["node_uuid"])
            out.append(d)
        return _json({"nodes": out})

    @router.get("/active-ips", summary="Активные IP по нодам для скачивания (ddos:view)")
    async def active_ips_route(_admin: AdminUser = Depends(require_permission("ddos", "view"))):
        """GET /active-ips — уникальные активные IP, сгруппированные по нодам."""
        return _json({"nodes": await data.active_ips_by_node(ctx)})

    @router.get("/history", summary="Drill-down: срезы метрик ноды за range (ddos:view)")
    async def history_route(
        node_uuid: str,
        range: str = "1h",  # noqa: A002 — query param name matches API spec
        _admin: AdminUser = Depends(require_permission("ddos", "view")),
    ):
        """GET /history?node_uuid=...&range=1h — drill-down для sparkline UI."""
        return _json(await data.history_series(ctx, node_uuid, range))

    @router.post("/nodes/order", summary="Изменить порядок нод (ddos:edit)")
    async def nodes_order_route(
        payload: dict,
        _admin: AdminUser = Depends(require_permission("ddos", "edit")),
    ):
        """POST /nodes/order — {"order": [{"node_uuid": "...", "sort_order": 0}, ...]}"""
        order = payload.get("order")
        if not isinstance(order, list):
            return _json({"error": "order must be a list"}, status=400)
        if len(order) > 500:
            return _json({"error": "order too large (max 500)"}, status=400)
        for i, item in enumerate(order):
            if not isinstance(item, dict) or "node_uuid" not in item or "sort_order" not in item:
                return _json({"error": f"order[{i}] must have node_uuid and sort_order"}, status=400)
            try:
                int(item["sort_order"])
            except (ValueError, TypeError):
                return _json({"error": f"order[{i}].sort_order must be int"}, status=400)
        await data.set_node_order(ctx, order)
        return _json({"ok": True, "updated": len(order)})

    @router.get("/health", summary="Живость плагина")
    async def health(_admin: AdminUser = Depends(require_permission("ddos", "view"))):
        from .agent_installer import AGENT_VERSION
        return _json({"ok": True, "version": AGENT_VERSION})

    @router.get("/ui-module", summary="UI-модуль для /plugins/:pluginId (ddos:view)")
    async def ui_module(_admin: AdminUser = Depends(require_permission("ddos", "view"))):
        from .module import MODULE_JS
        from fastapi.responses import Response
        return Response(MODULE_JS, media_type="application/javascript; charset=utf-8",
                        headers=_NO_STORE)

    @router.get("/tg", summary="Настройки Telegram: маскированный токен + chat_ids (ddos:view)")
    async def tg_get(_admin: AdminUser = Depends(require_permission("ddos", "view"))):
        from .tg_bot import _as_str, _chat_ids, mask_token
        token = _as_str(await ctx.settings.get("tg_bot_token"))
        raw = _as_str(await ctx.settings.get("tg_chat_ids"))
        sum_en = await ctx.settings.get("summary_enabled")
        sum_h = await ctx.settings.get("summary_interval_h")
        try:
            sum_h = max(1, int(sum_h)) if sum_h is not None else 1
        except (TypeError, ValueError):
            sum_h = 1
        cd = await ctx.settings.get("alert_cooldown_m")
        try:
            cd = max(0, int(cd)) if cd is not None else 5
        except (TypeError, ValueError):
            cd = 5
        return _json({"token_masked": mask_token(token),
                      "chat_ids": _chat_ids(raw),
                      "summary_enabled": True if sum_en is None else bool(sum_en),
                      "summary_interval_h": sum_h,
                      "alert_cooldown_m": cd})

    @router.post("/tg", summary="Сохранить настройки Telegram + автоотчёта (токен в settings БД, ddos:view)")
    async def tg_post(payload: dict = Body(...),
                      _admin: AdminUser = Depends(require_permission("ddos", "view"))):
        token = str(payload.get("bot_token") or "").strip()
        chats = str(payload.get("chat_ids") or "").strip()
        if token:
            await ctx.settings.set("tg_bot_token", token)
        if chats:
            await ctx.settings.set("tg_chat_ids", chats)
        if "summary_enabled" in payload:
            await ctx.settings.set("summary_enabled", bool(payload["summary_enabled"]))
        if "summary_interval_h" in payload:
            try:
                h = max(1, int(payload["summary_interval_h"]))
                await ctx.settings.set("summary_interval_h", h)
            except (TypeError, ValueError):
                pass
        if "alert_cooldown_m" in payload:
            try:
                m = max(0, int(payload["alert_cooldown_m"]))
                await ctx.settings.set("alert_cooldown_m", m)
            except (TypeError, ValueError):
                pass
        return _json({"saved": True})

    @router.post("/tg/test", summary="Тестовое сообщение в настроенные чаты (ddos:view)")
    async def tg_test(payload: dict = Body(default=None),
                      _admin: AdminUser = Depends(require_permission("ddos", "view"))):
        from . import tg_bot
        text = (payload or {}).get("text") or "✅ DDoS-мониторинг: тест связи"
        state = {"sent": 0}
        real_api = tg_bot._bot_api

        async def counting(token, method, pl):
            res = await real_api(token, method, pl)
            state["sent"] += 1
            return res

        tg_bot._bot_api = counting
        try:
            await tg_bot.send(ctx, tg_bot.escape(text), severity="info")
        finally:
            tg_bot._bot_api = real_api
        via = "panel" if state["sent"] == 0 and ctx.panel_calls else "bot"
        return _json({"sent": state["sent"], "via": via})

    @router.post("/tg/webhook", summary="Telegram webhook для бота плагина (без сессии)",
                 include_in_schema=False)
    async def tg_webhook(request: Request, payload: dict = Body(default=None)):
        """Принимает update от Telegram и обрабатывает команды /update, /node.

        Авторизация — через X-Telegram-Bot-Api-Secret-Token (если задан в
        plugin_settings.tg_webhook_secret). Если секрет не задан — принимаем
        update от любого Telegram-сервера (URL знает только владелец бота).

        Команды:
          /update         — то же, что и автоотчёт (send_summary), ответ в чат
          /node <имя|uuid> — статус конкретной ноды
          /help           — список команд
        """
        from . import tg_bot, notify
        payload = payload or {}
        # 1) Верификация webhook по X-Telegram-Bot-Api-Secret-Token
        secret = _as_str(await ctx.settings.get("tg_webhook_secret"))
        sent_token = request.headers.get("x-telegram-bot-api-secret-token", "")
        if secret and not _hmac_eq(sent_token, secret):
            return _json({"error": "bad_webhook_secret"}, status=403)
        # 2) Извлекаем сообщение
        msg = (payload.get("message") or payload.get("edited_message") or {})
        text = (msg.get("text") or "").strip()
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        if not text or chat_id is None:
            return _json({"ok": True})  # не наша команда
        # 3) Anti-abuse: разрешены только настроенные chat_ids
        allowed = set(_chat_ids(_as_str(await ctx.settings.get("tg_chat_ids"))))
        if allowed and chat_id not in allowed:
            _log.warning("ddos-monitoring: tg_webhook from unknown chat %s", chat_id)
            return _json({"ok": True})  # молча игнорим (не раскрываем факт)
        # 4) Маршрутизация команд
        if text == "/update" or text.startswith("/update ") or text.startswith("/update@"):
            try:
                rows = await POLLER._summary_rows(ctx)
            except Exception:  # noqa: BLE001
                _log.warning("ddos-monitoring: tg_webhook /update rows failed", exc_info=True)
                rows = []
            body = notify.build_summary_text(rows)
            await tg_bot.send(ctx, body, severity="info", chat_id=int(chat_id))
        elif text == "/node" or text.startswith("/node ") or text.startswith("/node@"):
            parts = text.split(maxsplit=1)
            arg = parts[1].strip() if len(parts) > 1 else ""
            await _handle_node_cmd(ctx, chat_id=int(chat_id), arg=arg)
        elif text == "/help" or text.startswith("/help ") or text.startswith("/help@"):
            await tg_bot.send(
                ctx,
                "🛡 <b>DDoS-мониторинг — команды</b>\n\n"
                "/update — сводка по всем нодам (как автоотчёт)\n"
                "/node <имя или uuid> — статус конкретной ноды\n"
                "/help — это сообщение",
                severity="info", chat_id=int(chat_id),
            )
        return _json({"ok": True})

    @router.get("/ui", summary="Standalone-страница (панели <4.5.4, без generic-маршрута, ddos:view)")
    async def ui_page(_admin: AdminUser = Depends(require_permission("ddos", "view"))):
        from .page import PAGE_HTML
        from fastapi.responses import HTMLResponse
        return HTMLResponse(PAGE_HTML, headers=_NO_STORE)

    # Агентские роуты (установка через exec_script, статус, UI-секция)
    from .agent_routes import register_agent_routes
    register_agent_routes(router, ctx=ctx, Body=Body,
                          permission_factory=lambda res, act: require_permission(res, act))

    return router
