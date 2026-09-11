"""Роуты управления ddos-agent: установка на ноды + статус.

POST /agent/nodes — установить/переустановить агента на выбранных нодах
GET  /agent/status — кто рапортует, версия, свежесть
"""

import time

from .agent_installer import build_install_script, AGENT_VERSION


def register_agent_routes(router, *, ctx, Body, permission_factory):
    """Регистрация в PluginAPIRouter плагина.

    permission_factory("ddos", "manage") → зависимость авторизации;
    оба роута требуют право ddos:manage (установка = exec на нодах).
    """

    from fastapi import Depends, HTTPException

    @router.get("/agent/status", summary="Статус ddos-agent по нодам (ddos:view)")
    async def agent_status(_admin: object = Depends(permission_factory("ddos", "view"))):
        from . import agent_receiver as AR
        from web.backend.core.plugin_api import panel_api

        nodes_res = await panel_api().get_nodes()
        rows = nodes_res.get("response", []) if isinstance(nodes_res, dict) else []
        out = {}
        for row in rows:
            uuid = str(row.get("uuid") or "")
            info = AR._last_report.get(uuid)
            if not info:
                out[uuid] = {"name": row.get("name"), "online": False,
                             "agent_version": None}
                continue
            age = time.time() - info["ts"]
            out[uuid] = {
                "name": row.get("name"),
                "online": age <= AR.ONLINE_WINDOW_S,
                "last_seen_age_s": int(age),
                "agent_version": info.get("agent_version"),
            }
        return {"agent_version": AGENT_VERSION, "nodes": out}

    @router.get("/agent/ui", summary="HTML секции «Агент на нодах» (ddos:view)")
    async def agent_ui(_admin: object = Depends(permission_factory("ddos", "view"))):
        from fastapi.responses import HTMLResponse
        from .module import render_agent
        try:
            st = await agent_status()
        except Exception:
            st = {"agent_version": AGENT_VERSION, "nodes": {}}
        return HTMLResponse(render_agent(st))

    @router.post("/agent/nodes",
                 summary="Установить/переустановить ddos-agent (ddos:manage)")
    async def agent_install(payload: dict,
                            _admin: object = Depends(permission_factory("ddos", "manage"))):
        from web.backend.core.plugin_api import panel_api

        payload = payload or {}
        uuids = [str(u) for u in (payload.get("node_uuids") or [])]
        interval = min(300, max(5, int(payload.get("interval_s") or 15)))
        ip_limit = max(0, int(payload.get("ip_limit") or 50))
        top_n = max(1, int(payload.get("top_ips_n") or 10))

        # Приоритет адреса панели для репортов агента (self-service: работает
        # в любой панели без ручных настроек):
        #   1. настройка agent_report_base_url (осознанный override)
        #   2. origin запроса админа (тот домен, через который открыта панель)
        #   3. plugin_api._base_url → env PANEL_PUBLIC_URL
        base_url = None
        try:
            from shared.database import db_service as _db
            async with _db.acquire() as _conn:
                _v = await _conn.fetchval(
                    "select value::text from plugin_settings "
                    "where plugin_id='ddos-monitoring' and key='agent_report_base_url'")
                if _v:
                    import json as _json
                    base_url = str(_json.loads(_v) if _v.startswith('"') else _v).rstrip("/")
        except Exception:  # noqa: BLE001
            base_url = None
        if not base_url:
            # Из URL панели (fallback, если base_url не задан в настройках)
            base_url = None

        nodes_res = await panel_api().get_nodes()
        rows = nodes_res.get("response", []) if isinstance(nodes_res, dict) else []
        known = {str(r.get("uuid")) for r in rows}
        unknown = [u for u in uuids if u not in known]
        targets = [u for u in uuids if u in known]

        secret = await ctx.settings.get("agent_secret")
        if isinstance(secret, dict):
            secret = next(iter(secret.values()), "")
        secret = (secret or "").strip()
        if not secret:
            # Общий fallback не генерируем молча: per-node секреты обязательны,
            # глобальный — только как base при их отсутствии.
            raise HTTPException(
                status_code=409, detail="agent_secret_not_configured")

        panel_url = str(payload.get("panel_url") or "").rstrip("/")
        installed = []
        errors: dict[str, str] = {}

        if panel_url:
            return {"error": "panel_url_param_deprecated",
                    "detail": "panel_url определяется автоматически"}

        if not base_url:
            try:
                from web.backend.core.plugin_api import panel_api
                pa = panel_api()
                base_url = getattr(pa, "_base_url", None)
            except Exception:  # noqa: BLE001
                base_url = None
        if not base_url:
            import os
            base_url = os.environ.get("PANEL_PUBLIC_URL") or ""
        if not base_url:
            return {"error": "no_panel_url",
                    "detail": "не удалось определить внешний адрес панели"}

        # Транспорт — Fleet exec-script панели. Плагин выполняется в том же
        # uvicorn-процессе, что и WS-реестр агентов, поэтому используем
        # внутренний путь scripts._exec_one напрямую (без HTTP и админ-JWT).
        from shared.database import db_service
        from web.backend.api.v2.scripts import _exec_one

        async with db_service.acquire() as conn:
            for u in targets:
                script_body = build_install_script(base_url, u,
                                                   interval=interval,
                                                   ip_limit=ip_limit,
                                                   top_ips_n=top_n)
                name = f"ddos-agent-install-{u[:8]}"
                row = await conn.fetchrow(
                    """INSERT INTO node_scripts (name, display_name, description,
                                                 script_content, timeout_seconds)
                       VALUES ($1,$1,$2,$3,120)
                       ON CONFLICT (name) DO UPDATE SET
                           script_content = EXCLUDED.script_content,
                           updated_at = NOW()
                       RETURNING *""",
                    name, "DDoS-мониторинг: установка ddos-agent", script_body)
                try:
                    res = await _exec_one(
                        db_service, dict(row), u,
                        {"DDOS_AGENT_SECRET": secret},
                        admin_id=None, admin_username="plugin:ddos-monitoring")
                    if res.get("status") == "running":
                        installed.append(u)
                    else:
                        errors[u] = str(res.get("error") or "exec_failed")
                except Exception as e:  # noqa: BLE001 — ошибка одной ноды не роняет остальные
                    errors[u] = str(e)[:200]

        result = {"installed": installed, "unknown": unknown, "errors": errors,
                  "agent_version": AGENT_VERSION}
        if unknown:
            result["error"] = "unknown_nodes"
        return result
