"""Роуты управления ddos-agent: установка на ноды + статус.

POST /agent/nodes — установить/переустановить агента на выбранных нодах
GET  /agent/status — кто рапортует, версия, свежесть
"""

import logging
import time

from .agent_installer import build_install_script, AGENT_VERSION

_log = logging.getLogger("ddos_monitoring.agent_routes")


def _node_info_from_report(uuid: str, name, AR) -> dict:
    """Собрать инфо-объект ноды: имя + online + agent_version из _last_report.

    Если репорта не было — online=False, agent_version=None. Имя берётся
    из любого доступного источника (panel_api или прямой SQL к nodes).
    """
    info = AR._last_report.get(uuid)
    if not info:
        return {"name": name, "online": False, "agent_version": None}
    age = time.time() - info["ts"]
    return {
        "name": name,
        "online": age <= AR.ONLINE_WINDOW_S,
        "last_seen_age_s": int(age),
        "agent_version": info.get("agent_version"),
    }


async def _precheck_install_targets(targets, conn,
                                    return_unknown: bool = False):
    """Проверка готовности нод к install через SQL.

    Без agent_token (NULL) fleet-agent панели не сможет авторизоваться
    на ноде → _exec_one вернёт AGENT_NOT_CONNECTED. Без is_connected —
    агент ещё не зарегистрировался в WS-реестре панели.

    Возвращает (filtered_targets, errors). Если return_unknown=True —
    дополнительно (filtered_targets, errors, unknown).
    """
    errors: dict[str, str] = {}
    if not targets:
        return (targets, errors, []) if return_unknown else (targets, errors)

    rows = await conn.fetch(
        "SELECT uuid::text, "
        "       (agent_token IS NOT NULL) AS has_token, "
        "       COALESCE(is_connected, false) AS is_connected "
        "FROM public.nodes WHERE uuid = ANY($1::uuid[])",
        list(targets))
    by_uuid = {str(r["uuid"]): r for r in rows}

    new_targets: list[str] = []
    unknown: list[str] = []
    for u in targets:
        row = by_uuid.get(u)
        if row is None:
            unknown.append(u)
            continue
        if not row["has_token"]:
            errors[u] = (
                "NO_AGENT_TOKEN: fleet agent на ноде не зарегистрирован. "
                "Сгенерируй токен в UI панели (карточка ноды → "
                "Подключить → Получить токен) или через API.")
            continue
        if not row["is_connected"]:
            errors[u] = (
                "FLEET_AGENT_OFFLINE: fleet agent на ноде не подключён "
                "к панели. Проверь xray-agent на сервере и перезапусти.")
            continue
        new_targets.append(u)

    if return_unknown:
        return new_targets, errors, unknown
    return new_targets, errors


async def agent_status_impl(ctx) -> dict:
    """Ядро /agent/status: panel_api → fallback на прямой SQL к таблице nodes.

    Ядро Remnawave /api/nodes иногда возвращает не все ноды (особенность
    фильтрации по полям raw_data/xray_version/traffic — наблюдалось на
    82.38.96.91). Чтобы /agent/ui показывал все ноды (даже без агента),
    дополняем результат прямым SQL-запросом к public.nodes.
    """
    from . import agent_receiver as AR
    from web.backend.core.plugin_api import panel_api

    out: dict[str, dict] = {}

    # 1) Основной источник — panel_api (с именами и кэшированием ядра)
    try:
        nodes_res = await panel_api().get_nodes()
        rows = nodes_res.get("response", []) if isinstance(nodes_res, dict) else []
        for row in rows:
            uuid = str(row.get("uuid") or "")
            if not uuid:
                continue
            out[uuid] = _node_info_from_report(uuid, row.get("name"), AR)
    except Exception:  # noqa: BLE001 — fallback ниже всё равно спасёт
        pass

    # 2) Fallback — прямой SQL к таблице nodes. Если uuid есть в БД, но
    # не пришёл из panel_api, добавляем с online=False.
    #    Дополнительно: вытаскиваем agent_token (NULL → нода не сможет
    #    выполнять exec_script → install вернёт AGENT_NOT_CONNECTED).
    try:
        db = getattr(ctx, "db", None)
        if db is not None:
            db_rows = await db.fetch(
                "SELECT uuid::text, name, "
                "       (agent_token IS NOT NULL) AS has_token, "
                "       COALESCE(is_connected, false) AS is_connected "
                "FROM public.nodes WHERE is_disabled = false")
            for row in db_rows:
                uuid = str(row["uuid"])
                info = out.get(uuid) or _node_info_from_report(
                    uuid, row["name"], AR)
                info["name"] = info.get("name") or row["name"]
                info["has_agent_token"] = bool(row["has_token"])
                info["is_connected"] = bool(row["is_connected"])
                out[uuid] = info
    except Exception:  # noqa: BLE001
        pass

    return {"agent_version": AGENT_VERSION, "nodes": out}


def register_agent_routes(router, *, ctx, Body, permission_factory):
    """Регистрация в PluginAPIRouter плагина.

    permission_factory("ddos", "manage") → зависимость авторизации;
    оба роута требуют право ddos:manage (установка = exec на нодах).
    """

    from fastapi import Depends, HTTPException

    @router.get("/agent/status", summary="Статус ddos-agent по нодам (ddos:view)")
    async def agent_status(_admin: object = Depends(permission_factory("ddos", "view"))):
        return await agent_status_impl(ctx)

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
        _log.info("ddos-install: handler entered payload=%s",
                  str({k: (v if k != 'panel_url' else '...') for k, v in (payload or {}).items()})[:300])

        payload = payload or {}
        uuids = [str(u) for u in (payload.get("node_uuids") or [])]
        _log.info("ddos-install: uuids=%s", uuids)
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
        _log.info("ddos-install: panel_api returned %d nodes", len(rows))
        known = {str(r.get("uuid")) for r in rows}
        unknown: list[str] = []
        targets = [u for u in uuids if u in known]
        missing = [u for u in uuids if u not in known]
        _log.info("ddos-install: panel_api-known targets=%s missing=%s",
                  targets, missing)

        # Fallback: UUID'ы отсутствующие в panel_api() (например добавленные
        # вручную через UI «Подключить сервер», либо фильтруемые ядром по
        # raw_data). Если UUID есть в public.nodes с agent_token и
        # is_connected — добавляем в targets. Иначе — в unknown с причиной.
        errors: dict[str, str] = {}
        if missing:
            try:
                from shared.database import db_service as _db_fb
                async with _db_fb.acquire() as _fb_conn:
                    _fb_rows = await _fb_conn.fetch(
                        "SELECT uuid::text, name, "
                        "       (agent_token IS NOT NULL) AS has_token, "
                        "       COALESCE(is_connected, false) AS is_connected, "
                        "       is_disabled "
                        "FROM public.nodes WHERE uuid = ANY($1::uuid[])",
                        missing)
                    _fb_by_uuid = {str(r["uuid"]): r for r in _fb_rows}
                    for u in missing:
                        row = _fb_by_uuid.get(u)
                        if row is None:
                            unknown.append(u)
                            errors[u] = "UNKNOWN_NODE: UUID отсутствует в БД"
                            continue
                        if row["is_disabled"]:
                            unknown.append(u)
                            errors[u] = "NODE_DISABLED: нода отключена"
                            continue
                        if not row["has_token"]:
                            unknown.append(u)
                            errors[u] = (
                                "NO_AGENT_TOKEN: fleet agent на ноде не "
                                "зарегистрирован. Сгенерируй токен в UI "
                                "панели (карточка ноды → Подключить → "
                                "Получить токен).")
                            continue
                        if not row["is_connected"]:
                            unknown.append(u)
                            errors[u] = (
                                "FLEET_AGENT_OFFLINE: fleet agent на ноде "
                                "не подключён к панели. Проверь xray-agent "
                                "на сервере и перезапусти.")
                            continue
                        # Всё ОК — добавляем в targets
                        targets.append(u)
                        _log.info(
                            "ddos-install: %s (%s) added via SQL fallback",
                            u, row["name"])
            except Exception as _e:  # noqa: BLE001
                _log.warning("ddos-install: SQL fallback failed: %s", _e)
                # Если fallback упал — оставляем в unknown
                for u in missing:
                    if u not in unknown:
                        unknown.append(u)
                        errors[u] = "SQL_FALLBACK_FAILED: " + str(_e)[:120]

        _log.info("ddos-install: after SQL fallback targets=%s unknown=%s",
                  targets, unknown)

        # Pre-check: для каждой target-проверяем что agent_token сгенерирован.
        # Дополнительная проверка через _precheck (дублируется для safety).
        if targets:
            try:
                from shared.database import db_service as _db_pre
                async with _db_pre.acquire() as _conn:
                    targets, _pre_errors, _pre_unknown = await _precheck_install_targets(
                        targets, _conn, return_unknown=True)
                    errors.update(_pre_errors)
                    unknown.extend(_pre_unknown)
                    _log.info(
                        "ddos-install: after precheck targets=%s errors=%s",
                        targets, list(errors.keys()))
            except Exception as _e:  # noqa: BLE001
                _log.warning("ddos-install: precheck failed: %s", _e)

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
        # errors уже инициализирован выше (после SQL fallback)

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
                _log.info("ddos-install: target=%s known_count=%d", u, len(known))
                try:
                    res = await _exec_one(
                        db_service, dict(row), u,
                        {"DDOS_AGENT_SECRET": secret},
                        admin_id=None, admin_username="plugin:ddos-monitoring")
                    _log.info("ddos-install: target=%s res=%s", u, str(res)[:500])
                    if res.get("status") == "running":
                        installed.append(u)
                    else:
                        errors[u] = str(res.get("error") or "exec_failed")
                        _log.warning("ddos-install: target=%s failed: %s",
                                     u, errors[u])
                except Exception as e:  # noqa: BLE001 — ошибка одной ноды не роняет остальные
                    errors[u] = str(e)[:200]
                    _log.exception("ddos-install: target=%s exception", u)

        result = {"installed": installed, "unknown": unknown, "errors": errors,
                  "agent_version": AGENT_VERSION}
        _log.info("ddos-install: summary installed=%d unknown=%d errors=%d",
                  len(installed), len(unknown), len(errors))
        return result
        if unknown:
            result["error"] = "unknown_nodes"
        return result
