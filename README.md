# ddos-monitoring

DDoS-мониторинг для [remnawave-admin](https://github.com/Case211/remnawave-admin) как плагин
(Plugin API v1). Перенос логики ddos-monitoring-monitor: телеметрия нод → детект атак → история.

## Источник данных

Телеметрия node-agent'ов, которую панель складывает в `node_metrics_snapshots`
(net_rx_bps/net_rx_pps/conntrack_*/tcp_syncookies_ps — агент 1.3.0+).
SSH и ключи старого монитора **не используются**.

## Установка

Собрать wheel и положить в `RWA_PLUGINS_DIR` (по умолчанию `/app/plugins`), перезапустить панель:

```bash
python -m build --wheel
cp dist/ddos_monitoring-*.whl /app/plugins/
```

## Права (RBAC)

- `ddos:view` — атаки и нагрузка (дашборд)
- `ddos:view_ips` — IP атакующих (фаза 2; в фазе 1 не выдаётся нигде)

## Тесты

```bash
python -m venv .venv && .venv/bin/pip install pytest pytest-asyncio fastapi build
.venv/bin/python -m pytest tests/ -q
```

Тесты самодостаточны (фейковый ctx/db), реальная БД и панель не нужны.

## Статус

- Фаза 1 ✅ — скелет, poller (tick-lock, backoff, сохранение среза при сбое),
  идемпотентная схема (`ddos_monitoring_*`, версия в plugin_settings), routes с RBAC,
  UI-модуль (window.rwaPluginUI).
- Фаза 2 ⏳ — TG-алерты из воркера с буферизацией, страйки/карантин.
- Фаза 3 ⏳ — SVG-схема флота.

## Известные ограничения

- **Multi-worker:** состояние poller'а живёт в памяти процесса. При запуске панели с
  >1 uvicorn worker'ом каждый воркер детектит атаки независимо и пишет дубли в БД.
  Для фазы 1 принято (как у образца live-flow); в фазе 2 — UNIQUE-констрейнт
  «одна открытая атака на ноду» + лидер-выбор/лок.
- **Рестарт mid-attack:** открытые атаки остаются без close до следующего тика;
  закрытие по таймауту добавим в фазе 2.
