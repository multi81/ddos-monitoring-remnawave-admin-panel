<div align="center">

# 🛡️ ddos-monitoring

**DDoS-мониторинг для [remnawave-admin](https://github.com/Case211/remnawave-admin)**

[![Plugin API v1](https://img.shields.io/badge/Plugin%20API-v1-blue)]()
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Tests](https://img.shields.io/badge/tests-123%20passed-brightgreen)]()

Телеметрия нод → детект атак → история → TG-алерты.
Полностью встроенный плагин: **без SSH, без внешних зависимостей, без отдельного сервера мониторинга.**

</div>

---

## Что это

Плагин для панели remnawave-admin, который превращает её в полноценный DDoS-монитор:

- **Агент на каждой ноде** — лёгкий Python-скрипт без зависимостей, собирает метрики из `/proc` и отправляет в панель
- **Poller в панели** — читает телеметрию из БД, детектит атаки по порогам с подтверждениями
- **Встроенный UI** — дашборд прямо в админке: ноды, атаки, расшифровка вердиктов
- **Telegram-бот** — алерты с детализацией: тип атаки, severity, метрики, топ IP
- **Автоустановка** — агент ставится на ноды через `exec_script` канала панели, одним кликом

## Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    remnawave-admin                       │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌───────────────────┐  │
│  │  Poller   │───▶│ Classify │───▶│ notify / tg_bot   │  │
│  │ (тик 20с) │    │ (пороги) │    │ (TG / panel_push) │  │
│  └────┬─────┘    └──────────┘    └───────────────────┘  │
│       │                                                  │
│       ▼                                                  │
│  ┌──────────────────────┐    ┌─────────────────────┐    │
│  │ PostgreSQL (панель)   │    │   Plugin API v1      │    │
│  │                       │    │                      │    │
│  │ node_metrics_snapshots│    │ /data  /attacks      │    │
│  │ ddos_monitoring_*     │    │ /details /settings   │    │
│  └──────────────────────┘    │ /agent/report        │    │
│                               └──────────┬───────────┘    │
│                                          │                │
└──────────────────────────────────────────┼────────────────┘
                                           │
                    ┌──────────────────────┼──────────┐
                    │  ddos-agent (нода)    │          │
                    │                       │          │
                    │  /proc → collect() ───┘          │
                    │  HMAC-SHA256                      │
                    │  systemd service                  │
                    └──────────────────────────────────┘
```

## Компоненты

| Модуль | Строк | Назначение |
|---|---|---|
| `__init__.py` | 83 | Точка входа плагина: манифест, scheduled tasks, PluginParts |
| `poller.py` | 975 | Poller: чтение телеметрии из БД, классификация атак, lifecycle атак |
| `data.py` | 472 | Схема БД (DDL, идемпотентный), запросы: ноды, атаки, события, топ IP |
| `routes.py` | 161 | FastAPI-роуты: `/data`, `/attacks`, `/details`, `/settings`, `/agent/report` |
| `agent_receiver.py` | 191 | Приёмник срезов агента: HMAC-валидация, replay-защита, запись в БД |
| `agent_routes.py` | 164 | Роуты управления агентами: установка, статус, UI-секция |
| `agent_installer.py` | 326 | Сборка bash-скрипта установки агента (systemd unit + python-файл) |
| `notify.py` | 262 | Алёртинг: форматирование сообщений, отправка через TG-бот или panel_notify |
| `tg_bot.py` | 92 | Telegram Bot API: sendMessage, fallback на panel_notify панели |
| `module.py` | 513 | UI-модуль: JS для админки (window.rwaPluginUI), таблица нод и атак |
| `page.py` | 51 | Standalone HTML для панелей < 4.5.4 (без generic-маршрута) |
| `secret.py` | 68 | Lifecycle HMAC-секрета: генерация, миграция, per-context lock |

## ddos-agent

Лёгкий сборщик метрик на ноде. **Ноль зависимостей** — только stdlib Python.

**Собирает:**
- CPU (дельта `/proc/stat`), RAM, Swap, диск
- Сетевая статистика: RX/TX bps/pps, дропы (дельта `/proc/net/dev`)
- TCP-соединения: SYN_RECV, ESTABLISHED, per-IP (парсинг `/proc/net/tcp[6]`)
- conntrack (count/max)
- Упавшие systemd-юниты

**Отправляет:**
- POST на панель: `/api/v2/plugins/ddos-monitoring/agent/report`
- HMAC-SHA256 подпись: `HMAC(secret, "{node_uuid}|{ts}|{metrics_json}")`
- Интервал: настраивается (по умолчанию 15 сек)

**Безопасность:**
- Секрет хранится в `/etc/ddos-monitoring/agent-secret` (chmod 600)
- Replay-защита: окно свежести 120 сек
- Per-node секреты (генерируются при установке)

## Детект атак

Классификатор (`poller.py::classify`) анализирует каждый срез метрик:

### Пороги (по умолчанию)

| Метрика | Порог | Описание |
|---|---|---|
| `rx_bps` | 500 Мбит/с | Входящий трафик |
| `rx_pps` | 100 000 пак/с | Входящие пакеты |
| `syncookies_ps` | 1 000 | SYN cookies в секунду |
| `listen_drop_ps` | 500 | Дропы очереди listen |
| `conntrack_ratio` | 75% | Заполненность conntrack |
| `cpu_percent` | 95% | CPU |
| `memory_percent` | 95% | RAM |
| `load_per_cpu` | 3.0 | Load Average на ядро |
| `disk_percent` | 90% | Диск |

### Типы атак

| Тип | Детект |
|---|---|
| TCP SYN-флуд | syncookies ≥ 50% порога и ≥ listen_drop |
| conntrack-исчерпание | conntrack_ratio ≥ 90% |
| TCP-флуд (переполнение очереди) | listen_drop ≥ порога |
| Пакетный флуд | rx_pps превышает порог |
| Объёмный флуд | rx_bps превышает порог |

### Severity

| Уровень | Условие |
|---|---|
| **critical** | peak_ratio ≥ 3.0 или conntrack ≥ 95% |
| **high** | peak_ratio ≥ 1.5 |
| **medium** | все остальные |

### Lifecycle

```
Норма → [2 подтверждения] → АТАКА → [3 подтверждения] → Норма
                              │
                              ├── load (CPU/RAM/disk)
                              ├── health (ошибки сети)
                              └── offline (нет данных > 120с)
```

## UI

Встроенный дашборд в админке панели:

- **Таблица нод** — имя, версия агента, статус, активная атака, тип
- **Последние атаки** — нода, начало, конец, тип, severity
- **Расшифровка по нодам** — вердикт (атака/стабильно/нагрузка/нет связи), метрики среза, топ IP
- **Кнопка «Обновить»** — ручной рефреш без ожидания poller
- **Настройки** — пороги, TG-бот (токен + chat_id), base URL для агента

Поддержка тем: тёмная и светлая (CSS-переменные панели).

## Telegram-алерты

Сообщения с эмодзи-статусами, московским временем, метриками:

```
🚨 DDoS-атака обнаружена
──────────────────────
🖥 Нода: fr1
📡 Источник: ddos-agent
⏰ 11.09.2026 14:32:15 МСК
🔴 КРИТИЧЕСКИЙ

Тип: TCP SYN-флуд
Причины: SYN cookies, listen drop
🎯 Target: node

📥 RX: 850.0 Мбит/с · 125 000 пак/с
📤 TX: 45.2 Мбит/с · 3 200 пак/с
🔗 Соединения: SYN_RECV: 12450 · EST: 890
👥 Уникальные IP: 3 · 192.168.1.1 (5000) [vpn], 10.0.0.1 (3200)
```

**Два режима:**
1. **Свой бот** — токен и chat_id в настройках плагина, отправка через Bot API
2. **Fallback** — через `panel_notify` панели (если бот не настроен)

## Установка

```bash
# Собрать wheel
python -m build --wheel

# Положить в директорию плагинов панели
cp dist/ddos_monitoring-*.whl /app/plugins/

# Перезапустить панель
systemctl restart remnawave-admin
```

Агент на ноды ставится из UI панели (кнопка «Установить агент») через `exec_script` канала нод.

### Настройка

В админке панели → Настройки плагина:

| Ключ | Описание | По умолчанию |
|---|---|---|
| `thresholds` | JSON с порогами (см. таблицу выше) | встроенные |
| `tg_bot_token` | Токен Telegram-бота | — |
| `tg_chat_ids` | Chat ID через запятую | — |
| `agent_report_base_url` | URL панели для агентов (auto-detect если пусто) | — |

## Права (RBAC)

| Ресурс | Permission | Описание |
|---|---|---|
| `ddos` | `view` | Дашборд: атаки, нагрузка, ноды |
| `ddos` | `view_ips` | IP атакующих (приватные данные) |
| `ddos` | `manage` | Установка/переустановка агента на нодах |

## Тесты

123 теста, самодостаточные (фейковый ctx/db, реальная БД не нужна):

```bash
python -m venv .venv && .venv/bin/pip install pytest pytest-asyncio fastapi build
.venv/bin/python -m pytest tests/ -q
```

**Покрытие:**
- Классификация атак (все типы + edge cases)
- Poller: lifecycle атак, подтверждения, recovery, stale
- Agent receiver: HMAC, replay-защита, bad payloads
- Routes: RBAC, data/attacks/details endpoints
- Telegram: отправка, форматирование, fallback
- Схема: идемпотентный DDL, миграции
- Интеграционные: полный цикл атака→алерт→recovery

## Статус

- ✅ **Фаза 1** — скелет, poller (tick-lock, backoff), идемпотентная схема, routes с RBAC, UI-модуль
- ✅ **Фаза 2** — TG-алерты, агент (сборка/установка/статус), классификация (все типы атак), lifecycle атак с подтверждениями
- ⏳ **Фаза 3** — SVG-схема флота, расширенная аналитика

## Известные ограничения

- **Multi-worker:** состояние poller'а в памяти. При >1 uvicorn worker — дубли в БД. Решение: UNIQUE-констрейнт «одна открытая атака на ноду» + лидер-выбор (фаза 2+).
- **Рестарт mid-attack:** открытые атаки закрываются по таймауту на следующем тике.

## Зависимости

- Python ≥ 3.11
- `aiohttp` ≥ 3.9 (для Telegram Bot API)
- remnawave-admin ≥ 4.5.4 (Plugin API v1, полный UI)

## Лицензия

MIT
