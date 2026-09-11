<div align="center">

# 🛡️ ddos-monitoring

**DDoS-мониторинг для [remnawave-admin](https://github.com/Case211/remnawave-admin)**

[![Plugin API v1](https://img.shields.io/badge/Plugin%20API-v1-blue)](https://github.com/Case211/remnawave-admin)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-green.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-161-brightgreen)](#тестирование)

Реалтайм-детекция DDoS-атак на флот VPN-нод с адаптивными порогами, Telegram-алертами и встроенным дашбордом.

</div>

---

## Архитектура

```
Нода (agent) ──WebSocket──▶ Панель (poller) ──▶ PostgreSQL
                              │
                              ├─ threshold check → attack start/end
                              ├─ Telegram alert
                              └─ UI dashboard
```

**Agent** — скрипт на каждой ноде, собирает метрики каждые 20 сек и отправляет на панель через WebSocket.

**Poller** — ядро панели. Получает снапшоты, сравнивает с порогами, открывает/закрывает атаки, шлёт алерты.

**Dashboard** — веб-интерфейс с KPI, гистограммами, sparkline и таблицей атак.

---

## Метрики

Агент отправляет снапшот каждые 20 сек:

| Категория | Метрики |
|-----------|---------|
| **Трафик** | `rx_bps`, `tx_bps` — байт/сек входящий/исходящий |
| **Пакеты** | `rx_pps` — пакетов/сек |
| **Соединения** | `syn_recv`, `established` — TCP-состояния |
| **Дропы** | `syncookies_ps`, `listen_drop_ps`, `rx_drop_ps` — счётчики |
| **Conntrack** | `conntrack_count`, `conntrack_max` — таблица соединений |
| **Ресурсы** | `cpu_pct`, `ram_pct`, `swap_pct`, `disk_pct`, `load1`, `cores` |

Панель сохраняет снапшоты в `ddos_monitoring_agent_snapshots` (один INSERT на ноду за тик).

---

## Пороги

### Статические (по умолчанию)

| Метрика | Порог | Описание |
|---------|-------|----------|
| `rx_bps` | 200 Мбит/с | Объёмный входящий трафик |
| `rx_pps` | 30,000 | Пакетов в секунду |
| `syncookies_ps` | 200 | SYN-cookie активация (SYN-flood) |
| `listen_drop_ps` | 100 | TCP listen queue overflow |
| `rx_drop_ps` | 50 | NIC дропы |
| `cpu_percent` | 90% | Загрузка CPU |
| `memory_percent` | 90% | Загрузка RAM |
| `load_per_cpu` | 2.0 | Средняя нагрузка на ядро |
| `disk_percent` | 85% | Загрузка диска |
| `conntrack_ratio` | 75% | Заполненность conntrack |

### Baseline (адаптивные)

Включаются через `baseline_mode=true`. Каждый час poller пересчитывает пороги на основе 7-дневной истории:

| Метрика | Формула | Min floor |
|---------|---------|-----------|
| `rx_bps` | p95 × 3 | ≥ 20 Мбит/с |
| `rx_pps` | p95 × 2 | ≥ 5,000 |
| `syncookies_ps` | p95 + 5 | ≥ 10 |
| `listen_drop_ps` | p95 + 5 | ≥ 5 |
| `rx_drop_ps` | p95 + 5 | ≥ 5 |

**Итоговый порог** = `max(static, baseline, min_floor)` — берётся наибольший.

Каждая нода адаптируется к **своему** трафику.

### Per-node

Индивидуальные пороги на конкретную ноду через `plugin_settings`.

---

## Детекция

Каждый тик (20 сек) для каждой ноды:

1. **Собрать** текущие метрики от agent'а
2. **Вычислить** effective thresholds (static + baseline)
3. **Проверить** каждую метрику против порога:
   - `syncookies_ps > threshold` → **SYN-flood**
   - `rx_bps > threshold` → **объёмная атака**
   - `rx_pps > threshold` → **packet flood**
   - `listen_drop_ps > threshold` → **TCP overflow**
   - `rx_drop_ps > threshold` → **NIC drops**
   - `cpu/ram/disk/load/conntrack` → **ресурсные**
4. Если **хотя бы одна** метрика превышена → **ATTACK**

---

## Lifecycle атаки

```
METRIC > THRESHOLD
    │
    ▼
┌─────────────────────────────────────────────────┐
│ Нет активной атаки для этой ноды?              │
│   → INSERT в ddos_monitoring_attacks           │
│   → started_at = NOW()                         │
│   → severity = CRITICAL / WARNING / LOW        │
│   → Telegram: "🔴 АТАКА НА ..."                │
└─────────────────────────────────────────────────┘
    │
    ▼  (каждый тик: метрика всё ещё выше порога)
┌─────────────────────────────────────────────────┐
│ Атака активна                                   │
│   → Обновить last_seen_at                       │
│   → Обновить severity (максимальная метрика)    │
│   → Обновить attack_type                        │
└─────────────────────────────────────────────────┘
    │
    ▼  (метрика упала ниже порога)
┌─────────────────────────────────────────────────┐
│   → ended_at = NOW()                            │
│   → Telegram: "🟢 АТАКА ЗАВЕРШЕНА (длительность)"│
└─────────────────────────────────────────────────┘
```

### Stale attack cleanup

Если нода не отвечает > `attack_stale_ttl_s` (по умолчанию 0 = выкл):

- Все активные атаки этой ноды закрываются (`ended_at = NOW()`)
- Telegram: *"⚪ Атака закрыта — нода не отвечает"*

---

## Severity

| Уровень | Критерий |
|---------|----------|
| 🔴 **CRITICAL** | `syncookies > 2× порога` ИЛИ `rx_bps > 5× порога` |
| 🟡 **WARNING** | Метрика > порога, но не critical |
| 🔵 **LOW** | Незначительное превышение |

---

## Telegram-алерты

**Начало атаки:**
```
🔴 АТАКА НА <node_name>
Тип: SYN-flood / Volume / TCP-overflow
Severity: CRITICAL
Метрики: syncookies=1500 (порог=200), rx_bps=850M (порог=200M)
Время: 2026-09-11 16:30:00 UTC
```

**Конец атаки:**
```
🟢 АТАКА ЗАВЕРШЕНА: <node_name>
Длительность: 5m 32s
Пик: syncookies=1500, rx_bps=850M
```

**Нода не отвечает:**
```
⚪ Атака закрыта — нода не отвечает: <node_name>
```

---

## UI Dashboard

- **KPI**: всего нод, online, атаки, severity
- **Гистограмма**: атаки за 24ч по часам
- **Карточки нод**: CPU/RAM bars, sparkline 8ч, severity pill, сортировка ▲▼
- **Таблица атак**: нода, начало, конец, тип, severity, длительность
- **Секции**: TG-бот статус, Agent статус

---

## API

| Endpoint | Описание |
|----------|----------|
| `GET /data` | Fleet overview — все ноды + KPI + attacks |
| `GET /details` | Детали конкретной ноды |
| `GET /history?node_uuid=...&range=1h` | Drill-down sparkline |
| `POST /nodes/order` | Сортировка нод |
| `GET /tg` | Telegram-бот статус |
| `GET /agent` | Agent статус |
| `GET /health` | Liveness check |

---

## Настройки

| Параметр | Default | Описание |
|----------|---------|----------|
| `baseline_mode` | `false` | Адаптивные пороги (p95 за 7 дней) |
| `baseline_p95` | `0.95` | Перцентиль для baseline |
| `baseline_window_days` | `7` | Окно истории baseline |
| `attack_stale_ttl_s` | `0` | Авто-закрытие атак при offline ноды (0 = выкл) |
| Per-node thresholds | — | Индивидуальные пороги на ноду |

---

## Быстрый старт

### 1. Установка плагина

```bash
cd /path/to/remnawave-admin
npm run plugins:install -- https://github.com/multi81/ddos-monitoring-remnawave-admin-panel
npm run plugins:build
systemctl restart remnawave-admin
```

### 2. Установка агента на ноды

Панель → DDoS Monitoring → **Install agent** — автоматический деплой через SSH.

Или вручную:
```bash
curl -fsSL https://raw.githubusercontent.com/multi81/ddos-monitoring-remnawave-admin-panel/main/ddos_monitoring/agent/install.sh | bash -s -- \
  --url wss://your-panel.example.com \
  --token <node-agent-token>
```

### 3. Настройка

1. Откройте панель → DDoS Monitoring
2. Нажмите **Settings** → включите нужные пороги
3. Рекомендуется включить `baseline_mode` для адаптивных порогов

---

## Тестирование

```bash
# Все тесты
python -m pytest tests/ -v

# Только unit
python -m pytest tests/test_poller_*.py tests/test_module.py -v

# Без network/SSH
python -m pytest tests/ -v -k "not remote"
```

**161 тестов** — poller, thresholds, baseline, attacks, agent install, module, notify, schema, race conditions.

---

## Стек

- **Backend**: Python 3.11+, aiohttp, aiosqlite, paramiko
- **Agent**: Python 3.11+, psutil, websockets
- **Storage**: SQLite (WAL mode, migrations)
- **UI**: aiohttp + Vanilla JS (lit-html)
- **Alerts**: Telegram Bot API

---

<div align="center">

**[Plugin API](https://github.com/Case211/remnawave-admin)** · **[Issues](https://github.com/multi81/ddos-monitoring-remnawave-admin-panel/issues)**

</div>
