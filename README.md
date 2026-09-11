<div align="center">

# 🛡️ ddos-monitoring

**DDoS-мониторинг для [remnawave-admin](https://github.com/Case211/remnawave-admin)**

[![Plugin API v1](https://img.shields.io/badge/Plugin%20API-v1-blue)](https://github.com/Case211/remnawave-admin)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](#english) | [Русский](#русский)

</div>

---

## Русский

### Что это

Плагин для remnawave-admin (Plugin API v1), который мониторит ноды на DDoS-атаки и системные проблемы. Данные поступают от **ddos-agent** (устанавливается на ноды) через WebSocket-канал панели → `node_metrics_snapshots` → плагин читает и анализирует.

### Архитектура

```
┌─────────────────────────────────────────────────────────┐
│  remnawave-admin panel                                  │
│  ┌─────────────────────────────────────────────────┐    │
│  │ ddos-monitoring plugin                          │    │
│  │  ├─ Poller (каждые 20с)                         │    │
│  │  │   ├─ читает node_metrics_snapshots           │    │
│  │  │   ├─ читает ddos-agent snapshots             │    │
│  │  │   ├─ classify() → attack/stable/load/health  │    │
│  │  │   ├─ baseline: p95×3 за 7 дней               │    │
│  │  │   └─ подтверждения: 2 для атаки, 3 для heal  │    │
│  │  ├─ Routes (FastAPI)                            │    │
│  │  │   ├─ POST /agent/report  — HMAC-приёмник     │    │
│  │  │   ├─ GET  /data          — JSON для UI       │    │
│  │  │   ├─ GET  /details/:uuid — подробности ноды  │    │
│  │  │   └─ POST /agent/nodes   — установка агента  │    │
│  │  ├─ Notify                                      │    │
│  │  │   ├─ Telegram-бот (alerter)                  │    │
│  │  │   └─ Panel (in-app уведомления)              │    │
│  │  └─ Module — JS-виджет в UI панели              │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ ddos-agent (на каждой ноде)                     │    │
│  │  ├─ /proc/net/snmp (TCP SYN_RECV)               │    │
│  │  ├─ /proc/net/dev (rx/tx bytes, drops)          │    │
│  │  ├─ /proc/net/sockstat (mem, orphan, tw)        │    │
│  │  ├─ /proc/sys/net/netfilter/nf_conntrack_*      │    │
│  │  ├─ systemd failed-units                        │    │
│  │  ├─ load average, CPU, RAM, disk, swap          │    │
│  │  └─ per-protocol: TCP/UDP/ICMP bytes + pps      │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Ключевые возможности

| Возможность | Описание |
|---|---|
| **Baseline mode** | Автоматически learns нормальный трафик за 7 дней (p95×3). Пороги адаптируются к реальной нагрузке каждой ноды |
| **Per-protocol thresholds** | TCP/UDP/ICMP — отдельные пороги по Мбит/с и pps (стиль fastnetmon) |
| **SYN-rate detector** | Ловит медленный SYN-флуд по скорости роста `syn_recv/сек`, даже если абсолютное значение мало |
| **TTL closure** | Висящие атаки автоматически закрываются через настраиваемый TTL (по умолчанию выкл) |
| **State restore** | После рестарта панели — восстановление активных атак из БД (без «все зелёные») |
| **VPN-фильтр** | Легальные VPN-клиенты не триггерят атаку (опционально) |
| **Agent install** | Автоматическая установка ddos-agent на ноды через `exec_script` панели |
| **Precheck** | Проверка готовности ноды (agent_token, WebSocket) перед установкой агента |

### Детект атак

**Источник 1: панель** (`node_metrics_snapshots`)

| Порог | Значение по умолчанию | Описание |
|---|---|---|
| `rx_bps` | 200 Мбит/с | Входящий трафик |
| `rx_pps` | 30k pps | Пакеты в секунду |
| `syncookies_ps` | 200/с | SYN cookies |
| `listen_drop_ps` | 100/с | Listen drops |
| `conntrack_ratio` | 75% | Заполненность conntrack |
| `cpu_percent` | 90% | CPU |
| `memory_percent` | 90% | RAM |
| `load_per_cpu` | 2.0 | Load average |
| `disk_percent` | 85% | Диск |

**Источник 2: ddos-agent** (полные метрики)

| Порог | Значение | Описание |
|---|---|---|
| `tcp_mbps` / `udp_mbps` / `icmp_mbps` | 100 Мбит/с | Per-protocol bandwidth |
| `tcp_pps` / `udp_pps` / `icmp_pps` | 100k pps | Per-protocol pps |
| `syn_recv` | 1000 | SYN_RECV в очереди |
| `syn_rate` | 50/сек | Рост SYN_RECV (медленный флуд) |

**Типы атак:** TCP SYN-флуд, conntrack-исчерпание, TCP-флуд (переполнение очереди), пакетный флуд, объёмный флуд, per-protocol (UDP/ICMP flood)

**Severity:** `critical` (3× порога или conntrack ≥95%) → `high` (1.5×) → `medium`

**Lifecycle:** подтверждение 2 тика для атаки, 3 тика для recovery. Cooldown 5 мин между алертами.

### Baseline mode

Вместо статических порогов — автоматическая калибровка по реальному трафику:

1. Каждый час poller пересчитывает **p95** за последние 7 дней
2. Порог = `p95 × expression` (по умолчанию `value * 3`)
3. Минимальные пороги защищают от слишком низких baseline на тихих нодах
4. Включается через `plugin_settings.baseline_enabled = true`

```
Порог = max(p95_за_7_дней × 3, минимальный_порог)
```

### Установка

```bash
# 1. Клонировать в директорию плагинов панели
git clone https://github.com/multi81/ddos-monitoring-remnawave-admin-panel.git \
  /path/to/remnawave-admin/plugins/ddos-monitoring

# 2. Установить зависимости
cd /path/to/remnawave-admin/plugins/ddos-monitoring
pip install -e .

# 3. Перезапустить панель — плагин зарегистрируется автоматически
```

### Настройка

**plugin_settings** (создаются автоматически при первом запуске):

| Ключ | Значение по умолчанию | Описание |
|---|---|---|
| `thresholds` | `{}` | Кастомные пороги (перекрывают defaults) |
| `baseline_enabled` | `false` | Включить baseline mode |
| `exclude_vpn` | `false` | Исключить VPN-клиенты из детекта |
| `alert_cooldown_s` | `300` | Cooldown между алертами (сек) |
| `attack_stale_ttl_s` | `0` | TTL для зависших атак (0 = выкл) |

### ddos-agent

Устанавливается на ноды через панель (POST `/agent/nodes`). Сбор метрик:

- `/proc/net/snmp` — TCP SYN_RECV, established, time-wait
- `/proc/net/dev` — rx/tx bytes, packets, drops
- `/proc/net/sockstat` — mem, orphan, timewait
- `/proc/sys/net/netfilter/` — conntrack count/max
- `systemctl list-units --failed` — упавшие юниты
- `/proc/loadavg`, `/proc/stat`, `/proc/meminfo` — CPU, RAM, load, swap
- Per-protocol: TCP/UDP/ICMP bytes + pps (из `/proc/net/snmp` + XDP)

### Авторизация

| Метод | Описание |
|---|---|
| **HMAC-SHA256** | Агент → панель. Секрет хранится в `plugin_settings` (auto-init). Replay-защита: ±120с по timestamp |
| **RBAC** | Два права: `ddos:view` (атаки и нагрузка), `ddos:view_ips` (IP атакующих) |
| **Agent precheck** | Перед установкой агента: проверка `agent_token` и WebSocket-соединения |

### API Endpoints

| Метод | Путь | Описание | Авторизация |
|---|---|---|---|
| `POST` | `/agent/report` | Приём среза от агента | HMAC |
| `GET` | `/data` | Состояние флота + активные атаки | `ddos:view` |
| `GET` | `/details/:uuid` | Детали по ноде (метрики, атаки, топ IP) | `ddos:view` |
| `GET` | `/summary` | Текстовое саммари (для TG-бота) | `ddos:view` |
| `POST` | `/settings` | Обновить настройки плагина | admin |
| `POST` | `/baseline/recompute` | Принудительный пересчёт baseline | admin |
| `POST` | `/agent/nodes` | Установить агента на ноды | admin |
| `GET` | `/agent/status` | Статус агентов (версия, свежесть) | `ddos:view` |
| `GET` | `/settings` | Текущие настройки | `ddos:view` |
| `GET` | `/events` | Последние события | `ddos:view` |

### Зависимости

```
fastapi
asyncpg
```

### Тесты

```bash
pip install -e ".[test]"
pytest tests/ -v
```

161 тестов покрывают: classify, baseline, poller lifecycle, agent receiver, routes RBAC, notify, schema, agent install precheck, SYN-rate, offline attack close, per-protocol thresholds, state restore, name fallback race, CPU% baseline.

### Статус

**v0.7.48** — production-ready. Активно используется.

---

## English

### What

A plugin for [remnawave-admin](https://github.com/Case211/remnawave-admin) (Plugin API v1) that monitors nodes for DDoS attacks and system health issues. Data comes from **ddos-agent** installed on each node via the panel's WebSocket channel.

### Key Features

- **Baseline mode** — auto-calibrates thresholds from 7-day p95 traffic patterns
- **Per-protocol thresholds** — TCP/UDP/ICMP separate thresholds (fastnetmon-style)
- **SYN-rate detector** — catches slow SYN floods by growth rate
- **TTL closure** — auto-close stale attacks after configurable TTL
- **State restore** — survives panel restarts without losing active attacks
- **VPN filtering** — legal VPN clients excluded from attack detection
- **Agent auto-install** — deploy ddos-agent to nodes via panel's `exec_script`
- **Precheck** — verifies node readiness (agent_token, WebSocket) before install

### Quick Start

```bash
git clone https://github.com/multi81/ddos-monitoring-remnawave-admin-panel.git \
  /path/to/remnawave-admin/plugins/ddos-monitoring
cd /path/to/remnawave-admin/plugins/ddos-monitoring
pip install -e .
# Restart panel — plugin registers automatically
```

### Tests

```bash
pip install -e ".[test]"
pytest tests/ -v  # 161 tests
```

### Status

**v0.7.48** — production-ready. Actively maintained.
