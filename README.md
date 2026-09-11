<div align="center">

# 🛡️ ddos-monitoring

**DDoS-мониторинг для [remnawave-admin](https://github.com/Case211/remnawave-admin)**

[![Plugin API v1](https://img.shields.io/badge/Plugin%20API-v1-blue)](https://github.com/Case211/remnawave-admin)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-green.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-161-brightgreen)](#тестирование)

Реалтайм-детекция DDoS на флот VPN-нод. Адаптивные пороги, Telegram-алерты, встроенный дашборд.

</div>

---

## Архитектура

```
Нода (agent) ──WebSocket──▶ Панель (poller) ──▶ SQLite
                              │
                              ├─ threshold check → attack start/end
                              ├─ Telegram alert
                              └─ UI dashboard
```

**Agent** — на каждой ноде, шлёт метрики каждые 20 сек. **Poller** — ядро, сравнивает с порогами, управляет атаками. **Dashboard** — веб-UI с KPI и sparkline.

---

## Метрики

| Категория | Что собирает |
|-----------|-------------|
| Трафик | `rx_bps`, `tx_bps` — байт/сек |
| Пакеты | `rx_pps` — пакетов/сек |
| TCP | `syn_recv`, `established` — соединения |
| Дропы | `syncookies_ps`, `listen_drop_ps`, `rx_drop_ps` |
| Conntrack | `conntrack_count`, `conntrack_max` |
| Ресурсы | `cpu_pct`, `ram_pct`, `swap_pct`, `disk_pct`, `load1` |

---

## Пороги

**Статические** (по умолчанию): `rx_bps` 200M, `rx_pps` 30K, `syncookies` 200, `listen_drop` 100, `rx_drop` 50, CPU/RAM 90%, disk 85%, conntrack 75%, load/cpu 2.0.

**Baseline** (`baseline_mode=true`): каждый час — p95 за 7 дней × коэффициент. Нода адаптируется к своему трафику. Min floor: rx_bps ≥ 20M, rx_pps ≥ 5K.

**Per-node**: индивидуальные пороги через настройки плагина.

Итоговый порог = `max(static, baseline, min_floor)`.

---

## Lifecycle атаки

```
METRIC > THRESHOLD
  → Нет активной атаки? INSERT, severity, Telegram "🔴 АТАКА"
  → Атака есть? Обновить last_seen, severity, type
METRIC < THRESHOLD
  → ended_at, Telegram "🟢 ЗАВЕРШЕНА (длительность)"
Nода не отвечает > stale_ttl
  → Все атаки закрыты, Telegram "⚪ Нода не отвечает"
```

**Severity**: 🔴 CRITICAL (syncookies > 2× или rx_bps > 5×), 🟡 WARNING (> порога), 🔵 LOW.

---

## Telegram-алерты

```
🔴 АТАКА НА <node>
Тип: SYN-flood | Severity: CRITICAL
Метрики: syncookies=1500 (порог=200)

🟢 ЗАВЕРШЕНА: <node> | Длительность: 5m 32s
```

---

## API

| Endpoint | Описание |
|----------|----------|
| `GET /data` | Fleet overview — ноды + KPI + attacks |
| `GET /details` | Детали ноды |
| `GET /history?node_uuid=...&range=1h` | Sparkline |
| `POST /nodes/order` | Сортировка |
| `GET /health` | Liveness |

---

## Быстрый старт

```bash
# Установка плагина
cd /path/to/remnawave-admin
npm run plugins:install -- https://github.com/multi81/ddos-monitoring-remnawave-admin-panel
npm run plugins:build && systemctl restart remnawave-admin

# Агент на ноду (через UI или вручную)
curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash -s -- --url wss://panel --token <token>
```

---

## Тестирование

```bash
python -m pytest tests/ -v          # 161 тестов
python -m pytest tests/ -v -k "not remote"  # без SSH
```

---

## Стек

Python 3.11+ · aiohttp · aiosqlite · psutil · websockets · Telegram Bot API · Vanilla JS (lit-html)
