<div align="center">

# 🛡️ ddos-monitoring

**Реалтайм-детекция DDoS для VPN-инфраструктуры**

[![Plugin API v1](https://img.shields.io/badge/Plugin_API-v1-blue?style=for-the-badge)](https://github.com/Case211/remnawave-admin)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-175-00C853?style=for-the-badge)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

Адаптивные пороги · Telegram-алерты · Встроенный дашборд · Автодеплой агентов

</div>

---

## Как работает

```
┌──────────┐    WebSocket     ┌──────────┐     SQLite     ┌──────────┐
│  Агент   │ ───────────────▶ │  Панель  │ ◀──────────── │ Dashboard│
│ (нода)   │  каждые 20 сек   │ (poller) │                │   (UI)   │
└──────────┘                  └────┬─────┘                └──────────┘
                                   │
                          ┌────────┼────────┐
                          ▼        ▼        ▼
                     Пороги   Атака    Telegram
```

Агент на каждой ноде собирает метрики → панель сравнивает с порогами → при превышении открывает атаку и шлёт алерт.

---

## Метрики

| Что | Метрики | Зачем |
|-----|---------|-------|
| 🌐 Трафик | `rx_bps` · `tx_bps` · `rx_pps` | Объём и пакеты |
| 🔌 TCP | `syn_recv` · `established` · `syncookies_ps` | SYN-flood |
| 💧 Дропы | `listen_drop_ps` · `rx_drop_ps` | Overflow / NIC |
| 📊 Conntrack | `conntrack_count` · `conntrack_max` | Таблица соединений |
| ⚙️ Ресурсы | `cpu_pct` · `ram_pct` · `disk_pct` · `load1` | Загрузка ноды |

---

## Пороги

### Статические

| Метрика | Порог | | Метрика | Порог |
|---------|-------|-|---------|-------|
| `rx_bps` | 200 Мбит/с | | `cpu` | 90% |
| `rx_pps` | 30K | | `ram` | 90% |
| `syncookies` | 200/с | | `disk` | 85% |
| `listen_drop` | 100/с | | `load/cpu` | 2.0 |
| `rx_drop` | 50/с | | `conntrack` | 75% |

### Baseline (адаптивные)

Включается через `baseline_mode=true`. Каждый час пересчёт p95 за 7 дней:

| Метрика | Формула | Минимум |
|---------|---------|---------|
| `rx_bps` | p95 × 3 | ≥ 20 Мбит/с |
| `rx_pps` | p95 × 2 | ≥ 5 000 |
| `syncookies` | p95 + 5 | ≥ 10 |
| `drops` | p95 + 5 | ≥ 5 |

**Итого**: `max(static, baseline, min)` — каждая нода адаптируется к себе.

---

## Lifecycle атаки

```
  МЕТРИКА > ПОРОГ
        │
        ▼
  ┌─ Нет активной атаки? ──────────────────────────┐
  │  • Запись в attacks (started_at, severity)      │
  │  • Telegram: 🔴 АТАКА НА <нода>                 │
  └─────────────────────────────────────────────────┘
        │
        ▼  (метрика всё ещё выше)
  ┌─ Атака активна ─────────────────────────────────┐
  │  • Обновление last_seen, severity, attack_type   │
  └─────────────────────────────────────────────────┘
        │
        ▼  (метрика ниже порога)
  ┌─ Завершение ────────────────────────────────────┐
  │  • ended_at = NOW()                              │
  │  • Telegram: 🟢 ЗАВЕРШЕНА (длительность)         │
  └─────────────────────────────────────────────────┘
```

---

## Severity

| Уровень | Когда |
|---------|-------|
| 🔴 **CRITICAL** | `syncookies > 2× порога` или `rx_bps > 5× порога` |
| 🟡 **WARNING** | Превышение порога (не critical) |
| 🔵 **LOW** | Незначительное превышение |

---

## Telegram-алерты

| Событие | Формат |
|---------|--------|
| Начало | `🔴 АТАКА НА <нода>` — тип, severity, метрики, время |
| Конец | `🟢 ЗАВЕРШЕНА: <нода>` — длительность, пик |
| Нода молчит | `⚪ Атака закрыта — нода не отвечает` |

---

## Dashboard

| Элемент | Что показывает |
|---------|---------------|
| **KPI-карточки** | Всего нод · Online · Атаки · Max severity |
| **Гистограмма** | Атаки за 24ч по часам |
| **Карточки нод** | CPU/RAM bars · sparkline 8ч · severity pill · сортировка ▲▼ |
| **Таблица атак** | Нода · начало · конец · тип · severity · длительность |
| **Статус** | TG-бот · Agent |

---

## API

```
GET  /data                      ← Fleet overview (ноды + KPI + attacks)
GET  /details                   ← Детали ноды
GET  /history?node_uuid=...&range=1h  ← Sparkline
POST /nodes/order               ← Сортировка
GET  /tg                        ← Telegram-бот статус
GET  /agent                     ← Agent статус
GET  /health                    ← Liveness
```

---

## Настройки

| Параметр | По умолчанию | Описание |
|----------|:---:|---------|
| `baseline_mode` | `off` | Адаптивные пороги (p95 × коэффициент) |
| `baseline_p95` | `0.95` | Перцентиль |
| `baseline_window_days` | `7` | Окно истории |
| `attack_stale_ttl_s` | `0` | Авто-закрытие при offline (0 = выкл) |
| Per-node thresholds | — | Пороги на конкретную ноду |

---

## Быстрый старт

```bash
# Установка плагина
cd /path/to/remnawave-admin
npm run plugins:install -- https://github.com/multi81/ddos-monitoring-remnawave-admin-panel
npm run plugins:build && systemctl restart remnawave-admin
```

**Агент на ноды** — через UI (кнопка *Install agent*) или вручную:

```bash
curl -fsSL https://raw.githubusercontent.com/multi81/ddos-monitoring-remnawave-admin-panel/main/ddos_monitoring/agent/install.sh | \
  bash -s -- --url wss://your-panel.example.com --token <node-token>
```

---

## Тесты

```bash
python -m pytest tests/ -v              # Все 175 тестов
python -m pytest tests/ -v -k "not remote"  # Без SSH
```

---

## Стек

| Слой | Технологии |
|------|-----------|
| Backend | Python 3.11+ · aiohttp · aiosqlite · paramiko |
| Agent | psutil · websockets |
| Storage | SQLite (WAL, миграции) |
| UI | Vanilla JS · lit-html |
| Alerts | Telegram Bot API |

---

<div align="center">

[Issues](https://github.com/multi81/ddos-monitoring-remnawave-admin-panel/issues) · [Remnawave Admin](https://github.com/Case211/remnawave-admin)

</div>
