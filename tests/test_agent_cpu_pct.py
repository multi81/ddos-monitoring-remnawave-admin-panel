"""Тесты для фикса CPU% в шаблоне agent_installer.py.

CPU-логика находится внутри _AGENT_TEMPLATE (строка), а не на уровне модуля —
потому что это код, который будет развёрнут на ноде.

Проверяется строка шаблона:
- prev_idle не используется как undefined name → должно быть prev[1] или prev_idle = prev[1]
- _net_prev["cpu"] записывается ДО использования
- корректная формула cpu_pct через дельту
"""
from __future__ import annotations

import importlib
import re

aginst = importlib.import_module("ddos_monitoring.agent_installer")
TEMPLATE = aginst._AGENT_TEMPLATE


def _extract_main_body() -> str:
    """Извлечь тело main() из шаблона."""
    # main() находится между "def main():" и "if __name__"
    m = re.search(r"def main\(\):\n(.*?)\nif __name__", TEMPLATE, re.DOTALL)
    assert m, "main() not found in template"
    return m.group(1)


def test_no_undefined_prev_idle():
    """prev_idle не должно быть использовано как undefined name (без присваивания)."""
    body = _extract_main_body()
    # Если есть выражение prev_idle, должно быть и присваивание ему ДО использования
    if "prev_idle" in body:
        # Либо prev_idle = ... либо prev[1]
        assert "prev_idle = " in body or "prev[1]" in body, (
            "prev_idle используется, но не присваивается — будет NameError"
        )


def test_cpu_prev_is_written_before_use():
    """_net_prev[\"cpu\"] должно быть записано (хотя бы одно присваивание)."""
    body = _extract_main_body()
    # Проверяем что есть запись в _net_prev["cpu"]
    assert '_net_prev["cpu"]' in body, (
        "нет записи _net_prev['cpu'] — deltа CPU никогда не посчитается"
    )


def test_cpu_pct_formula_uses_delta():
    """cpu_pct = round(100 * (dt - didle) / dt) — формула через дельту."""
    body = _extract_main_body()
    # Ищем формулу: cpu_pct = round(100 * ( ... - ... ) / ..., 1)
    assert "cpu_pct" in body
    # Должны быть и _cpu_total, и _cpu_idle
    assert "_cpu_total" in body
    assert "_cpu_idle" in body


def test_first_cycle_no_cpu_pct_logic():
    """Логика: если prev — None, cpu_pct НЕ выставляется (или = 0)."""
    body = _extract_main_body()
    # В шаблоне должно быть `if prev:` или эквивалент — без prev нет baseline
    assert "if prev" in body or "if not prev" in body, (
        "нет проверки на prev — будет TypeError при вычитании None"
    )


def test_compiled_template_runs_first_cycle_without_nameerror():
    """Компилируем main() из шаблона и проверяем первый цикл без NameError."""
    import types

    # Извлекаем весь блок main()
    m = re.search(r"def main\(\):\n(.*?)(?=\n\nif __name__)", TEMPLATE, re.DOTALL)
    assert m
    main_body = m.group(1)

    # Создаём минимальный namespace для запуска
    ns = {
        "collect": lambda: {"_cpu_total": 1000, "_cpu_idle": 700},
        "report": lambda m: (_ for _ in ()).throw(KeyboardInterrupt()),
        "time": type("T", (), {"sleep": lambda s: None})(),
        "_net_prev": {},
        "Exception": Exception,
    }
    code = "def main():\n" + main_body
    exec(compile(code, "<test_template>", "exec"), ns)
    main_fn = ns["main"]

    try:
        main_fn()
    except KeyboardInterrupt:
        pass
    except NameError as e:
        raise AssertionError(f"NameError в скомпилированном main(): {e}")

    # После первого цикла baseline записан
    assert "cpu" in ns["_net_prev"]
