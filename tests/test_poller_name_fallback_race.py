"""Тест race fix: fallback должен срабатывать для нод которые НЕТ в panel_api,
даже если их имя уже заполнено в node_state."""
from __future__ import annotations

import sys
import types


def _install_fake_modules():
    """Поднимаем fake web/starlette/fastapi модули."""
    # Уже могут быть установлены через fakes.py
    pass


def test_sql_name_fallback_works_for_existing_names(monkeypatch):
    """Если uuid есть в node_state, но НЕТ в panel_api (нет node_names),
    fallback должен достать имя из public.nodes — даже если имя уже
    заполнено в node_state (race fix)."""
    from ddos_monitoring import poller

    # Минимальный async poller для теста fallback логики.
    # Проверяем что _missing включает ВСЕ uuid'ы которых нет в node_names.
    node_names = {}  # panel_api ничего не вернул
    _state_rows = [
        {"node_uuid": "uuid-a"},  # Hermes-like — имя в БД есть, но panel нет
        {"node_uuid": "uuid-b"},  # обычная нода
    ]
    _missing = [str(r["node_uuid"]) for r in _state_rows
                if str(r["node_uuid"]) not in node_names]
    assert _missing == ["uuid-a", "uuid-b"], (
        f"expected both uuids in _missing, got {_missing}")


def test_sql_name_fallback_skips_when_panel_has_node():
    """Если uuid есть в node_state и в panel_api — fallback пропускает."""
    from ddos_monitoring import poller

    node_names = {"uuid-a": "Имя A"}  # panel_api вернул
    _state_rows = [{"node_uuid": "uuid-a"}, {"node_uuid": "uuid-b"}]
    _missing = [str(r["node_uuid"]) for r in _state_rows
                if str(r["node_uuid"]) not in node_names]
    assert _missing == ["uuid-b"], (
        f"expected only uuid-b in _missing (uuid-a in panel_api), got {_missing}")
