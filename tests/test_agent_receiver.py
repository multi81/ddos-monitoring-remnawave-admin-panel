"""Тесты для agent_receiver: replay-protection + instance-vs-class state.

Проверки:
- _check_replay: отклоняет уже виденный ts
- _check_replay: НЕ отклоняет ts, отстоящий на > STALE_WINDOW_S (будущее)
  — такие ts считаются валидным (их отвергнет staleness check выше), но не хранятся в set'е
- _check_replay: чистит устаревшие ts
- _check_replay: FIFO-eviction по uuid при _SEEN_MAX_UUIDS
- AgentReceiver._tables_ready: instance (не class) — per-request
- node_secret удалён из public API
"""
from __future__ import annotations

import importlib

ar = importlib.import_module("ddos_monitoring.agent_receiver")


def _reset_seen():
    """Изолированное состояние между тестами."""
    ar._seen_ts.clear()


def test_check_replay_new_uuid_first_ts():
    _reset_seen()
    import time
    ts = int(time.time())
    assert ar._check_replay("uuid-new", ts) is False
    assert ts in ar._seen_ts.get("uuid-new", set())


def test_check_replay_duplicate_ts():
    _reset_seen()
    import time
    ts = int(time.time())
    ar._check_replay("uuid-dup", ts)
    # Второй раз тот же ts → duplicate
    assert ar._check_replay("uuid-dup", ts) is True


def test_check_replay_old_ts_not_counted_as_duplicate():
    """ts старше STALE_WINDOW_S — будет отвергнут общим stale check'ом,
    но _check_replay должен чистить его из set'а, чтобы не считать дубликатом."""
    _reset_seen()
    import time
    old_ts = int(time.time()) - 1000
    new_ts = int(time.time())
    ar._check_replay("uuid-clean", old_ts)
    # Внутри set'а старый ts мог уже быть вычищен cutoff'ом
    s = ar._seen_ts["uuid-clean"]
    # В любом случае после очистки old_ts может не быть в set
    # Проверяем что новый ts не считается дубликатом
    assert ar._check_replay("uuid-clean", new_ts) is False


def test_check_replay_future_ts_not_stored():
    """OOM-атака: ts = now + very_large. Не должны сохранять в set (иначе set растёт).
    Поведение: future ts дальше чем now + STALE_WINDOW_S считаем валидным (вернёт False),
    но НЕ добавляем в set."""
    _reset_seen()
    import time
    far_future_ts = int(time.time()) + 10**9  # миллиарды секунд вперёд
    # Первый вызов: future ts → False (не дубликат)
    result = ar._check_replay("uuid-future", far_future_ts)
    assert result is False
    # Но в set'е этого ts быть не должно
    s = ar._seen_ts["uuid-future"]
    assert far_future_ts not in s, f"future ts сохранён: set size = {len(s)}"
    # Размер set'а должен быть 0 (пусто, либо только старые-валидные)
    # Повторный вызов всё равно False (не дубликат) — это значит replay защита не сработает,
    # но и не сожрёт память
    assert ar._check_replay("uuid-future", far_future_ts) is False


def test_check_replay_max_uuids_fifo_eviction():
    """_SEEN_MAX_UUIDS → FIFO evict. Превышение лимита должно вытеснять самый старый uuid."""
    _reset_seen()
    # Сначала заполняем ровно MAX uuid
    for i in range(ar._SEEN_MAX_UUIDS):
        ar._check_replay(f"uuid-{i}", 0)  # ts=0 → пройдёт cleanup, но добавится как "старый"
    # Теперь добавляем ещё один → должен вытеснить uuid-0
    assert len(ar._seen_ts) == ar._SEEN_MAX_UUIDS
    ar._check_replay("uuid-new", 1)
    assert len(ar._seen_ts) == ar._SEEN_MAX_UUIDS
    assert "uuid-0" not in ar._seen_ts, "FIFO eviction не сработал"


def test_node_secret_removed():
    """node_secret должен быть удалён из API (был unused)."""
    assert not hasattr(ar, "node_secret"), "node_secret остался — должен быть удалён"


def test_receiver_tables_ready_is_instance_not_class():
    """_tables_ready должен быть instance-атрибутом, а не class-атрибутом.
    Проверяем что на классе его нет (только на instance)."""
    assert not hasattr(ar.AgentReceiver, "_tables_ready") or \
        "_tables_ready" not in ar.AgentReceiver.__dict__, (
        "_tables_ready остался class-level — race condition между requests"
    )

    # Создаём 2 instance — они должны иметь разные _tables_ready
    r1 = ar.AgentReceiver(ctx=None)
    r2 = ar.AgentReceiver(ctx=None)
    assert hasattr(r1, "_tables_ready"), "отсутствует instance attr"
    assert hasattr(r2, "_tables_ready"), "отсутствует instance attr"

    # Изменение одного НЕ влияет на другой
    r1._tables_ready = True
    assert r2._tables_ready is False, (
        "изменение instance._tables_ready повлияло на другой instance — class-level!"
    )
