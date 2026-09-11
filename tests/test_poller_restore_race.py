"""Тест для L2: race между _restore_states_safe и первым _tick_impl."""
import asyncio

import pytest

from ddos_monitoring.poller import DdosPoller


@pytest.mark.asyncio
async def test_restore_before_first_tick():
    """L2: при первом tick() restore должен отработать ДО _tick_impl."""
    p = DdosPoller()
    calls = []

    original_restore = p._restore_states_safe

    async def mock_restore(log):
        calls.append("restore_start")
        await original_restore(log) if False else None  # без реального I/O
        # Симулируем, что restore пишет в _nodes
        p._nodes["node-1"] = {"verdict": "normal"}
        calls.append("restore_end")

    p._restore_states_safe = mock_restore  # type: ignore

    # Подменим _tick_impl чтобы не делать реальную работу
    async def mock_tick_impl(log):
        calls.append("tick_impl")

    p._tick_impl = mock_tick_impl  # type: ignore

    await p.tick()

    # restore_end ДОЛЖЕН быть до tick_impl (или restore_start до tick_impl)
    assert calls.index("restore_start") < calls.index("tick_impl"), \
        f"L2 NOT FIXED: tick_impl стартовал раньше restore_start: {calls}"
    assert calls.index("restore_end") < calls.index("tick_impl"), \
        f"L2 NOT FIXED: restore не завершён до tick_impl: {calls}"
