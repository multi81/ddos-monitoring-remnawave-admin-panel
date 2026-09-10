"""Lifecycle for the panel-scoped DDoS agent HMAC secret."""
from __future__ import annotations

import asyncio
import os
import secrets
from typing import Any

_SECRET_KEY = "agent_secret"
_LEGACY_KEY = "legacy_agent_secret"
_ENV_LEGACY_KEY = "DDOS_MONITORING_LEGACY_AGENT_SECRET"
_MIN_SECRET_LENGTH = 32
_LOCKS: dict[int, asyncio.Lock] = {}


def _normalize(value: Any) -> str:
    if isinstance(value, dict):
        value = next(iter(value.values()), "")
    return value.strip() if isinstance(value, str) else ""


def _validate(value: Any) -> str:
    result = _normalize(value)
    if len(result) < _MIN_SECRET_LENGTH:
        raise RuntimeError("agent_secret is missing or invalid")
    return result


def _lock_for(ctx: Any) -> asyncio.Lock:
    key = id(ctx)
    lock = _LOCKS.get(key)
    if lock is None:
        lock = _LOCKS[key] = asyncio.Lock()
    return lock


async def get_agent_secret(ctx: Any) -> str:
    """Read the configured panel secret or fail closed."""
    configured = await ctx.settings.get(_SECRET_KEY, None)
    if configured is None:
        raise RuntimeError("agent_secret is not configured")
    return _validate(configured)


async def ensure_agent_secret(ctx: Any) -> str:
    """Return the panel secret, creating or migrating it exactly once.

    ``PluginSettings.set`` is an upsert. The per-context lock prevents two
    concurrent plugin initializers in one process from rotating the value;
    the read-after-write check also detects a failed persistence operation.
    """
    async with _lock_for(ctx):
        configured = await ctx.settings.get(_SECRET_KEY, None)
        if configured is not None:
            return _validate(configured)

        legacy = await ctx.settings.get(_LEGACY_KEY, None)
        if legacy is None:
            legacy = os.environ.get(_ENV_LEGACY_KEY)
        if legacy is not None:
            value = _validate(legacy)
        else:
            value = secrets.token_urlsafe(32)
            _validate(value)

        await ctx.settings.set(_SECRET_KEY, value)
        persisted = await ctx.settings.get(_SECRET_KEY, None)
        return _validate(persisted)
