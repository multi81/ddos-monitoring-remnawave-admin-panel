"""Smoke: INSERT в panel-стиле plugin_settings (без value_type колонки)."""
import asyncio
import asyncpg

async def main():
    conn = await asyncpg.connect(
        host="127.0.0.1", port=54321,
        user="postgres", password="test", database="smoke",
    )
    # Имитация panel-provided схемы: БЕЗ value_type
    await conn.execute("DROP TABLE IF EXISTS smoke_settings_like")
    await conn.execute("""
        CREATE TABLE smoke_settings_like (
            id SERIAL PRIMARY KEY,
            plugin_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value JSONB,
            updated_at TIMESTAMPTZ,
            UNIQUE (plugin_id, key)
        )
    """)

    # INSERT как в исправленной data.py
    await conn.execute("""
        INSERT INTO smoke_settings_like
               (plugin_id, key, value, updated_at)
        VALUES ($1, $2, $3::jsonb, NOW())
        ON CONFLICT (plugin_id, key) DO NOTHING
    """, "ddos-monitoring", "baseline_mode", "false")
    await conn.execute("""
        INSERT INTO smoke_settings_like
               (plugin_id, key, value, updated_at)
        VALUES ($1, $2, $3::jsonb, NOW())
        ON CONFLICT (plugin_id, key) DO NOTHING
    """, "ddos-monitoring", "baseline_window_days", "7")
    await conn.execute("""
        INSERT INTO smoke_settings_like
               (plugin_id, key, value, updated_at)
        VALUES ($1, $2, $3::jsonb, NOW())
        ON CONFLICT (plugin_id, key) DO NOTHING
    """, "ddos-monitoring", "baseline_p95", "0.95")

    # ON CONFLICT DO NOTHING — повторный INSERT не перезаписывает
    await conn.execute("""
        INSERT INTO smoke_settings_like
               (plugin_id, key, value, updated_at)
        VALUES ($1, $2, $3::jsonb, NOW())
        ON CONFLICT (plugin_id, key) DO NOTHING
    """, "ddos-monitoring", "baseline_mode", "true")

    rows = await conn.fetch(
        "SELECT plugin_id, key, value FROM smoke_settings_like ORDER BY key"
    )
    print("Rows in plugin_settings-like:")
    for r in rows:
        print(f"  {dict(r)}")

    # Проверяем что admin override НЕ перезаписан
    override = await conn.fetchval(
        "SELECT value FROM smoke_settings_like WHERE key = 'baseline_mode'"
    )
    assert str(override) == "false", f"baseline_mode был перезаписан: {override!r}"
    print("\nOK: ON CONFLICT DO NOTHING защищает override админа")

    await conn.close()

if __name__ == "__main__":
    asyncio.run(main())
