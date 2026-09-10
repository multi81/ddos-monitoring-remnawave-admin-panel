"""Standalone-страница для панелей < 4.5.4 (без generic-маршрута /plugins/:id).

Полный HTML со своим CSS на переменных темы панели (--card/--border/--primary):
выглядит родной в тёмной и светлой теме. Данные берёт с нашего же /data.
"""
PAGE_HTML = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DDoS Monitoring</title>
<style>
  :root { color-scheme: dark light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px;
    font: 400 14px/1.45 ui-sans-serif, system-ui, sans-serif;
    background: hsl(var(--background, 220 14% 6%));
    color: hsl(var(--foreground, 220 9% 84%));
  }
  .ddos-h1 { font: 500 28px/1.2 ui-sans-serif, system-ui, sans-serif;
             color: hsl(var(--foreground, 220 9% 84%)); margin: 0 0 4px; }
  .ddos-sub { color: hsl(var(--muted-foreground, 220 9% 56%)); font-size: 14px; margin: 0 0 22px; }
  .ddos-card { background: hsl(var(--card, 220 20% 10%));
               border: 1px solid hsl(var(--border, 220 14% 18%));
               border-radius: 14px; padding: 16px 18px 12px; margin-bottom: 16px; }
  .ddos-head { display: flex; align-items: baseline; gap: 12px; margin-bottom: 10px;
               font: 500 15px/1.2 ui-sans-serif, system-ui, sans-serif; }
  .ddos-meta { margin-left: auto; color: hsl(var(--muted-foreground, 220 9% 56%)); font-size: 12px; }
  table.ddos-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .ddos-table th { text-align: left; opacity: .65; font-weight: 500;
                   padding: 4px 10px 6px 0; border-bottom: 1px solid hsl(var(--border, 220 14% 18%)); }
  .ddos-table td { padding: 7px 10px 7px 0; border-top: 1px solid hsl(var(--border, 220 14% 18%) / .5); }
  .ddos-table tr:first-child td { border-top: 0; }
  .ddos-ok { color: hsl(var(--success, 152 60% 45%), var(--success, #3ca96c)); }
  .ddos-badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px;
                background: hsl(var(--destructive, 0 72% 51%) / .12);
                color: hsl(var(--destructive, 0 72% 51%)); font-weight: 600; }
  .ddos-muted { opacity: .5; }
  .ddos-err { color: hsl(var(--destructive, 0 72% 51%)); }
  code { background: hsl(var(--muted, 220 14% 16%)); padding: 1px 6px; border-radius: 5px; font-size: 12px; }
</style>
</head>
<body>
<h1 class="ddos-h1">DDoS Monitoring</h1>
<p class="ddos-sub">Флот → ноды → атаки · обновление каждые 15 с</p>
<div id="root"><i class="ddos-muted">Загрузка…</i></div>
<script src="ui-module"></script>
</body>
</html>
"""
