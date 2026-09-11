"""UI-модуль плагина: контракт window.rwaPluginUI[id] = {mount, unmount}.

Один файл, не правит саму панель. Дизайн — карточный, KPI-шапка,
mini-bar-метрики, sparkline по нодам, гистограмма атак за 24 часа,
severity-бейджи пилюлями. Тёмная и светлая темы, тени, hover, focus.
"""
MODULE_JS = r"""
(function () {
  var PLUGIN_ID = 'ddos-monitoring';

  // ── Утилы ───────────────────────────────────────────────────────────
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmtTime(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    return isNaN(d.getTime()) ? '—' : d.toLocaleString();
  }
  function fmtAgo(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    var s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
    if (s < 60) return s + ' с';
    if (s < 3600) return Math.round(s / 60) + ' мин';
    if (s < 86400) return Math.round(s / 3600) + ' ч';
    return Math.round(s / 86400) + ' дн';
  }
  function pct(v) { return Math.max(0, Math.min(100, Math.round(v || 0))); }
  function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

  // ── Иконки SVG (inline, без зависимостей) ─────────────────────────
  function icon(name) {
    var I = {
      shield: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v7c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>',
      bolt: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h8l-1 8 10-12h-8l1-8Z"/></svg>',
      alert: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 2 21h20L12 2Z"/><path d="M12 9v5M12 17h.01"/></svg>',
      server: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><circle cx="6" cy="7" r="0.8"/><circle cx="6" cy="17" r="0.8"/></svg>',
      refresh: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/></svg>',
      expand: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>',
      bot: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="8" width="18" height="12" rx="3"/><path d="M12 4v4M9 14h6"/></svg>',
      zap: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h8l-1 8 10-12h-8l1-8Z"/></svg>',
      trend: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m3 17 6-6 4 4 8-8"/><path d="M14 7h7v7"/></svg>'
    };
    return I[name] || '';
  }

  // ── Severity палитра: фон + текст, контраст WCAG AA ───────────────
  function sevBg(sev) {
    return {
      critical: 'var(--ddos-crit)',
      high: 'var(--ddos-warn)',
      medium: 'var(--ddos-mid)',
      normal: 'var(--ddos-ok)'
    }[sev] || 'var(--ddos-mid)';
  }
  function sevDot(sev) {
    return {
      critical: 'var(--ddos-crit-dot)',
      high: 'var(--ddos-warn-dot)',
      medium: 'var(--ddos-mid-dot)',
      normal: 'var(--ddos-ok-dot)'
    }[sev] || 'var(--ddos-mid-dot)';
  }

  // ── CSS дизайн-система (внутри <style>, scope `.ddos-*`) ──────────
  var STYLES = '' +
    '<style>' +
    '  .ddos-monitoring-root { font: 400 14px/1.5 var(--ddos-font-sans, system-ui, -apple-system, Segoe UI, Roboto, sans-serif);' +
    '                         color: var(--ddos-ink); padding: 0; max-width: 1200px; margin: 0; }' +
    '  .ddos-monitoring-root *, .ddos-monitoring-root *::before, .ddos-monitoring-root *::after { box-sizing: border-box; }' +
    '  .ddos-row { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 16px; }' +
    '  @media (max-width: 920px) { .ddos-row { grid-template-columns: repeat(2, 1fr); } }' +
    '  @media (max-width: 480px) { .ddos-row { grid-template-columns: 1fr; } }' +
    '  .ddos-kpi { background: var(--ddos-card); border: 1px solid var(--ddos-border); border-radius: var(--ddos-radius);' +
    '              padding: 14px 16px; display: flex; flex-direction: column; gap: 6px;' +
    '              box-shadow: var(--ddos-shadow); transition: border-color .15s ease; }' +
    '  .ddos-kpi:hover { border-color: var(--ddos-border-strong); }' +
    '  .ddos-kpi-label { display: flex; align-items: center; gap: 6px; font-size: 12px;' +
    '                    color: var(--ddos-muted); letter-spacing: .02em; }' +
    '  .ddos-kpi-value { font: 600 26px/1.1 var(--ddos-font-display, ui-serif, Georgia, serif);' +
    '                    color: var(--ddos-ink); font-variant-numeric: tabular-nums; }' +
    '  .ddos-kpi-sub { font-size: 11px; color: var(--ddos-muted); font-variant-numeric: tabular-nums; }' +
    '  .ddos-kpi[data-sev=critical] .ddos-kpi-value { color: var(--ddos-crit); }' +
    '  .ddos-kpi[data-sev=high] .ddos-kpi-value { color: var(--ddos-warn); }' +
    '  .ddos-kpi[data-sev=normal] .ddos-kpi-value { color: var(--ddos-ok); }' +
    '  .ddos-section { background: var(--ddos-card); border: 1px solid var(--ddos-border);' +
    '                  border-radius: var(--ddos-radius); padding: 16px 18px;' +
    '                  margin-bottom: 16px; box-shadow: var(--ddos-shadow); }' +
    '  .ddos-h { display: flex; align-items: center; gap: 8px; margin: 0 0 12px;' +
    '            font: 500 14px/1.2 var(--ddos-font-sans); color: var(--ddos-ink-strong); }' +
    '  .ddos-h .ddos-meta { margin-left: auto; display: flex; gap: 8px; align-items: center;' +
    '                       font-size: 11px; color: var(--ddos-muted); font-weight: 400; }' +
    '  .ddos-btn { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 8px;' +
    '              border: 1px solid var(--ddos-border-strong); background: transparent; color: var(--ddos-ink);' +
    '              cursor: pointer; font: inherit; font-size: 12px; line-height: 1;' +
    '              transition: background .12s ease, border-color .12s ease, transform .04s ease; }' +
    '  .ddos-btn:hover { background: var(--ddos-card-hover); border-color: var(--ddos-accent); }' +
    '  .ddos-btn:active { transform: scale(.97); }' +
    '  .ddos-btn:focus-visible { outline: 2px solid var(--ddos-accent); outline-offset: 2px; }' +
    '  .ddos-btn-primary { background: var(--ddos-accent); color: var(--ddos-accent-ink); border-color: var(--ddos-accent); }' +
    '  .ddos-btn-primary:hover { filter: brightness(1.08); background: var(--ddos-accent); border-color: var(--ddos-accent); }' +
    '  .ddos-pill { display: inline-flex; align-items: center; gap: 4px; padding: 2px 9px; border-radius: 999px;' +
    '               font-size: 11px; font-weight: 600; letter-spacing: .02em; line-height: 1.5;' +
    '               background: var(--ddos-pill-bg); color: var(--ddos-pill-ink);' +
    '               border: 1px solid var(--ddos-pill-border); white-space: nowrap; }' +
    '  .ddos-pill[data-sev=critical] { background: var(--ddos-crit); color: var(--ddos-pill-on); border-color: transparent; }' +
    '  .ddos-pill[data-sev=high] { background: var(--ddos-warn); color: var(--ddos-pill-on); border-color: transparent; }' +
    '  .ddos-pill[data-sev=medium] { background: var(--ddos-mid); color: var(--ddos-pill-on); border-color: transparent; }' +
    '  .ddos-pill[data-sev=normal] { background: var(--ddos-ok); color: var(--ddos-pill-on); border-color: transparent; }' +
    '  .ddos-pill[data-sev=offline] { background: var(--ddos-muted); color: var(--ddos-card); border-color: transparent; }' +
    '  .ddos-pill-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }' +
    '  .ddos-bar { height: 4px; border-radius: 2px; background: var(--ddos-bar-bg); overflow: hidden; position: relative; }' +
    '  .ddos-bar-fill { position: absolute; inset: 0 auto 0 0; border-radius: inherit;' +
    '                   background: var(--ddos-bar-fill, var(--ddos-accent)); }' +
    '  .ddos-bar-fill[data-sev=critical] { background: var(--ddos-crit); }' +
    '  .ddos-bar-fill[data-sev=high] { background: var(--ddos-warn); }' +
    '  .ddos-bar-fill[data-sev=medium] { background: var(--ddos-mid); }' +
    '  .ddos-bar-fill[data-sev=normal] { background: var(--ddos-ok); }' +
    '  .ddos-nodes { display: grid; gap: 8px; }' +
    '  .ddos-node { display: grid; grid-template-columns: 14px minmax(0,1.4fr) auto minmax(0,1fr) auto;' +
    '               align-items: center; gap: 14px; padding: 10px 8px;' +
    '               border: 1px solid var(--ddos-border); border-radius: var(--ddos-radius-sm);' +
    '               background: var(--ddos-card); transition: border-color .12s ease, background .12s ease; }' +
    '  .ddos-node:hover { background: var(--ddos-card-hover); border-color: var(--ddos-border-strong); }' +
    '  .ddos-node[data-under-attack] { border-color: var(--ddos-crit); background: var(--ddos-card-warn); }' +
    '  @media (max-width: 720px) { .ddos-node { grid-template-columns: 14px minmax(0,1fr); gap: 4px 8px; }' +
    '    .ddos-node > .ddos-node-bar, .ddos-node > .ddos-node-spark, .ddos-node > .ddos-node-aside { grid-column: 2 / -1; } }' +
    '  .ddos-node-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--ddos-ok);' +
    '                   box-shadow: 0 0 0 3px var(--ddos-ok-glow); }' +
    '  .ddos-node-dot[data-stale] { background: var(--ddos-mid); box-shadow: 0 0 0 3px var(--ddos-mid-glow); }' +
    '  .ddos-node-dot[data-off] { background: var(--ddos-crit); box-shadow: 0 0 0 3px var(--ddos-crit-glow); }' +
    '  .ddos-node-name { font-weight: 500; color: var(--ddos-ink-strong); display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }' +
    '  .ddos-node-name small { font-weight: 400; color: var(--ddos-muted); font-size: 11px; }' +
    '  .ddos-node-bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; min-width: 0; }' +
    '  .ddos-node-bar .ddos-bar { width: 60px; }' +
    '  .ddos-node-bar .ddos-bar small { font-size: 10px; color: var(--ddos-muted); font-variant-numeric: tabular-nums; min-width: 30px; text-align: right; }' +
    '  .ddos-spark { display: block; height: 24px; width: 100px; }' +
    '  .ddos-spark path { fill: none; stroke: var(--ddos-accent); stroke-width: 1.5; vector-effect: non-scaling-stroke; }' +
    '  .ddos-spark path.ddos-spark-fill { fill: var(--ddos-accent-glow); stroke: none; opacity: .6; }' +
    '  .ddos-spark .dot { fill: var(--ddos-accent); }' +
    '  .ddos-spark[data-empty] { opacity: .35; }' +
    '  .ddos-node-aside { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }' +
    '  .ddos-sort-btn { cursor: pointer; background: none; border: 1px solid var(--ddos-border); border-radius: 3px;' +
    '    color: var(--ddos-muted); font-size: 12px; padding: 2px 5px; line-height: 1; transition: all .12s; }' +
    '  .ddos-sort-btn:hover { color: var(--ddos-accent); border-color: var(--ddos-accent); }' +
    '  .ddos-empty { color: var(--ddos-muted); font-size: 13px; padding: 12px 0; text-align: center; }' +
    '  .ddos-table { width: 100%; border-collapse: collapse; font-size: 13px; font-variant-numeric: tabular-nums; }' +
    '  .ddos-table th { text-align: left; padding: 8px 10px; font-weight: 500; color: var(--ddos-muted);' +
    '                   border-bottom: 1px solid var(--ddos-border); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }' +
    '  .ddos-table td { padding: 10px; border-top: 1px solid var(--ddos-border); vertical-align: middle; }' +
    '  .ddos-table tr:first-child td { border-top: 0; }' +
    '  .ddos-table tr:hover td { background: var(--ddos-card-hover); }' +
    '  .ddos-hist { display: grid; grid-template-columns: repeat(24, 1fr); gap: 3px; align-items: end;' +
    '               height: 60px; padding: 8px 0; }' +
    '  .ddos-hist-col { background: var(--ddos-bar-bg); border-radius: 2px; min-height: 2px;' +
    '                   position: relative; transition: background .15s ease; }' +
    '  .ddos-hist-col[data-active] { background: var(--ddos-accent); }' +
    '  .ddos-hist-col[data-sev=critical] { background: var(--ddos-crit); }' +
    '  .ddos-hist-col[data-sev=high] { background: var(--ddos-warn); }' +
    '  .ddos-hist-col:hover { filter: brightness(1.15); }' +
    '  .ddos-hist-legend { display: flex; justify-content: space-between; font-size: 11px; color: var(--ddos-muted);' +
    '                      font-variant-numeric: tabular-nums; }' +
    '  details.ddos-details { border: 1px solid var(--ddos-border); border-radius: var(--ddos-radius-sm); padding: 10px 14px;' +
    '                         background: var(--ddos-card); margin-bottom: 6px; }' +
    '  details.ddos-details > summary { cursor: pointer; font-weight: 500; padding: 4px 0;' +
    '                                   list-style: none; display: flex; align-items: center; gap: 8px; }' +
    '  details.ddos-details > summary::-webkit-details-marker { display: none; }' +
    '  details.ddos-details > summary::before { content: "+"; color: var(--ddos-muted); font-weight: 400;' +
    '                                            width: 12px; display: inline-block; transition: transform .15s; }' +
    '  details.ddos-details[open] > summary::before { content: "−"; }' +
    '  details.ddos-details .ddos-reason { padding: 8px 0 4px; border-top: 1px solid var(--ddos-border); margin-top: 8px; }' +
    '  details.ddos-details .ddos-reason-title { font-weight: 600; font-size: 13px; margin-bottom: 2px; }' +
    '  details.ddos-details .ddos-reason-hint { font-size: 12px; color: var(--ddos-muted); margin: 2px 0 6px; }' +
    '  details.ddos-details ul { margin: 4px 0 4px 18px; padding: 0; font-size: 12px; line-height: 1.55; }' +
    '  details.ddos-details .ddos-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));' +
    '                                       gap: 8px 16px; margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--ddos-border);' +
    '                                       font-size: 11px; color: var(--ddos-muted); font-variant-numeric: tabular-nums; }' +
    '  .ddos-form { display: flex; flex-direction: column; gap: 12px; max-width: 540px; }' +
    '  .ddos-form label { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--ddos-muted); }' +
    '  .ddos-form input[type=password], .ddos-form input[type=text], .ddos-form input[type=number] {' +
    '              padding: 8px 10px; border: 1px solid var(--ddos-border); border-radius: 8px;' +
    '              background: var(--ddos-input); color: var(--ddos-ink); font: inherit; font-size: 13px;' +
    '              transition: border-color .12s ease, box-shadow .12s ease; }' +
    '  .ddos-form input:focus { outline: none; border-color: var(--ddos-accent);' +
    '                            box-shadow: 0 0 0 3px var(--ddos-accent-glow); }' +
    '  .ddos-form-row { display: flex; gap: 16px; flex-wrap: wrap; align-items: end; }' +
    '  .ddos-form-row > * { flex: 1; min-width: 120px; }' +
    '  .ddos-form-row .ddos-checkbox { flex: 0 0 auto; min-width: auto; }' +
    '  .ddos-form-row .ddos-checkbox label { flex-direction: row; align-items: center; gap: 6px; }' +
    '  .ddos-form .ddos-actions { display: flex; gap: 8px; align-items: center; }' +
    '  .ddos-form .ddos-status { font-size: 12px; color: var(--ddos-muted); }' +
    '  .ddos-form .ddos-status[data-ok] { color: var(--ddos-ok); }' +
    '  .ddos-form .ddos-status[data-err] { color: var(--ddos-crit); }' +
    '  .ddos-banner { background: var(--ddos-card); border: 1px solid var(--ddos-border); border-radius: var(--ddos-radius-sm);' +
    '                 padding: 8px 12px; font-size: 12px; color: var(--ddos-muted); margin-top: 12px;' +
    '                 display: flex; gap: 8px; align-items: center; }' +
    '  .ddos-banner[data-sev=critical] { border-color: var(--ddos-crit); color: var(--ddos-crit); }' +
    '  .ddos-err { color: var(--ddos-crit); font-size: 12px; margin-top: 8px; padding: 8px 12px;' +
    '              background: var(--ddos-card); border-left: 3px solid var(--ddos-crit); border-radius: 4px; }' +
    '  code { background: var(--ddos-bar-bg); padding: 1px 6px; border-radius: 4px; font-size: 12px; font-family: var(--ddos-font-mono); }' +
    '  .ddos-spark-tt { font-size: 10px; color: var(--ddos-muted); fill: var(--ddos-muted); font-variant-numeric: tabular-nums; }' +
    '  .ddos-mute { color: var(--ddos-muted); }' +
    '  .ddos-strong { color: var(--ddos-ink-strong); font-weight: 500; }' +
    '  .ddos-bullet { display: inline-block; width: 4px; height: 4px; border-radius: 50%; background: var(--ddos-accent); margin-right: 6px; }' +
    '  .ddos-version { font-size: 10px; color: var(--ddos-muted); }' +
    '</style>';

  // ── Палитра и темы (через class на root, светлая по умолчанию в админке) ──
  var THEMES = '' +
    '<style>' +
    '  .ddos-monitoring-root {' +
    '    --ddos-font-sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;' +
    '    --ddos-font-display: ui-serif, Georgia, "Times New Roman", serif;' +
    '    --ddos-font-mono: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;' +
    '    --ddos-radius: 12px;' +
    '    --ddos-radius-sm: 8px;' +
    '    --ddos-shadow: 0 1px 2px rgba(0,0,0,.04), 0 4px 14px rgba(0,0,0,.03);' +
    '    --ddos-accent: #4f7cff;' +
    '    --ddos-accent-glow: rgba(79,124,255,.18);' +
    '    --ddos-accent-ink: #ffffff;' +
    '    --ddos-ok: #16a34a;' +
    '    --ddos-ok-glow: rgba(22,163,74,.18);' +
    '    --ddos-ok-dot: #16a34a;' +
    '    --ddos-mid: #d97706;' +
    '    --ddos-mid-glow: rgba(217,119,6,.18);' +
    '    --ddos-mid-dot: #d97706;' +
    '    --ddos-warn: #ea580c;' +
    '    --ddos-warn-dot: #ea580c;' +
    '    --ddos-crit: #dc2626;' +
    '    --ddos-crit-glow: rgba(220,38,38,.18);' +
    '    --ddos-crit-dot: #dc2626;' +
    '    --ddos-pill-bg: transparent;' +
    '    --ddos-pill-ink: var(--ddos-muted);' +
    '    --ddos-pill-border: var(--ddos-border);' +
    '    --ddos-pill-on: #ffffff;' +
    '    --ddos-bar-bg: rgba(128,128,128,.16);' +
    '    --ddos-bar-fill: var(--ddos-accent);' +
    '    --ddos-card-warn: rgba(220,38,38,.04);' +
    '  }' +
    '  @media (prefers-color-scheme: dark) {' +
    '    .ddos-monitoring-root {' +
    '      --ddos-ink: #e6e8eb;' +
    '      --ddos-ink-strong: #ffffff;' +
    '      --ddos-muted: #8a94a3;' +
    '      --ddos-border: rgba(255,255,255,.08);' +
    '      --ddos-border-strong: rgba(255,255,255,.18);' +
    '      --ddos-card: rgba(255,255,255,.03);' +
    '      --ddos-card-hover: rgba(255,255,255,.05);' +
    '      --ddos-input: rgba(255,255,255,.04);' +
    '      --ddos-shadow: 0 1px 2px rgba(0,0,0,.3), 0 6px 18px rgba(0,0,0,.25);' +
    '      --ddos-bar-bg: rgba(255,255,255,.08);' +
    '      --ddos-card-warn: rgba(220,38,38,.08);' +
    '    }' +
    '  }' +
    '  @media (prefers-color-scheme: light) {' +
    '    .ddos-monitoring-root {' +
    '      --ddos-ink: #1f2937;' +
    '      --ddos-ink-strong: #0f172a;' +
    '      --ddos-muted: #6b7280;' +
    '      --ddos-border: rgba(15,23,42,.10);' +
    '      --ddos-border-strong: rgba(15,23,42,.18);' +
    '      --ddos-card: #ffffff;' +
    '      --ddos-card-hover: rgba(15,23,42,.02);' +
    '      --ddos-input: #ffffff;' +
    '      --ddos-shadow: 0 1px 2px rgba(15,23,42,.05), 0 4px 14px rgba(15,23,42,.04);' +
    '      --ddos-bar-bg: rgba(15,23,42,.08);' +
    '      --ddos-card-warn: rgba(220,38,38,.04);' +
    '    }' +
    '  }' +
    '</style>';

  // ── Sparkline — генерируется из истории нагрузки ноды ─────────────
  // Ожидается поле node.history: массив чисел от 0..100 (нормализованная
  // загрузка: max(cpu_pct, syn_recv/100, established/1000)). Если поля нет
  // — вернём пустую заглушку.
  function sparkline(history) {
    var w = 100, h = 24, pad = 2;
    if (!history || !history.length) {
      return '<svg class="ddos-spark" data-empty="1" viewBox="0 0 ' + w + ' ' + h +
        '" xmlns="http://www.w3.org/2000/svg"><line x1="0" y1="' + h/2 +
        '" x2="' + w + '" y2="' + h/2 +
        '" stroke="currentColor" stroke-dasharray="2 3" opacity=".4"/></svg>';
    }
    var n = history.length;
    var max = Math.max.apply(null, history.concat([1]));
    var step = (w - pad * 2) / Math.max(1, n - 1);
    var points = history.map(function (v, i) {
      var x = pad + i * step;
      var y = pad + (1 - v / max) * (h - pad * 2);
      return [x, y];
    });
    var d = points.map(function (p, i) {
      return (i === 0 ? 'M' : 'L') + p[0].toFixed(1) + ',' + p[1].toFixed(1);
    }).join(' ');
    var fillD = d + ' L' + points[points.length - 1][0].toFixed(1) + ',' + (h - pad) +
                ' L' + points[0][0].toFixed(1) + ',' + (h - pad) + ' Z';
    var last = points[points.length - 1];
    var first = points[0];
    var trend = history[history.length - 1] > history[0] ? '↑' :
                history[history.length - 1] < history[0] ? '↓' : '→';
    return '<svg class="ddos-spark" viewBox="0 0 ' + w + ' ' + h +
      '" xmlns="http://www.w3.org/2000/svg" aria-label="Тренд нагрузки">' +
      '<path class="ddos-spark-fill" d="' + fillD + '"/>' +
      '<path d="' + d + '"/>' +
      '<circle class="dot" cx="' + last[0].toFixed(1) + '" cy="' + last[1].toFixed(1) + '" r="2"/>' +
      '<text class="ddos-spark-tt" x="' + (w - 2) + '" y="9" text-anchor="end">' + trend + '</text>' +
      '</svg>';
  }

  // ── Mini-bar для метрики (CPU / RAM / conntrack) ──────────────────
  function miniBar(label, value, sev) {
    var v = pct(value);
    var autoSev = sev || (v >= 85 ? 'critical' : v >= 70 ? 'high' : v >= 50 ? 'medium' : 'normal');
    return '<div class="ddos-bar" title="' + esc(label) + ': ' + v + '%">' +
      '<div class="ddos-bar-fill" data-sev="' + autoSev + '" style="width:' + v + '%"></div>' +
    '</div>';
  }

  // ── Гистограмма атак за 24 часа (по часовым бакетам) ───────────────
  function attackHistogram(attacks) {
    var now = Date.now();
    var buckets = new Array(24);
    for (var i = 0; i < 24; i++) buckets[i] = { count: 0, maxSev: 'normal' };
    (attacks || []).forEach(function (a) {
      if (!a.started_at) return;
      var t = new Date(a.started_at).getTime();
      if (isNaN(t)) return;
      var hoursAgo = Math.floor((now - t) / 3600000);
      if (hoursAgo < 0 || hoursAgo >= 24) return;
      // bucket[0] = текущий час, bucket[23] = 23 часа назад
      var b = 23 - hoursAgo;
      buckets[b].count++;
      var sev = a.severity || 'normal';
      var order = { normal: 0, medium: 1, high: 2, critical: 3 };
      if ((order[sev] || 0) > (order[buckets[b].maxSev] || 0)) buckets[b].maxSev = sev;
    });
    var max = Math.max.apply(null, buckets.map(function (b) { return b.count; }).concat([1]));
    var h = '';
    h += '<div class="ddos-hist" role="img" aria-label="Атаки за последние 24 часа">';
    buckets.forEach(function (b, i) {
      var pct = max > 0 ? Math.max(2, (b.count / max) * 100) : 2;
      var active = b.count > 0;
      var title = (23 - i) + ' ч назад: ' + b.count + ' атак' +
                  (b.maxSev !== 'normal' ? ' (' + b.maxSev + ')' : '');
      h += '<div class="ddos-hist-col" data-active="' + (active ? '1' : '0') +
           '" data-sev="' + b.maxSev + '" title="' + esc(title) +
           '" style="height:' + pct + '%"></div>';
    });
    h += '</div>';
    h += '<div class="ddos-hist-legend"><span>24 ч назад</span><span>сейчас</span></div>';
    return h;
  }

  // ── KPI-карточки ───────────────────────────────────────────────────
  function kpiCards(data, pollerStale) {
    var nodes = data.nodes || [];
    var attacks = data.attacks_recent || [];
    var attacks24 = attacks.filter(function (a) {
      if (!a.started_at) return false;
      var t = new Date(a.started_at).getTime();
      return !isNaN(t) && (Date.now() - t) < 86400000;
    });
    var live = nodes.filter(function (n) { return !!n.attack_id; }).length;
    var totalMonitored = nodes.length;
    // v0.7.49: total_nodes_in_panel из бэка — все ноды, которые знает панель
    var totalPanel = (typeof data.total_nodes_in_panel === 'number' && data.total_nodes_in_panel >= totalMonitored)
      ? data.total_nodes_in_panel : 0;
    var last24Sev = attacks24.reduce(function (m, a) {
      var order = { normal: 0, medium: 1, high: 2, critical: 3 };
      return Math.max(m, order[a.severity] || 0);
    }, 0);
    var fleetSev = (function () {
      // Если есть активные атаки critical → полк под ударом
      var under = nodes.some(function (n) { return n.severity === 'critical' && n.attack_id; });
      if (under) return 'critical';
      if (live > 0) return 'high';
      if (nodes.some(function (n) { return n.last_seen_at; })) return 'normal';
      return 'offline';
    })();
    var fleetLabel = ({
      critical: '⚠ Под атакой',
      high: 'Атаки идут',
      normal: 'Стабильно',
      offline: 'Нет данных'
    })[fleetSev];

    var cards = [
      {
        icon: 'server', label: 'Под наблюдением',
        value: totalPanel > 0 ? (totalMonitored + ' / ' + totalPanel) : totalMonitored,
        sub: (nodes.filter(function (n) { return n.last_seen_at; }).length) + ' со срезом' +
             (totalPanel > totalMonitored ? ' · ' + (totalPanel - totalMonitored) + ' без агента' : '')
      },
      {
        icon: 'bolt', label: 'Атаки прямо сейчас', value: live, sev: live > 0 ? 'critical' : 'normal',
        sub: live > 0 ? 'требуется внимание' : 'тихо'
      },
      {
        icon: 'trend', label: 'За последние 24 ч', value: attacks24.length,
        sev: total24Sev(attacks24), sub: 'из ' + attacks.length + ' в логе'
      },
      {
        icon: 'shield', label: 'Вердикт полка', value: fleetLabel, sev: fleetSev,
        sub: pollerStale ? 'опрос устарел' : 'опрос в норме'
      }
    ];

    var h = '<div class="ddos-row">';
    cards.forEach(function (c) {
      var sevAttr = c.sev ? ' data-sev="' + c.sev + '"' : '';
      h += '<div class="ddos-kpi"' + sevAttr + '>' +
           '<div class="ddos-kpi-label">' + icon(c.icon) + ' ' + esc(c.label) + '</div>' +
           '<div class="ddos-kpi-value">' + esc(String(c.value)) + '</div>' +
           '<div class="ddos-kpi-sub">' + esc(c.sub) + '</div>' +
           '</div>';
    });
    h += '</div>';
    return h;
  }
  function total24Sev(attacks24) {
    var max = 0;
    var order = { normal: 0, medium: 1, high: 2, critical: 3 };
    attacks24.forEach(function (a) { max = Math.max(max, order[a.severity] || 0); });
    return max >= 3 ? 'critical' : max === 2 ? 'high' : max === 1 ? 'medium' : 'normal';
  }

  // ── Главный рендер секции «Данные» ─────────────────────────────────
  function render(data) {
    var p = data.poller || {};
    var nodes = data.nodes || [];
    var attacks = data.attacks_recent || [];

    var h = '';
    // Banners: опрос устарел / ошибка
    if (p.stale) {
      h += '<div class="ddos-banner" data-sev="critical">' + icon('alert') +
           'Опрос устарел — данные могут быть неполными. ' +
           (p.error ? 'Ошибка: <code>' + esc(p.error) + '</code>' : 'Проверь poller.') +
           '</div>';
    }

    // KPI
    h += kpiCards(data, p.stale);

    // Гистограмма атак
    h += '<div class="ddos-section">' +
      '<div class="ddos-h">' + icon('bolt') + ' Атаки за 24 часа' +
      '<span class="ddos-meta">' + attacks.length + ' в логе · ' +
      attacks.filter(function (a) { return !a.ended_at; }).length + ' активных</span>' +
      '</div>';
    h += attackHistogram(attacks);
    h += '</div>';

    // Ноды — список карточек с mini-bar
    h += '<div class="ddos-section">' +
      '<div class="ddos-h">' + icon('server') + ' Ноды' +
      '<button id="ddos-refresh" class="ddos-btn" type="button">' + icon('refresh') + ' Обновить</button>' +
      '<span id="ddos-refresh-ts" class="ddos-meta"></span>' +
      '</div>';

    if (!nodes.length) {
      h += '<div class="ddos-empty">Телеметрии пока нет — ждём первый срез агентов.</div>';
    } else {
      h += '<div class="ddos-nodes">';
      nodes.forEach(function (n) {
        var under = !!n.attack_id;
        var sev = under ? (n.severity || 'high') : null;
        var stale = n.last_seen_at
          ? ((Date.now() - new Date(n.last_seen_at).getTime()) > 90000)
          : true;
        var dotState = stale ? (n.last_seen_at ? 'data-stale' : 'data-off') : '';

        // CPU / RAM / conntrack: из /details (metrics), здесь приближение через прочерк
        var cpu = n.metrics && n.metrics.cpu_pct;
        var ram = n.metrics && n.metrics.ram_pct;
        var est = n.metrics && n.metrics.established;

        var pill = under
          ? '<span class="ddos-pill" data-sev="' + sev + '"><span class="ddos-pill-dot"></span>' +
            esc(n.attack_type || 'атака') + '</span>'
          : '<span class="ddos-pill" data-sev="normal"><span class="ddos-pill-dot"></span>ОК</span>';

        var ago = n.last_seen_at ? fmtAgo(n.last_seen_at) : 'нет среза';
        var version = n.agent_version ? '<small>v' + esc(n.agent_version) + '</small>' : '';

        h += '<div class="ddos-node"' + (under ? ' data-under-attack="1"' : '') + ' data-uuid="' + esc(n.node_uuid) + '">' +
          '<span class="ddos-node-dot" ' + dotState + ' title="' + esc(ago) + '"></span>' +
          '<div class="ddos-node-name">' +
            esc(n.node_name || n.node_uuid) + ' ' + version +
          '</div>' +
          '<div class="ddos-node-bar">' +
            (cpu != null
              ? '<small>CPU ' + pct(cpu) + '%</small>' + miniBar('CPU', cpu)
              : '<small>CPU —</small><div class="ddos-bar"><div class="ddos-bar-fill" style="width:0%"></div></div>') +
            (ram != null
              ? '<small>RAM ' + pct(ram) + '%</small>' + miniBar('RAM', ram)
              : '<small>RAM —</small><div class="ddos-bar"><div class="ddos-bar-fill" style="width:0%"></div></div>') +
            (est != null
              ? '<small>СОЕД ' + (est >= 1000 ? (est / 1000).toFixed(1) + 'k' : est) + '</small>' +
                miniBar('Соединения', Math.min(100, est / 100))
              : '') +
          '</div>' +
          '<div class="ddos-spark-wrap">' +
            sparkline(n.history || (n.metrics && n.metrics.history)) +
          '</div>' +
          '<div class="ddos-node-aside">' +
            '<button class="ddos-sort-btn" data-sort="up" title="Вверх">▲</button>' +
            '<button class="ddos-sort-btn" data-sort="down" title="Вниз">▼</button>' +
            pill +
            '<span class="ddos-mute" style="font-size:11px;">' + esc(ago) + '</span>' +
          '</div>' +
        '</div>';
      });
      h += '</div>';
    }
    h += '</div>';

    // Атаки — последние
    h += '<div class="ddos-section">' +
      '<div class="ddos-h">' + icon('alert') + ' Последние атаки</div>';

    if (!attacks.length) {
      h += '<div class="ddos-empty">Пока тихо.</div>';
    } else {
      h += '<table class="ddos-table"><thead><tr>' +
        '<th>Нода</th><th>Начало</th><th>Конец</th><th>Тип</th><th>Severity</th><th>Длительность</th>' +
        '</tr></thead><tbody>';
      attacks.slice(0, 20).forEach(function (a) {
        var dur = '';
        if (a.started_at) {
          var endT = a.ended_at ? new Date(a.ended_at).getTime() : Date.now();
          var sec = Math.round((endT - new Date(a.started_at).getTime()) / 1000);
          dur = sec < 60 ? sec + ' с' : sec < 3600 ? Math.round(sec / 60) + ' мин' : Math.round(sec / 3600) + ' ч';
        }
        h += '<tr>' +
          '<td class="ddos-strong">' + esc(a.node_name || a.node_uuid) + '</td>' +
          '<td>' + esc(fmtTime(a.started_at)) + '</td>' +
          '<td>' + (a.ended_at
            ? esc(fmtTime(a.ended_at))
            : '<span class="ddos-pill" data-sev="critical"><span class="ddos-pill-dot"></span>идёт</span>') + '</td>' +
          '<td>' + esc(a.attack_type || '—') + '</td>' +
          '<td><span class="ddos-pill" data-sev="' + esc(a.severity || 'normal') + '">' +
            esc(a.severity || 'normal') + '</span></td>' +
          '<td class="ddos-mute">' + esc(dur) + '</td>' +
        '</tr>';
      });
      h += '</tbody></table>';
    }
    h += '</div>';

    h += '<div id="ddos-details-slot"></div>';
    return h;
  }

  // ── Расшифровка по нодам ──────────────────────────────────────────
  var VERDICT_RU = { attack: '🔴 Атакуют', health: '🟡 Требует внимания',
                     load: '🟠 Высокая нагрузка', offline: '⚫ Нет связи',
                     stable: '🟢 Стабильно', unknown: '…' };
  function renderDetails(d) {
    var nodes = (d && d.nodes) || [];
    var h = '<details class="ddos-details"><summary>' + icon('zap') +
            ' Расшифровка по нодам</summary>';
    if (!nodes.length) {
      h += '<div class="ddos-empty">Нет данных.</div></details>';
      return h;
    }
    nodes.forEach(function (n) {
      var v = VERDICT_RU[n.verdict] || n.verdict || '…';
      var age = n.snapshot_age_s != null ? (' · срез ' + n.snapshot_age_s + ' с назад') : '';
      h += '<details class="ddos-details" data-duuid="' + esc(n.node_uuid) + '">' +
           '<summary>' + esc(n.node_name || n.node_uuid) + ' — <b>' + v + '</b>' +
           '<span class="ddos-mute">' + esc(age) + '</span></summary>';

      if (!(n.reasons || []).length) {
        h += '<div class="ddos-mute" style="font-size:12px;padding:8px 0;">Причин нет — все метрики в норме.</div>';
      }
      (n.reasons || []).forEach(function (r) {
        h += '<div class="ddos-reason">' +
             '<div class="ddos-reason-title"><span class="ddos-bullet"></span>' + esc(r.text) + '</div>';
        if (r.hint) h += '<div class="ddos-reason-hint">' + esc(r.hint) + '</div>';
        h += '<ul>';
        (r.items || []).forEach(function (it) {
          if (typeof it === 'string') { h += '<li>' + esc(it) + '</li>'; return; }
          h += '<li><b>' + esc(it.unit || '') + '</b> — ' + esc(it.what || '');
          if (it.todo) h += '<div class="ddos-reason-hint" style="margin:2px 0 4px 10px;">Что делать: ' + esc(it.todo) + '</div>';
          h += '</li>';
        });
        if (r.total_ips > (r.items || []).length)
          h += '<li class="ddos-mute">…и ещё ' + (r.total_ips - r.items.length) + ' IP</li>';
        h += '</ul></div>';
      });

      var m = n.metrics || {};
      if (Object.keys(m).length) {
        h += '<div class="ddos-metrics">' +
          metricCell('SYN_RECV', m.syn_recv) +
          metricCell('Соединения', m.established) +
          metricCell('CPU', pct(m.cpu_pct) + '%', m.cpu_pct) +
          metricCell('RAM', pct(m.ram_pct) + '%', m.ram_pct) +
          metricCell('Swap', pct(m.swap_pct) + '%', m.swap_pct) +
          metricCell('Диск', pct(m.disk_pct) + '%', m.disk_pct) +
        '</div>';
      }
      h += '</details>';
    });
    h += '</details>';
    return h;
  }
  function metricCell(label, val, raw) {
    if (val == null) return '';
    var bar = '';
    if (typeof raw === 'number') bar = '<div class="ddos-bar" style="margin-top:3px"><div class="ddos-bar-fill" style="width:' + pct(raw) + '%"></div></div>';
    return '<div><div>' + esc(label) + ': <b style="color:var(--ddos-ink-strong)">' + esc(val) + '</b></div>' + bar + '</div>';
  }

  function loadDetails(root) {
    var slot = root.querySelector('#ddos-details-slot');
    if (!slot) return;
    var openSet = {};
    var prevDuuids = slot.querySelectorAll('details[data-duuid]');
    for (var i = 0; i < prevDuuids.length; i++) {
      openSet[prevDuuids[i].getAttribute('data-duuid')] = prevDuuids[i].open;
    }
    fetch(API_BASE + '/details', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        slot.innerHTML = renderDetails(d);
        var newDuuids = slot.querySelectorAll('details[data-duuid]');
        for (var k = 0; k < newDuuids.length; k++) {
          var du = newDuuids[k].getAttribute('data-duuid');
          if (du in openSet) newDuuids[k].open = openSet[du];
        }
        detailsLoadedOnce = true;
      })
      .catch(function () { slot.innerHTML = ''; });
    var ts = root.querySelector('#ddos-refresh-ts');
    if (ts) ts.textContent = 'обновлено ' + new Date().toLocaleTimeString();
  }
  function bindRefresh(root) {
    var btn = root.querySelector('#ddos-refresh');
    if (btn && !btn._bound) {
      btn._bound = true;
      btn.addEventListener('click', function () { loadDetails(root); });
    }
    // Sort buttons — event delegation
    var nodesContainer = root.querySelector('.ddos-nodes');
    if (nodesContainer && !nodesContainer._sortBound) {
      nodesContainer._sortBound = true;
      nodesContainer.addEventListener('click', function (e) {
        var btn = e.target.closest('.ddos-sort-btn');
        if (!btn) return;
        var card = btn.closest('.ddos-node');
        if (!card) return;
        var dir = btn.getAttribute('data-sort');
        var parent = card.parentNode;
        var cards = Array.from(parent.querySelectorAll('.ddos-node'));
        var idx = cards.indexOf(card);
        if (dir === 'up' && idx > 0) {
          parent.insertBefore(card, cards[idx - 1]);
        } else if (dir === 'down' && idx < cards.length - 1) {
          parent.insertBefore(card, cards[idx + 1].nextSibling);
        } else {
          return;
        }
        // Collect new order and POST
        var newOrder = Array.from(parent.querySelectorAll('.ddos-node')).map(function (el, i) {
          return { node_uuid: el.getAttribute('data-uuid'), sort_order: i };
        });
        fetch(API_BASE + '/nodes/order', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ order: newOrder }),
        }).catch(function (err) { console.warn('[ddos] sort save failed', err); });
      });
    }
  }
  var detailsLoadedOnce = false;
  function refreshDetailsQuiet(root) {
    var slot = root.querySelector('#ddos-details-slot');
    if (!slot || !slot.firstChild) return;
    fetch(API_BASE + '/details', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        var nodes = (d && d.nodes) || [];
        nodes.forEach(function (n) {
          var el = slot.querySelector('[data-duuid="' + n.node_uuid + '"] b');
          if (el) el.textContent = (VERDICT_RU[n.verdict] || n.verdict);
        });
        detailsLoadedOnce = true;
      })
      .catch(function () {});
  }

  // ── Telegram-настройки ────────────────────────────────────────────
  function renderTg(tg) {
    var h = '<details class="ddos-details"><summary>' + icon('bot') +
            ' Настройки Telegram-бота</summary>';
    h += '<div class="ddos-form" style="margin-top:8px">';

    if (tg.token_masked) {
      h += '<div class="ddos-mute" style="font-size:12px;">Текущий бот: <code id="ddos-tg-mask">' +
           esc(tg.token_masked) + '</code></div>';
    } else {
      h += '<div class="ddos-banner">' + icon('bot') +
           'Свой бот не настроен — алерты идут через уведомления панели.</div>';
    }

    h += '<label>Bot Token' +
         '<input id="ddos-tg-token" type="password" placeholder="' +
         (tg.token_masked ? 'оставить текущий: ' + esc(tg.token_masked) : '123456:ABC-DEF...') + '">' +
         '</label>';
    h += '<label>Chat ID (через запятую)' +
         '<input id="ddos-tg-chats" type="text" value="' + esc((tg.chat_ids || []).join(',')) +
         '" placeholder="380424819, -1001234567890">' +
         '</label>';

    h += '<div class="ddos-form-row">' +
      '<label class="ddos-checkbox"><input type="checkbox" id="ddos-sum-en" ' +
        (tg.summary_enabled === false ? '' : 'checked') + '> Автоотчёт</label>' +
      '<label>Каждые, ч <input type="number" id="ddos-sum-h" min="1" max="24" step="1" value="' +
        (tg.summary_interval_h || 1) + '"></label>' +
      '<label>Повтор алерта, мин <input type="number" id="ddos-cd-m" min="0" max="1440" step="1" value="' +
        (tg.alert_cooldown_m != null ? tg.alert_cooldown_m : 5) + '"></label>' +
      '</div>';

    h += '<div class="ddos-actions">' +
      '<button id="ddos-tg-save" class="ddos-btn ddos-btn-primary" type="button">' + icon('shield') + ' Сохранить</button>' +
      '<button id="ddos-tg-test" class="ddos-btn" type="button">' + icon('zap') + ' Тест</button>' +
      '<span id="ddos-tg-status" class="ddos-status"></span>' +
      '</div>';

    h += '</div></details>';
    return h;
  }

  function api(method, path, body) {
    var headers = { 'Accept': 'application/json' };
    if (body) headers['Content-Type'] = 'application/json';
    var m = document.cookie.match(/(?:^|;\s*)rw_csrf=([^;]+)/);
    if (method !== 'GET' && m) headers['X-CSRF-Token'] = decodeURIComponent(m[1]);
    return fetch(API_BASE + path, {
      method: method, credentials: 'same-origin',
      headers: headers,
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }

  function bindTg(root) {
    var save = root.querySelector('#ddos-tg-save');
    var test = root.querySelector('#ddos-tg-test');
    var status = root.querySelector('#ddos-tg-status');
    var tokenEl = root.querySelector('#ddos-tg-token');
    var chatsEl = root.querySelector('#ddos-tg-chats');

    if (save) save.addEventListener('click', function () {
      status.textContent = 'Сохранение…';
      status.removeAttribute('data-ok'); status.removeAttribute('data-err');
      var payload = {};
      if (tokenEl.value.trim()) payload.bot_token = tokenEl.value.trim();
      payload.chat_ids = chatsEl.value.trim();
      var sumEn = root.querySelector('#ddos-sum-en');
      var sumH = root.querySelector('#ddos-sum-h');
      if (sumEn) payload.summary_enabled = sumEn.checked;
      if (sumH && sumH.value) payload.summary_interval_h = Math.max(1, parseInt(sumH.value, 10) || 1);
      var cdM = root.querySelector('#ddos-cd-m');
      if (cdM && cdM.value !== '') payload.alert_cooldown_m = Math.max(0, parseInt(cdM.value, 10) || 0);
      api('POST', '/tg', payload)
        .then(function () { status.textContent = '✓ сохранено'; status.setAttribute('data-ok', '1'); load(); })
        .catch(function (e) { status.textContent = '✗ ' + e.message; status.setAttribute('data-err', '1'); });
    });

    if (test) test.addEventListener('click', function () {
      status.textContent = 'Отправка…';
      status.removeAttribute('data-ok'); status.removeAttribute('data-err');
      api('POST', '/tg/test', { text: '✅ DDoS-мониторинг: тест связи' })
        .then(function (r) {
          status.textContent = r.via === 'bot'
            ? '✓ отправлено ботом (' + r.sent + ')'
            : '⚠ токен не задан — ушло через уведомления панели';
          status.setAttribute('data-ok', '1');
        })
        .catch(function (e) { status.textContent = '✗ ' + e.message; status.setAttribute('data-err', '1'); });
    });
  }

  // ── Агент на нодах (UI генерирует python render_agent) ─────────────
  var agentRendered = false;
  var lastDataSnap = null;
  var tgRendered = false;
  function refreshAgentStatus() {
    return fetch(API_BASE + '/agent/status', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }
  function mergeAgentStatus(data, agent) {
    var nodes = (agent && agent.nodes) || {};
    (data.nodes || []).forEach(function (n) {
      var a = nodes[n.node_uuid];
      if (!a) return;
      n.agent_version = a.agent_version || null;
      if (a.last_seen_age_s != null) n.last_seen_at = new Date(Date.now() - a.last_seen_age_s * 1000).toISOString();
    });
    return data;
  }
  function refreshDataSection(root) {
    return Promise.all([
      fetch(API_BASE + '/data?fresh=' + Date.now(), { credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }),
      refreshAgentStatus()
    ])
      .then(function (res) {
        var data = mergeAgentStatus(res[0], res[1]);
        var dataEl = root.querySelector('#ddos-data-slot');
        if (!dataEl) return;
        dataEl.innerHTML = render(data);
        bindRefresh(root);
        loadDetails(root);
      });
  }
  function bindAgent(root, agentStatus, forceReload) {
    var slot = root.querySelector('#ddos-agent-slot');
    if (!slot) return;
    if (agentRendered && !forceReload) { updateAgentBadges(slot, agentStatus); return; }
    fetch(API_BASE + '/agent/ui', { credentials: 'same-origin' })
      .then(function (r) { return r.text(); })
      .then(function (html) {
        slot.innerHTML = html;
        agentRendered = true;
        updateAgentBadges(slot, agentStatus);
      })
      .then(function () {
        var btn = slot.querySelector('#ddos-agent-install');
        var host = root.querySelector('#ddos-agent-msg') ||
                   (function () { var s = document.createElement('span');
                     s.id = 'ddos-agent-msg'; slot.parentNode.appendChild(s); return s; })();
        var status = {
          set textContent(v) { host.textContent = v; },
          get textContent() { return host.textContent; }
        };
        if (!btn) { console.warn('[ddos] install button not found'); return; }
        console.log('[ddos] binding install button');
        btn.addEventListener('click', function () {
          console.log('[ddos] install clicked');
          var uuids = Array.prototype.map.call(
            slot.querySelectorAll('.ddos-agent-node:checked'), function (c) { return c.value; });
          console.log('[ddos] uuids:', uuids);
          if (!uuids.length) { status.textContent = 'Выбери хотя бы одну ноду'; return; }
          status.textContent = 'Установка…';
          console.log('[ddos] POST /agent/nodes');
          api('POST', '/agent/nodes', {
            node_uuids: uuids,
            interval_s: parseInt((slot.querySelector('#ddos-agent-interval') || {}).value, 10) || 15,
            ip_limit: parseInt((slot.querySelector('#ddos-agent-ip-limit') || {}).value, 10) || 50,
            top_ips_n: parseInt((slot.querySelector('#ddos-agent-top-n') || {}).value, 10) || 10
          }).then(function (r) {
            console.log('[ddos] install done:', r);
            var msg = '✓ установлено: ' + (r.installed || []).length;
            if (r.unknown && r.unknown.length) {
              msg += ' · неизвестных: ' + r.unknown.length;
            }
            if (r.errors && Object.keys(r.errors).length) {
              var errs = Object.keys(r.errors).map(function (uuid) {
                return uuid.slice(0, 8) + ': ' + r.errors[uuid];
              }).slice(0, 3).join('; ');
              msg += ' · ошибок: ' + Object.keys(r.errors).length + ' (' + errs + ')';
            }
            status.textContent = msg;
            setTimeout(function () {
              refreshAgentStatus()
                .then(function (fresh) {
                  bindAgent(root, fresh, true);
                  return refreshDataSection(root);
                })
                .catch(function () {
                  bindAgent(root, {}, true);
                  return refreshDataSection(root);
                });
            }, 3000);
          }).catch(function (e) {
            console.error('[ddos] install failed:', e);
            status.textContent = '✗ ' + e.message;
          });
        });
      })
      .catch(function (e) {
        console.warn('[ddos] agent ui load failed:', e);
      });
  }

  // ── Inject styles once ─────────────────────────────────────────────
  function ensureStyles() {
    if (document.getElementById('ddos-styles')) return;
    var div = document.createElement('div');
    div.id = 'ddos-styles';
    div.innerHTML = STYLES + THEMES;
    document.head.appendChild(div);
  }

  // ── Standalone auto-mount ──────────────────────────────────────────
  var API_BASE = (function () {
    var m = location.pathname.match(/^(.*\/api\/v2)\/plugins\//);
    return (m ? m[1] : '/api/v2') + '/plugins/' + PLUGIN_ID;
  })();
  function autoMount() {
    var rootEl = document.getElementById('root');
    if (rootEl && !window.rwaPluginUIMounted) {
      window.rwaPluginUIMounted = true;
      window.rwaPluginUI[PLUGIN_ID].mount(rootEl);
    }
  }

  function updateAgentBadges(slot, agentStatus) {
    if (!agentStatus) return;
    var nodes = agentStatus.nodes || {};
    Array.prototype.forEach.call(
      slot.querySelectorAll('.ddos-agent-state'), function (el) {
        var info = nodes[el.getAttribute('data-uuid')];
        if (!info) return;
        var ver = info.agent_version, online = !!info.online;
        if (ver && online) {
          el.innerHTML = '<span class="ddos-pill" data-sev="normal"><span class="ddos-pill-dot"></span>онлайн · v' + esc(ver) + '</span>';
        } else if (ver) {
          el.innerHTML = '<span class="ddos-pill" data-sev="medium"><span class="ddos-pill-dot"></span>offline</span>';
        } else {
          el.innerHTML = '<span class="ddos-pill" data-sev="offline"><span class="ddos-pill-dot"></span>не установлен</span>';
        }
      });
  }

  window.rwaPluginUI = window.rwaPluginUI || {};
  window.rwaPluginUI[PLUGIN_ID] = {
    mount: function (el) {
      ensureStyles();
      el.innerHTML = '<div class="ddos-monitoring-root"><i class="ddos-mute">Загрузка…</i></div>';
      var root = el.querySelector('.ddos-monitoring-root');
      var timer = null;
      function load() {
        Promise.all([
          fetch(API_BASE + '/data', { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }),
          fetch(API_BASE + '/tg', { credentials: 'same-origin' })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .catch(function () { return {}; }),
          fetch(API_BASE + '/agent/status', { credentials: 'same-origin' })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .catch(function () { return {}; })
        ])
          .then(function (res) {
            var data = mergeAgentStatus(res[0], res[2]), tg = res[1] || {}, agent = res[2] || {};
            var dataEl = root.querySelector('#ddos-data-slot');
            var tgEl = root.querySelector('#ddos-tg-slot');
            if (!dataEl) {
              root.innerHTML = '<div id="ddos-data-slot"></div><div id="ddos-tg-slot"></div><div id="ddos-agent-slot"></div>';
              dataEl = root.querySelector('#ddos-data-slot');
              tgEl = root.querySelector('#ddos-tg-slot');
            }
            var snap = JSON.stringify((data.nodes || []).map(function (n) {
              return [n.node_uuid, !!n.attack_id, n.attack_type, n.severity, !!n.last_seen_at];
            }).concat([data.attacks_recent || []]));
            if (snap !== lastDataSnap || !detailsLoadedOnce) {
              lastDataSnap = snap;
              dataEl.innerHTML = render(data);
              bindRefresh(root);
              loadDetails(root);
            } else if (detailsLoadedOnce) {
              refreshDetailsQuiet(root);
            }
            if (!tgRendered) {
              tgEl.innerHTML = renderTg(tg);
              bindTg(tgEl);
              tgRendered = true;
            } else {
              var maskEl = tgEl.querySelector('#ddos-tg-mask');
              if (maskEl && tg.token_masked) maskEl.textContent = tg.token_masked;
            }
            if (!agentRendered) bindAgent(root, agent, false);
            else updateAgentBadges(root.querySelector('#ddos-agent-slot'), agent);
          })
          .catch(function (e) {
            var errEl = root.querySelector('#ddos-load-error');
            if (!errEl) {
              errEl = document.createElement('div');
              errEl.id = 'ddos-load-error';
              errEl.className = 'ddos-err';
              root.insertBefore(errEl, root.firstChild);
            }
            errEl.textContent = '⚠ сбой обновления данных: ' + e.message + ' (секции сохранены)';
          });
      }
      load();
      timer = setInterval(load, 15000);
      this._stop = function () { if (timer) clearInterval(timer); timer = null; };
    },
    unmount: function () {
      if (this._stop) this._stop();
      agentRendered = false;
      tgRendered = false;
      lastDataSnap = null;
      detailsLoadedOnce = false;
      window.rwaPluginUIMounted = false;
    }
  };

  if (location.pathname.endsWith('/ui')) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', autoMount);
    } else {
      autoMount();
    }
  }
})();
"""


def render_agent(agent_status: dict) -> str:
    """HTML секции установки ddos-agent: карточный список нод.

    UI генерируется JS внутри плагина: карточки-ноды с pill-бейджами
    и формой параметров установки.
    """
    import html as _h

    def esc(s):
        return _h.escape(str(s), quote=True)

    nodes = (agent_status or {}).get("nodes") or {}
    h = ''
    h += '<details class="ddos-details"><summary>'
    h += '🖥 Агент на нодах '
    h += '<span class="ddos-mute" style="font-weight:400">(полный мониторинг: службы, SYN_RECV, источники по IP)</span>'
    h += '</summary>'

    if not nodes:
        h += '<div class="ddos-empty">Ноды не найдены</div></details>'
        return h

    h += '<table class="ddos-table" style="margin:8px 0"><thead><tr>'
    h += '<th style="width:32px"></th>'
    h += '<th>Нода</th>'
    h += '<th>Статус</th>'
    h += '</tr></thead><tbody>'

    for uuid, info in nodes.items():
        state = ('<span class="ddos-pill" data-sev="normal">'
                 '<span class="ddos-pill-dot"></span>онлайн · v' + esc(info.get("agent_version", "")) +
                 '</span>' if info.get("agent_version") and info.get("online")
                 else '<span class="ddos-pill" data-sev="medium">'
                      '<span class="ddos-pill-dot"></span>offline</span>'
                      if info.get("agent_version")
                      else '<span class="ddos-pill" data-sev="offline">'
                           '<span class="ddos-pill-dot"></span>не установлен</span>')
        h += ('<tr>'
              '<td><input type="checkbox" class="ddos-agent-node" value="' + esc(uuid) + '"></td>'
              '<td class="ddos-strong">' + esc(info.get("name") or uuid) + '</td>'
              '<td><span class="ddos-agent-state" data-uuid="' + esc(uuid) + '">' + state + '</span></td>'
              '</tr>')
    h += '</tbody></table>'

    h += '<div class="ddos-form-row" style="margin:8px 0">'
    h += '<label>Опрос, с <input type="number" id="ddos-agent-interval" min="5" max="300" value="15"></label>'
    h += '<label>Лимит соед./IP <input type="number" id="ddos-agent-ip-limit" min="0" max="100000" value="50"></label>'
    h += '<label>Топ источников <input type="number" id="ddos-agent-top-n" min="1" max="50" value="10"></label>'
    h += '</div>'

    h += '<div class="ddos-actions">'
    h += '<button id="ddos-agent-install" class="ddos-btn ddos-btn-primary" type="button">Установить / Обновить</button>'
    h += '<span id="ddos-agent-status" class="ddos-status"></span>'
    h += '</div>'

    h += '</details>'
    return h
