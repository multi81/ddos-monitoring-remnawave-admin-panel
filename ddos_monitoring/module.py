"""UI-модуль плагина: контракт window.rwaPluginUI[id] = {mount, unmount}.

Фаза 1 — минимальная страница «флот → ноды → атаки»: статус poller,
таблица нод с активными атаками. SVG-схема — фаза 3.
"""
MODULE_JS = r"""
(function () {
  var PLUGIN_ID = 'ddos-monitoring';

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

  var SEV = { critical: '#d64545', high: '#e08a3c', medium: '#d9b23c', normal: 'var(--nf-success, #3ca96c)' };

  function render(data) {
    var p = data.poller || {};
    var nodes = data.nodes || [];
    var attacks = data.attacks_recent || [];
    var h = '';
    h += '<div class="ddos-status" style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;font-size:13px;">';
    h += '<span>Опрос: <b style="color:' + (p.stale ? SEV.critical : SEV.normal) + '">' +
         (p.stale ? 'устарел' : 'ок') + '</b></span>';
    if (p.error) h += '<span>Ошибка: <code>' + esc(p.error) + '</code></span>';
    h += '<span>Нод под наблюдением: <b>' + (p.nodes_monitored || 0) + '</b></span>';
    h += '</div>';

    h += '<h3 style="margin:12px 0 6px;display:flex;align-items:center;gap:10px;">Ноды' +
         '<button id="ddos-refresh" type="button" style="font-size:12px;padding:2px 10px;cursor:pointer;">↻ Обновить</button>' +
         '<span id="ddos-refresh-ts" style="font-weight:400;font-size:11px;opacity:.6;"></span></h3>';
    h += '<table class="ddos-table" style="width:100%;border-collapse:collapse;font-size:13px;">';
    h += '<tr style="text-align:left;opacity:.7;"><th>Нода</th><th>Агент</th><th>Статус</th><th>Атака</th><th>С</th><th>Тип</th></tr>';
    if (!nodes.length) h += '<tr><td colspan="6" style="opacity:.5;padding:8px 0;">Телеметрии пока нет — ждём первый срез агентов.</td></tr>';
    nodes.forEach(function (n) {
      var under = !!n.attack_id;
      var agentVersion = n.agent_version ? 'v' + esc(n.agent_version) : '—';
      h += '<tr style="border-top:1px solid rgba(128,128,128,.2);">';
      h += '<td style="padding:4px 8px 4px 0;">' + esc(n.node_name || n.node_uuid) + '</td>';
      h += '<td>' + agentVersion + '</td>';
      h += '<td>' + (n.last_seen_at ? '<span style="color:' + SEV.normal + '">данные есть</span>'
                                    : '<span style="color:' + SEV.medium + '">нет данных</span>') + '</td>';
      h += '<td style="color:' + (under ? (SEV[n.severity] || SEV.medium) : 'inherit') + '">' +
           (under ? 'АТАКА' : '—') + '</td>';
      h += '<td>' + fmtTime(n.attack_started) + '</td>';
      h += '<td>' + esc(n.attack_type || '') + '</td></tr>';
    });
    h += '</table>';

    h += '<h3 style="margin:16px 0 6px;">Последние атаки</h3><table class="ddos-table" style="width:100%;border-collapse:collapse;font-size:13px;">';
    h += '<tr style="text-align:left;opacity:.7;"><th>Нода</th><th>Начало</th><th>Конец</th><th>Тип</th><th>Severity</th></tr>';
    if (!attacks.length) h += '<tr><td colspan="5" style="opacity:.5;padding:8px 0;">Пока тихо.</td></tr>';
    attacks.forEach(function (a) {
      h += '<tr style="border-top:1px solid rgba(128,128,128,.2);">';
      h += '<td>' + esc(a.node_name || a.node_uuid) + '</td>';
      h += '<td>' + fmtTime(a.started_at) + '</td>';
      h += '<td>' + (a.ended_at ? fmtTime(a.ended_at) : '<b style="color:' + SEV.critical + '">идёт</b>') + '</td>';
      h += '<td>' + esc(a.attack_type || '') + '</td>';
      h += '<td style="color:' + (SEV[a.severity] || 'inherit') + '">' + esc(a.severity) + '</td></tr>';
    });
    h += '</table>';
    h += '<div id="ddos-details-slot" style="margin-top:14px;"></div>';
    return h;
  }

  // ── Расшифровка вердиктов по нодам (/details) + кнопка «Обновить» ──
  var VERDICT_RU = { attack: '🔴 атакуют', health: '🟡 требует внимания',
                     load: '🟠 высокая нагрузка', offline: '⚫️ нет связи',
                     stable: '🟢 стабильно', unknown: '…' };
  function renderDetails(d) {
    var nodes = (d && d.nodes) || [];
    var h = '<details style="border:1px solid rgba(128,128,128,.25);border-radius:8px;padding:10px 12px;">' +
            '<summary style="cursor:pointer;font-weight:600;">🔎 Расшифровка по нодам</summary>';
    if (!nodes.length) { h += '<div style="opacity:.5;font-size:13px;margin-top:8px;">Нет данных.</div></details>'; return h; }
    nodes.forEach(function (n) {
      var v = VERDICT_RU[n.verdict] || n.verdict;
      var age = n.snapshot_age_s != null ? (' · срез ' + n.snapshot_age_s + ' с назад') : '';
      h += '<details data-duuid="' + esc(n.node_uuid) + '" style="margin-top:8px;border-top:1px solid rgba(128,128,128,.15);padding-top:6px;">' +
           '<summary style="cursor:pointer;font-size:13px;">' + esc(n.node_name || n.node_uuid) +
           ' — <b>' + v + '</b>' + esc(age) + '</summary>';
      if (!(n.reasons || []).length) {
        h += '<div style="opacity:.6;font-size:12px;margin:6px 0;">Причин нет — все метрики в норме.</div>';
      }
      (n.reasons || []).forEach(function (r) {
        h += '<div style="margin:8px 0 2px;font-size:13px;font-weight:600;">• ' + esc(r.text) + '</div>';
        if (r.hint) h += '<div style="font-size:12px;opacity:.7;margin:2px 0;">' + esc(r.hint) + '</div>';
        h += '<ul style="margin:2px 0 4px 18px;font-size:12px;opacity:.85;">';
        (r.items || []).forEach(function (it) {
          if (typeof it === 'string') { h += '<li>' + esc(it) + '</li>'; return; }
          h += '<li><b>' + esc(it.unit || '') + '</b> — ' + esc(it.what || '');
          if (it.todo) h += '<div style="opacity:.75;margin:2px 0 6px 10px;">Что делать: ' + esc(it.todo) + '</div>';
          h += '</li>';
        });
        if (r.total_ips > (r.items || []).length)
          h += '<li>…и ещё ' + (r.total_ips - r.items.length) + ' IP</li>';
        h += '</ul>';
      });
      var m = n.metrics || {};
      if (Object.keys(m).length) {
        h += '<div style="font-size:11px;opacity:.55;margin-top:4px;">Метрики: SYN_RECV ' + (m.syn_recv || 0) +
             ' · соед. ' + (m.established || 0) + ' · CPU ' + Math.round(m.cpu_pct || 0) + '%' +
             ' · RAM ' + Math.round(m.ram_pct || 0) + '%' +
             ' · Swap ' + Math.round(m.swap_pct || 0) + '%' +
             ' · Диск ' + (m.disk_pct || 0) + '%</div>';
      }
      h += '</details>';
    });
    h += '</details>';
    return h;
  }
  function loadDetails(root) {
    var slot = root.querySelector('#ddos-details-slot');
    if (!slot) return;
    fetch(API_BASE + '/details', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) { slot.innerHTML = renderDetails(d); detailsLoadedOnce = true; })
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
  }
  var detailsLoadedOnce = false;
  function refreshDetailsQuiet(root) {
    var slot = root.querySelector('#ddos-details-slot');
    if (!slot || !slot.firstChild) return;
    fetch(API_BASE + '/details', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        // Точечно обновляем ТОЛЬКО строки вердиктов внутри уже
        // отрендеренных <details> — открытое состояние сохраняется.
        var nodes = (d && d.nodes) || [];
        nodes.forEach(function (n) {
          var el = slot.querySelector('[data-duuid="' + n.node_uuid + '"] b');
          if (el) el.textContent = (VERDICT_RU[n.verdict] || n.verdict);
        });
        detailsLoadedOnce = true;
      })
      .catch(function () {});
  }

  // ── Секция «Настройки Telegram» ─────────────────────────────────
  function renderTg(tg) {
    var h = '';
    h += '<details style="margin-top:20px;border:1px solid rgba(128,128,128,.25);border-radius:8px;padding:10px 12px;">';
    h += '<summary style="cursor:pointer;font-weight:600;">⚙️ Настройки Telegram-бота</summary>';
    h += '<div style="margin-top:10px;font-size:13px;max-width:480px;display:flex;flex-direction:column;gap:8px;">';
    if (tg.token_masked) {
      h += '<div>Текущий бот: <code id="ddos-tg-mask">' + esc(tg.token_masked) + '</code></div>';
    } else {
      h += '<div style="opacity:.6;">Свой бот не настроен — алерты идут через уведомления панели.</div>';
    }
    h += '<label>Bot Token<br><input id="ddos-tg-token" type="password" placeholder="' +
         (tg.token_masked ? 'оставить текущий: ' + esc(tg.token_masked) : '123456:ABC-DEF...') +
         '" style="width:100%;margin-top:2px;"></label>';
    h += '<label>Chat ID (через запятую)<br><input id="ddos-tg-chats" value="' + esc((tg.chat_ids || []).join(',')) +
         '" placeholder="380424819, -1001234567890" style="width:100%;margin-top:2px;"></label>';
    h += '<div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:2px;">';
    h += '<label><input type="checkbox" id="ddos-sum-en" ' + (tg.summary_enabled === false ? '' : 'checked') + '> Автоотчёт о состоянии</label>';
    h += '<label>Каждые <input type="number" id="ddos-sum-h" min="1" max="24" step="1" value="' +
         (tg.summary_interval_h || 1) + '" style="width:56px;"> ч</label>';
    h += '<label>Повтор алерта раз в <input type="number" id="ddos-cd-m" min="0" max="1440" step="1" value="' +
         (tg.alert_cooldown_m != null ? tg.alert_cooldown_m : 5) + '" style="width:56px;"> мин</label>';
    h += '</div>';
    h += '<div style="display:flex;gap:8px;margin-top:4px;">';
    h += '<button id="ddos-tg-save" class="ddos-btn" style="padding:5px 14px;cursor:pointer;">Сохранить</button>';
    h += '<button id="ddos-tg-test" class="ddos-btn" style="padding:5px 14px;cursor:pointer;">Тест</button>';
    h += '<span id="ddos-tg-status" style="align-self:center;opacity:.8;"></span>';
    h += '</div></div></details>';
    return h;
  }

    // API-хелпер на уровне модуля: нужен и bindTg, и bindAgent.
  function api(method, path, body) {
    var headers = { 'Accept': 'application/json' };
    if (body) headers['Content-Type'] = 'application/json';
    // CSRF double-submit: панель требует X-CSRF-Token для мутирующих методов
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
        .then(function () { status.textContent = '✅ сохранено'; load(); })
        .catch(function (e) { status.textContent = '❌ ' + e.message; });
    });

    if (test) test.addEventListener('click', function () {
      status.textContent = 'Отправка…';
      api('POST', '/tg/test', { text: '✅ DDoS-мониторинг: тест связи' })
        .then(function (r) {
          status.textContent = r.via === 'bot'
            ? '✅ отправлено ботом (' + r.sent + ')'
            : '⚠️ токен не задан — ушло через уведомления панели';
        })
        .catch(function (e) { status.textContent = '❌ ' + e.message; });
    });
  }

  // Секция «Агент на нодах»: HTML генерирует python (render_agent) → GET /agent/ui.
  // Секцию агента НЕ пересоздаём на тиках автообновления — иначе сбрасываются
  // открытый <details> и введённые значения input'ов. Рендерим один раз,
  // дальше обновляем только бейджи онлайн-статуса нод.
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
        // Статус установки живёт ВНЕ slot — тики его не затирают
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
            status.textContent = '✅ установлено: ' + (r.installed || []).length +
              (r.unknown && r.unknown.length ? ' · неизвестных: ' + r.unknown.length : '');
            // перерисовать секцию, чтобы бейджи показали свежую версию агента
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
            status.textContent = '❌ ' + e.message;
          });
        });
      })
      .catch(function (e) {
        // Слот агента НЕ очищаем — секция и чекбоксы остаются на месте,
        // ошибка уходит в строку статуса.
        console.warn('[ddos] agent ui load failed:', e);
      });
  }

  // Панель вызывает mount(el); standalone-страница /ui — авто-mount в #root.
  var API_BASE = (function () {
    var m = location.pathname.match(/^(.*\/api\/v2)\/plugins\//);
    return (m ? m[1] : '/api/v2') + '/plugins/' + PLUGIN_ID;
  })();

  // ── standalone-режим: страница /ui грузит этот файл тегом <script src>,
  // панель generic-роут вызывает mount() сам. Авто-mount для /ui:
  function autoMount() {
    var rootEl = document.getElementById('root');
    if (rootEl && !window.rwaPluginUIMounted) {
      window.rwaPluginUIMounted = true;
      window.rwaPluginUI[PLUGIN_ID].mount(rootEl);
    }
  }
  
  // Обновить только бейджи статуса нод (без пересоздания секции).
  function updateAgentBadges(slot, agentStatus) {
    if (!agentStatus) return;
    var nodes = agentStatus.nodes || {};
    Array.prototype.forEach.call(
      slot.querySelectorAll('.ddos-agent-state'), function (el) {
        var info = nodes[el.getAttribute('data-uuid')];
        if (!info) return;
        var ver = info.agent_version, online = !!info.online;
        if (ver && online) {
          el.innerHTML = '<span style="color:#3fbf5f;">онлайн · v' + esc(ver) + '</span>';
        } else if (ver) {
          el.innerHTML = '<span style="color:#d69e2e;">offline</span>';
        } else {
          el.innerHTML = '<span style="opacity:.55;">не установлен</span>';
        }
      });
  }

  window.rwaPluginUI = window.rwaPluginUI || {};
  window.rwaPluginUI[PLUGIN_ID] = {
    mount: function (el) {
      el.innerHTML = '<div class="ddos-monitoring-root"><i style="opacity:.5">Загрузка…</i></div>';
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
            // Обновляем ТОЧЕЧНО: секцию агента пересоздаём только один раз,
            // иначе innerHTML сбрасывает чекбоксы/ввод и ломает клики.
            var dataEl = root.querySelector('#ddos-data-slot');
            var tgEl = root.querySelector('#ddos-tg-slot');
            if (!dataEl) {
              root.innerHTML = '<div id="ddos-data-slot"></div><div id="ddos-tg-slot"></div><div id="ddos-agent-slot"></div>';
              dataEl = root.querySelector('#ddos-data-slot');
              tgEl = root.querySelector('#ddos-tg-slot');
            }
            // Ререндер ТОЛЬКО при изменении данных: иначе каждые 15с
            // схлопываются открытые <details> расшифровки.
            // ВАЖНО: last_seen_at/attack_started меняются постоянно —
            // в «отпечаток» берём только значимые для отображения поля.
            var snap = JSON.stringify((data.nodes || []).map(function (n) {
              return [n.node_uuid, !!n.attack_id, n.attack_type, n.severity, !!n.last_seen_at];
            }).concat([data.attacks_recent || []]));
            if (snap !== lastDataSnap || !detailsLoadedOnce) {
              lastDataSnap = snap;
              dataEl.innerHTML = render(data);
              bindRefresh(root);
              loadDetails(root);
            } else if (detailsLoadedOnce) {
              // данные не изменились — тихо подтянем возраст срезов без ререндера
              refreshDetailsQuiet(root);
            }
            // Секция Telegram НЕ пересоздаётся на тиках — иначе каждые 15с
            // схлопывается открытый <details> и стирается ввод. Рендерим один
            // раз; маску бота обновляем точечно.
            if (!tgRendered) {
              tgEl.innerHTML = renderTg(tg);
              bindTg(tgEl);
              tgRendered = true;
            } else {
              var maskEl = tgEl.querySelector('#ddos-tg-mask');
              if (maskEl && tg.token_masked) maskEl.textContent = tg.token_masked;
            }
            // Секция агента пересоздаётся ТОЛЬКО один раз при первом mount,
            // чтобы клики по кнопке «Установить» работали всегда.
            if (!agentRendered) bindAgent(root, agent, false);
            else updateAgentBadges(root.querySelector('#ddos-agent-slot'), agent);
          })
          .catch(function (e) {
            // Не затираем DOM: секции и ввод пользователя должны пережить
            // разовый сбой сети. Показываем ошибку отдельной строкой.
            var errEl = root.querySelector('#ddos-load-error');
            if (!errEl) {
              errEl = document.createElement('div');
              errEl.id = 'ddos-load-error';
              errEl.style.cssText = 'color:#d69e2e;font-size:12px;margin-top:8px;';
              root.insertBefore(errEl, root.firstChild);
            }
            errEl.textContent = '⚠️ сбой обновления данных: ' + e.message + ' (секции сохранены)';
          });
      }
      load();
      timer = setInterval(load, 15000);
      this._stop = function () { if (timer) clearInterval(timer); timer = null; };
    },
    unmount: function () {
      if (this._stop) this._stop();
      // Панель — SPA: следующий вход должен монтировать модуль заново.
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

# ── Python-сторона: рендер секции «Агент на нодах» (тестируется напрямую) ──


def render_agent(agent_status: dict) -> str:
    """HTML секции установки ddos-agent: таблица нод (без <details> — не сворачивается)."""
    import html as _h

    def esc(s):
        return _h.escape(str(s), quote=True)

    nodes = (agent_status or {}).get("nodes") or {}
    h = ''
    h += '<div style="margin-top:14px;border:1px solid rgba(128,128,128,.25);border-radius:8px;padding:10px 12px;">'
    h += '<div style="font-weight:600;margin-bottom:6px;">🖥 Агент на нодах <span style="opacity:.6;font-weight:400;">(полный мониторинг: службы, SYN_RECV, источники по IP)</span></div>'
    if not nodes:
        h += '<div style="opacity:.6;padding:8px 0;">Ноды не найдены</div></div>'
        return h
    h += '<table style="width:100%;border-collapse:collapse;font-size:13px;margin:6px 0;">'
    h += ('<thead><tr>'
          '<th style="text-align:left;padding:4px 6px;opacity:.7;font-weight:500;"></th>'
          '<th style="text-align:left;padding:4px 6px;opacity:.7;font-weight:500;">Нода</th>'
          '<th style="text-align:left;padding:4px 6px;opacity:.7;font-weight:500;">Статус</th>'
          '</tr></thead><tbody>')
    for uuid, info in nodes.items():
        online = bool(info.get("online"))
        ver = info.get("agent_version")
        state = ('<span style="color:#3fbf5f;">онлайн · v' + esc(ver) + '</span>' if ver and online
                 else '<span style="color:#d69e2e;">offline</span>' if ver
                 else '<span style="opacity:.55;">не установлен</span>')
        h += ('<tr style="border-top:1px solid rgba(128,128,128,.15);">'
              '<td style="padding:4px 6px;"><input type="checkbox" class="ddos-agent-node" value="' + esc(uuid) + '"></td>'
              '<td style="padding:4px 6px;"><span class="ddos-agent-node-name">' + esc(info.get("name") or uuid) + '</span></td>'
              '<td style="padding:4px 6px;"><span class="ddos-agent-state" data-uuid="' + esc(uuid) + '">' + state + '</span></td>'
              '</tr>')
    h += '</tbody></table>'
    h += '<div style="display:flex;gap:14px;flex-wrap:wrap;margin:6px 0;align-items:center;font-size:13px;">'
    h += 'Опрос каждые <input type="number" id="ddos-agent-interval" min="5" max="300" value="15" style="width:56px;"> с'
    h += '· Лимит соед. с 1 IP <input type="number" id="ddos-agent-ip-limit" min="0" max="100000" value="50" style="width:70px;">'
    h += '· Топ источников <input type="number" id="ddos-agent-top-n" min="1" max="50" value="10" style="width:52px;">'
    h += '</div>'
    h += '<div style="display:flex;gap:8px;align-items:center;">'
    h += '<button id="ddos-agent-install" class="ddos-btn" style="padding:5px 14px;cursor:pointer;">Установить / Обновить</button>'
    h += '<span id="ddos-agent-status" style="opacity:.8;"></span>'
    h += '</div></div>'
    return h
