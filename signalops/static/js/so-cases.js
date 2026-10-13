/* SignalOps — "Save to case" + "Export" araç çubuğu (tüm tarama sayfalarında ortak).
 *
 *   window.SignalOpsCase.attach(containerEl, {
 *     kind: 'nearby',                       // tarama türü: nearby|cctv|cell|adsb|ais|search|other
 *     title: 'SIGINT Map',                  // dışa aktarma başlığı / dosya adı
 *     getDevices: () => [...],              // güncel sonuç dizisi
 *     getCenter: () => ({lat, lon}) | null, // isteğe bağlı
 *   });  → { refresh(), destroy() }
 *
 * Harici kütüphane yok. API'den gelen metinler escape edilir, onclick string'i kurulmaz.
 */
(function (w, d) {
  'use strict';
  if (w.SignalOpsCase) return;

  var MAX_DEVICES = 20000;
  var LS_LAST_CASE = 'so_last_case';
  var FORMATS = [['pdf', 'PDF report'], ['kml', 'KML (Google Earth)'], ['geojson', 'GeoJSON'], ['csv', 'CSV (Excel)']];

  function esc(v) {
    if (typeof w.escapeHtml === 'function') return w.escapeHtml(v);
    if (v === null || v === undefined) return '';
    return String(v).replace(/[&<>"'`]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c];
    });
  }

  /* ── Stil (bir kez) ─────────────────────────────────── */
  var CSS = [
    '.so-cs-bar{display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;vertical-align:middle;position:relative}',
    '.so-cs-btn{font-family:Rajdhani,"Segoe UI",sans-serif;font-size:12px;font-weight:700;letter-spacing:1px;',
    '  text-transform:uppercase;cursor:pointer;border-radius:6px;padding:5px 11px;line-height:1.3;white-space:nowrap;',
    '  background:rgba(139,92,246,0.10);color:var(--pl,#A78BFA);border:1px solid rgba(139,92,246,0.35);transition:all .15s}',
    '.so-cs-btn:hover:not(:disabled){background:rgba(139,92,246,0.2);color:#fff;box-shadow:0 0 10px rgba(139,92,246,0.3)}',
    '.so-cs-btn:disabled{opacity:.45;cursor:not-allowed}',
    '.so-cs-btn.so-cs-g{background:rgba(74,222,128,0.08);color:var(--g,#4ADE80);border-color:rgba(74,222,128,0.3)}',
    '.so-cs-btn.so-cs-g:hover:not(:disabled){background:rgba(74,222,128,0.18);color:var(--g,#4ADE80)}',
    '.so-cs-dd{position:relative;display:inline-block}',
    '.so-cs-menu{position:absolute;right:0;top:calc(100% + 4px);min-width:190px;z-index:10040;display:none;',
    '  background:var(--s,#0F140F);border:1px solid rgba(139,92,246,0.35);border-radius:8px;padding:4px;',
    '  box-shadow:0 10px 30px rgba(0,0,0,0.55)}',
    '.so-cs-menu.open{display:block}',
    '.so-cs-menu button{display:block;width:100%;text-align:left;background:none;border:0;border-radius:5px;cursor:pointer;',
    '  color:var(--t,#E2E2EC);font-family:"JetBrains Mono",monospace;font-size:12px;padding:8px 10px}',
    '.so-cs-menu button:hover,.so-cs-menu button:focus{background:rgba(139,92,246,0.15);outline:none}',
    '.so-cs-menu button b{color:var(--pl,#A78BFA);display:inline-block;width:62px}',
    '.so-cs-ov{position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:10050;display:flex;align-items:center;justify-content:center;padding:16px}',
    '.so-cs-modal{width:100%;max-width:420px;background:var(--s,#0F140F);border:1px solid rgba(139,92,246,0.35);border-radius:10px;',
    '  padding:18px;color:var(--t,#E2E2EC);font-family:"JetBrains Mono",monospace;font-size:12px;box-shadow:0 20px 60px rgba(0,0,0,0.6)}',
    '.so-cs-modal h3{font-family:Rajdhani,sans-serif;font-size:17px;letter-spacing:2px;text-transform:uppercase;margin:0 0 4px;color:var(--t,#E2E2EC)}',
    '.so-cs-modal .so-cs-sub{color:var(--td,#9896AE);font-size:11px;margin-bottom:14px}',
    '.so-cs-modal label{display:block;font-size:10px;letter-spacing:2px;color:var(--tm,#6B6B80);margin:10px 0 5px;text-transform:uppercase}',
    '.so-cs-modal input,.so-cs-modal select{width:100%;box-sizing:border-box;background:var(--e,#1A1F1A);color:var(--t,#E2E2EC);',
    '  border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:8px 10px;font-family:"JetBrains Mono",monospace;font-size:12px;outline:none}',
    '.so-cs-modal input:focus,.so-cs-modal select:focus{border-color:rgba(139,92,246,0.55)}',
    '.so-cs-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px;flex-wrap:wrap}',
    '.so-cs-err{color:#F87171;font-size:11px;margin-top:10px;min-height:1em}',
    '.so-cs-toasts{position:fixed;right:16px;bottom:16px;z-index:10060;display:flex;flex-direction:column;gap:8px;max-width:calc(100vw - 32px)}',
    '.so-cs-toast{background:var(--s,#0F140F);border:1px solid rgba(74,222,128,0.4);border-left:3px solid var(--g,#4ADE80);border-radius:8px;',
    '  padding:10px 34px 10px 12px;color:var(--t,#E2E2EC);font-family:"JetBrains Mono",monospace;font-size:12px;position:relative;',
    '  box-shadow:0 10px 30px rgba(0,0,0,0.5);max-width:420px;line-height:1.6}',
    '.so-cs-toast.err{border-color:rgba(248,113,113,0.45);border-left-color:#F87171}',
    '.so-cs-toast a{color:var(--pl,#A78BFA);font-weight:600}',
    '.so-cs-toast .x{position:absolute;right:8px;top:6px;background:none;border:0;color:var(--td,#9896AE);cursor:pointer;font-size:14px}',
    '.so-cs-n{color:var(--g,#4ADE80)}.so-cs-o{color:#9CA3AF}.so-cs-c{color:#FBBF24}',
    '@media (max-width:600px){.so-cs-btn{min-height:34px}.so-cs-toasts{left:16px;right:16px}}'
  ].join('\n');

  function injectCss() {
    if (d.getElementById('so-cs-style')) return;
    var st = d.createElement('style');
    st.id = 'so-cs-style';
    st.textContent = CSS;
    (d.head || d.documentElement).appendChild(st);
  }

  /* ── Yardımcılar ────────────────────────────────────── */
  function api(method, url, body) {
    var opt = { method: method, headers: { 'Accept': 'application/json' } };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    return fetch(url, opt).then(function (r) {
      return r.json().catch(function () { return null; }).then(function (j) {
        if (!r.ok) throw new Error((j && j.error) || ('HTTP ' + r.status));
        return j;
      });
    });
  }

  /* Leaflet/DOM referansı, fonksiyon ve döngüsel yapıları atarak JSON üretir. */
  function devicesJson(list) {
    var seen = typeof WeakSet === 'function' ? new WeakSet() : null;
    return JSON.stringify(list, function (k, v) {
      if (typeof v === 'function') return undefined;
      if (v && typeof v === 'object') {
        if ((typeof Node !== 'undefined' && v instanceof Node) || v._leaflet_id != null || v._map) return undefined;
        if (seen) { if (seen.has(v)) return undefined; seen.add(v); }
      }
      return v;
    });
  }

  function currentDevices(opts) {
    var arr;
    try { arr = opts.getDevices ? opts.getDevices() : []; } catch (e) { arr = []; }
    if (!Array.isArray(arr)) return [];
    return arr.filter(function (x) { return x && typeof x === 'object'; }).slice(0, MAX_DEVICES);
  }

  function currentCenter(opts) {
    try {
      var c = opts.getCenter ? opts.getCenter() : null;
      if (!c) return null;
      var lat = Number(c.lat), lon = Number(c.lon != null ? c.lon : c.lng);
      if (!isFinite(lat) || !isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
      return { lat: lat, lon: lon };
    } catch (e) { return null; }
  }

  var toastBox = null;
  function toast(html, isErr, ms) {
    injectCss();
    if (!toastBox || !d.body.contains(toastBox)) {
      toastBox = d.createElement('div');
      toastBox.className = 'so-cs-toasts';
      toastBox.setAttribute('role', 'status');
      d.body.appendChild(toastBox);
    }
    var t = d.createElement('div');
    t.className = 'so-cs-toast' + (isErr ? ' err' : '');
    t.innerHTML = html + '<button class="x" type="button" aria-label="Close">✕</button>';
    t.querySelector('.x').addEventListener('click', function () { t.remove(); });
    toastBox.appendChild(t);
    setTimeout(function () { t.remove(); }, ms || (isErr ? 8000 : 10000));
    return t;
  }

  function diffSummary(scan, diff) {
    var c = (diff && diff.counts) || {};
    var s = 'Saved <b>#' + esc(scan.id) + '</b> · ' + esc(scan.device_count) + ' devices · ';
    if (c.baseline) return s + '<span class="so-cs-o">baseline</span> (first scan in this area)';
    return s + '<span class="so-cs-n">+' + (c.new | 0) + ' new</span> · <span class="so-cs-o">−' + (c.gone | 0) +
      ' gone</span> · <span class="so-cs-c">' + (c.changed | 0) + ' changed</span>';
  }

  function filenameFrom(res, fallback) {
    var cd = res.headers.get('Content-Disposition') || '';
    var m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
    var n = m ? decodeURIComponent(m[1]) : fallback;
    return n.replace(/[\\/:*?"<>|]+/g, '_');
  }

  function download(blob, name) {
    var url = URL.createObjectURL(blob);
    var a = d.createElement('a');
    a.href = url; a.download = name; a.style.display = 'none';
    d.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 2000);
  }

  /* ── Kaydet modalı ──────────────────────────────────── */
  function openSaveModal(opts, onDone) {
    var devices = currentDevices(opts);
    if (!devices.length) return;
    var center = currentCenter(opts);
    var ov = d.createElement('div');
    ov.className = 'so-cs-ov';
    var defLabel = (opts.title || opts.kind || 'Scan') + ' · ' + new Date().toLocaleString();
    ov.innerHTML =
      '<div class="so-cs-modal" role="dialog" aria-modal="true" aria-label="Save to case">' +
      '<h3>Save to case</h3>' +
      '<div class="so-cs-sub">' + esc(devices.length) + ' devices · ' + esc(opts.kind || 'other') +
      (center ? ' · ' + center.lat.toFixed(4) + ', ' + center.lon.toFixed(4) : '') + '</div>' +
      '<label for="so-cs-case">Case</label>' +
      '<select id="so-cs-case"><option value="">Loading…</option></select>' +
      '<div id="so-cs-new-wrap" style="display:none"><label for="so-cs-new">New case name</label>' +
      '<input id="so-cs-new" maxlength="200" placeholder="e.g. Operation Kadıköy"></div>' +
      '<label for="so-cs-label">Label (optional)</label>' +
      '<input id="so-cs-label" maxlength="200">' +
      '<div class="so-cs-err" id="so-cs-err"></div>' +
      '<div class="so-cs-actions">' +
      '<button type="button" class="so-cs-btn" data-act="cancel" style="color:var(--td,#9896AE);border-color:rgba(255,255,255,0.15);background:transparent">Cancel</button>' +
      '<button type="button" class="so-cs-btn so-cs-g" data-act="save">Save</button>' +
      '</div></div>';
    d.body.appendChild(ov);
    var sel = ov.querySelector('#so-cs-case'), newWrap = ov.querySelector('#so-cs-new-wrap'),
      newIn = ov.querySelector('#so-cs-new'), lblIn = ov.querySelector('#so-cs-label'),
      errEl = ov.querySelector('#so-cs-err'), saveBtn = ov.querySelector('[data-act="save"]');
    lblIn.value = defLabel;

    function close() { d.removeEventListener('keydown', onKey); ov.remove(); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    d.addEventListener('keydown', onKey);
    ov.addEventListener('mousedown', function (e) { if (e.target === ov) close(); });
    ov.querySelector('[data-act="cancel"]').addEventListener('click', close);
    sel.addEventListener('change', function () {
      newWrap.style.display = sel.value === '__new' ? 'block' : 'none';
      if (sel.value === '__new') newIn.focus();
    });

    api('GET', '/api/cases').then(function (j) {
      var open = ((j && j.cases) || []).filter(function (c) { return c.status !== 'closed'; });
      var last = ''; try { last = localStorage.getItem(LS_LAST_CASE) || ''; } catch (e) {}
      var html = '<option value="__new">New case…</option><option value="">— No case (unassigned) —</option>';
      open.forEach(function (c) {
        html += '<option value="' + esc(c.id) + '">' + esc(c.name) + ' (' + esc(c.scan_count) + ' scans)</option>';
      });
      sel.innerHTML = html;
      var hasLast = open.some(function (c) { return String(c.id) === last; });
      sel.value = hasLast ? last : (open.length ? String(open[0].id) : '__new');
      sel.dispatchEvent(new Event('change'));
    }).catch(function (e) {
      sel.innerHTML = '<option value="__new">New case…</option><option value="">— No case (unassigned) —</option>';
      sel.value = '__new'; sel.dispatchEvent(new Event('change'));
      errEl.textContent = 'Could not load cases: ' + e.message;
    });

    saveBtn.addEventListener('click', function () {
      errEl.textContent = '';
      var v = sel.value;
      var pre = Promise.resolve(v ? Number(v) : null);
      if (v === '__new') {
        var nm = newIn.value.trim();
        if (!nm) { errEl.textContent = 'Enter a case name.'; newIn.focus(); return; }
        pre = api('POST', '/api/cases', { name: nm }).then(function (j) { return j.case.id; });
      }
      saveBtn.disabled = true; saveBtn.textContent = 'Saving…';
      pre.then(function (caseId) {
        var body = '{"kind":' + JSON.stringify(opts.kind || 'other') +
          ',"label":' + JSON.stringify(lblIn.value.trim().slice(0, 200)) +
          ',"case_id":' + JSON.stringify(caseId || null) +
          (center ? ',"lat":' + center.lat + ',"lon":' + center.lon : '') +
          ',"params":' + JSON.stringify(Object.assign({ source_page: location.pathname, title: opts.title || '' },
                       (typeof opts.getParams === 'function' ? (opts.getParams() || {}) : {}))) +
          ',"devices":' + devicesJson(devices) + '}';
        return api('POST', '/api/scans', body).then(function (j) {
          try { if (caseId) localStorage.setItem(LS_LAST_CASE, String(caseId)); } catch (e) {}
          return j;
        });
      }).then(function (j) {
        close();
        toast(diffSummary(j.scan, j.diff) + '<br><a href="/cases?scan=' + encodeURIComponent(j.scan.id) + '">Open in Cases →</a>');
        if (onDone) onDone(j);
      }).catch(function (e) {
        saveBtn.disabled = false; saveBtn.textContent = 'Save';
        errEl.textContent = 'Save failed: ' + e.message;
      });
    });
    setTimeout(function () { sel.focus(); }, 0);
  }

  /* ── Dışa aktarma ───────────────────────────────────── */
  function doExport(opts, fmt, btn) {
    var devices = currentDevices(opts);
    if (!devices.length) return;
    var center = currentCenter(opts);
    var meta = { title: opts.title || 'SignalOps export', kind: opts.kind || 'other' };
    if (center) { meta.lat = center.lat; meta.lon = center.lon; }
    var orig = btn.textContent;
    btn.disabled = true; btn.textContent = '⏳ ' + fmt.toUpperCase() + '…';
    var body = '{"meta":' + JSON.stringify(meta) + ',"devices":' + devicesJson(devices) + '}';
    fetch('/api/export/' + encodeURIComponent(fmt), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body
    }).then(function (r) {
      if (!r.ok) return r.json().catch(function () { return null; }).then(function (j) {
        throw new Error((j && j.error) || ('HTTP ' + r.status));
      });
      return r.blob().then(function (b) { download(b, filenameFrom(r, 'signalops.' + fmt)); });
    }).catch(function (e) {
      toast('Export failed: ' + esc(e.message), true);
    }).then(function () { btn.disabled = false; btn.textContent = orig; });
  }

  /* ── attach ─────────────────────────────────────────── */
  function attach(container, opts) {
    if (!container) return null;
    opts = opts || {};
    injectCss();
    var bar = d.createElement('span');
    bar.className = 'so-cs-bar';
    bar.innerHTML =
      '<button type="button" class="so-cs-btn so-cs-g" data-so-save>Save to case</button>' +
      '<span class="so-cs-dd"><button type="button" class="so-cs-btn" data-so-export aria-haspopup="true" aria-expanded="false">Export ▾</button>' +
      '<span class="so-cs-menu" role="menu">' + FORMATS.map(function (f) {
        return '<button type="button" role="menuitem" data-fmt="' + f[0] + '"><b>' + f[0].toUpperCase() + '</b>' + esc(f[1].replace(/^\S+\s?/, '')) + '</button>';
      }).join('') + '</span></span>';
    container.appendChild(bar);
    var saveBtn = bar.querySelector('[data-so-save]'), expBtn = bar.querySelector('[data-so-export]'),
      menu = bar.querySelector('.so-cs-menu');

    function refresh() {
      var n = currentDevices(opts).length;
      var off = n === 0;
      saveBtn.disabled = off; expBtn.disabled = off;
      var hint = off ? 'Run a scan first — no results yet (önce tarama yap)' : '';
      bar.title = hint;
      saveBtn.title = off ? hint : 'Save these ' + n + ' results as a scan (change detection vs. the last scan here)';
      expBtn.title = off ? hint : 'Export ' + n + ' results';
      if (off) closeMenu();
    }
    function closeMenu() { menu.classList.remove('open'); expBtn.setAttribute('aria-expanded', 'false'); }
    saveBtn.addEventListener('click', function () { refresh(); if (!saveBtn.disabled) openSaveModal(opts); });
    expBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      var open = !menu.classList.contains('open');
      menu.classList.toggle('open', open);
      expBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        // Sağa taşıyorsa sola hizala
        menu.style.right = '0'; menu.style.left = 'auto';
        var r = menu.getBoundingClientRect();
        if (r.left < 8) { menu.style.left = '0'; menu.style.right = 'auto'; }
      }
    });
    menu.addEventListener('click', function (e) {
      var b = e.target.closest('button[data-fmt]');
      if (!b) return;
      closeMenu();
      doExport(opts, b.getAttribute('data-fmt'), expBtn);
    });
    function outside(e) { if (!bar.contains(e.target)) closeMenu(); }
    function onKey(e) { if (e.key === 'Escape') closeMenu(); }
    d.addEventListener('click', outside);
    d.addEventListener('keydown', onKey);
    bar.addEventListener('mouseenter', refresh);
    var timer = setInterval(function () { if (!d.hidden) refresh(); }, 1200);
    refresh();
    return {
      refresh: refresh,
      destroy: function () {
        clearInterval(timer);
        d.removeEventListener('click', outside);
        d.removeEventListener('keydown', onKey);
        bar.remove();
      }
    };
  }

  w.SignalOpsCase = { attach: attach, toast: toast, api: api };
})(window, document);
