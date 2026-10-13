/* SignalOps — sidebar shell: mobile drawer + live backend status.
   Works with templates/_sidebar.html; pages keep their own .topnav as a slim header. */
(function () {
  function init() {
    var side = document.getElementById('so-side');
    var nav = document.querySelector('.topnav');
    if (side) document.body.classList.add('so-shell');
    if (nav) {
      var syncHeight = function () {
        document.documentElement.style.setProperty('--so-nav-h', Math.round(nav.getBoundingClientRect().height) + 'px');
      };
      syncHeight();
      window.addEventListener('resize', syncHeight);
    }
    if (!side || !nav) return;

    var scrim = document.getElementById('so-side-scrim');
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'so-burger';
    btn.setAttribute('aria-label', 'Menu');
    btn.setAttribute('aria-controls', 'so-side');
    btn.setAttribute('aria-expanded', 'false');
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>';
    nav.insertBefore(btn, nav.firstChild);

    function setOpen(on) {
      document.body.classList.toggle('so-side-open', on);
      btn.setAttribute('aria-expanded', on ? 'true' : 'false');
      if (scrim) scrim.hidden = !on;
    }
    btn.addEventListener('click', function (e) { e.stopPropagation(); setOpen(!document.body.classList.contains('so-side-open')); });
    if (scrim) scrim.addEventListener('click', function () { setOpen(false); });
    side.addEventListener('click', function (e) { if (e.target.closest('a')) setOpen(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') setOpen(false); });
    window.addEventListener('resize', function () { if (window.innerWidth > 900) setOpen(false); });

    var active = side.querySelector('.so-nav-a.is-active');
    if (active && active.scrollIntoView) active.scrollIntoView({ block: 'nearest' });
  }

  // Live status: [data-so-live] elements follow /api/status
  function pollStatus() {
    var els = document.querySelectorAll('[data-so-live]');
    if (!els.length) return;
    fetch('/api/status', { cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (d) {
      var keyed = (d.active || []).filter(function (k) { return k !== 'Insecam' && k !== 'EarthCam'; }).length;
      var total = keyed + (d.missing || []).length;
      var net = d.net_mode === 'tor' ? 'Tor' : d.net_mode === 'custom' ? 'proxy' : 'direct';
      els.forEach(function (el) {
        var dot = el.querySelector('.so-live-dot, .dot');
        var txt = el.querySelector('[data-so-live-text]') || el.querySelector('span:last-child');
        if (dot) { dot.classList.remove('off'); dot.classList.toggle('warn', keyed === 0); }
        if (txt) txt.textContent = el.dataset.soLive === 'short' ? 'Online' : 'Online · ' + keyed + '/' + total + ' keys' + (net !== 'direct' ? ' · ' + net : '');
        el.title = 'Backend online · ' + keyed + ' API keys active · traffic: ' + net;
      });
    }).catch(function () {
      els.forEach(function (el) {
        var dot = el.querySelector('.so-live-dot, .dot');
        var txt = el.querySelector('[data-so-live-text]') || el.querySelector('span:last-child');
        if (dot) { dot.classList.add('off'); dot.classList.remove('warn'); }
        if (txt) txt.textContent = 'Offline';
        el.title = 'Backend is not responding';
      });
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { init(); pollStatus(); });
  else { init(); pollStatus(); }
  setInterval(pollStatus, 60000);
  window.soNavRefresh = pollStatus;
})();
