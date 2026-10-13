/* SignalOps — harita altlığı uyumluluğu.
   CARTO basemaps (basemaps.cartocdn.com) Ağustos 2026'dan beri API anahtarı istiyor; anahtarsız
   isteklerde "API KEY REQUIRED" filigranı çıkıyor. Bu script Leaflet yüklenirken L.tileLayer'ı sarar:
     - Settings'te CARTO anahtarı varsa → CARTO URL'lerine ?key=… eklenir (orijinal görünüm).
     - Yoksa → anahtarsız OpenStreetMap'e geçilir; koyu (dark_all) katmanlar CSS filtresiyle koyulaştırılır.
   Sayfa kodları değişmez. Leaflet'ten ÖNCE yüklenmeli. */
(function (w) {
  var KEY = (w.SO_CARTO_KEY || '').trim();
  var OSM = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
  var OSM_ATTR = '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors';

  function rewrite(url, opts) {
    opts = Object.assign({}, opts || {});
    if (typeof url !== 'string' || url.indexOf('basemaps.cartocdn.com') === -1) return [url, opts];
    if (KEY) {
      return [url + (url.indexOf('?') === -1 ? '?' : '&') + 'key=' + encodeURIComponent(KEY), opts];
    }
    var dark = /dark_all|dark_nolabels|dark_only_labels|dark-matter/i.test(url);
    opts.subdomains = 'abc';
    opts.attribution = OSM_ATTR;
    if (opts.maxZoom && opts.maxZoom > 19) opts.maxZoom = 19;
    if (opts.maxNativeZoom === undefined) opts.maxNativeZoom = 19;
    if (dark) opts.className = ((opts.className || '') + ' so-dark-tiles').trim();
    return [OSM, opts];
  }

  function patch(L) {
    if (!L || L.__soTilesPatched || typeof L.tileLayer !== 'function') return L;
    var orig = L.tileLayer;
    var wrapped = function (url, opts) { var r = rewrite(url, opts); return orig.call(this, r[0], r[1]); };
    for (var k in orig) { if (Object.prototype.hasOwnProperty.call(orig, k)) wrapped[k] = orig[k]; }
    L.tileLayer = wrapped;
    L.__soTilesPatched = true;
    return L;
  }

  // Koyu tema filtresi (sadece anahtarsız modda kullanılır)
  try {
    var st = document.createElement('style');
    st.textContent = '.so-dark-tiles{filter:invert(1) hue-rotate(180deg) brightness(.82) contrast(.92) saturate(.55)}';
    (document.head || document.documentElement).appendChild(st);
  } catch (e) {}

  if (w.L) { patch(w.L); return; }
  var _L;
  try {
    Object.defineProperty(w, 'L', {
      configurable: true, enumerable: true,
      get: function () { return _L; },
      set: function (v) { _L = v; patch(v); }
    });
  } catch (e) {
    // defineProperty mümkün değilse Leaflet yüklendikten sonra yamala
    document.addEventListener('DOMContentLoaded', function () { patch(w.L); });
  }
})(window);
