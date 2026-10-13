/* SignalOps — ortak güvenli render yardımcıları (XSS koruması).
   Tüm sayfalarda <head> içinde yüklenir. API'den gelen her metin
   innerHTML / template string içine girmeden önce escapeHtml()'den geçmeli. */
(function (w) {
  var MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
  function escapeHtml(v) {
    if (v === null || v === undefined) return '';
    return String(v).replace(/[&<>"'`]/g, function (c) { return MAP[c]; });
  }
  /* Sadece http/https/göreli URL'lere izin verir; javascript:, data: vb. → '#' */
  function safeUrl(v) {
    if (!v) return '';
    var s = String(v).trim();
    if (/^(https?:)?\/\//i.test(s) || /^\/(?!\/)/.test(s)) return escapeHtml(s);
    return '#';
  }
  w.escapeHtml = escapeHtml;
  w.esc = escapeHtml;
  w.safeUrl = safeUrl;
})(window);

/* Inline stroke icons used by scripts that swap button content (replaces old emoji glyphs) */
window.SO_PIN = '<svg class="so-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>';
