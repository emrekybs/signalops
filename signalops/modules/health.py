"""
SignalOps — sağlayıcı sağlık katmanı (provider health).

Ücretli API'lerin kotası bittiğinde / anahtar geçersiz olduğunda / hız sınırına
takıldığında platform çalışmaya devam etsin diye merkezi bir koruma:

* install() → requests.sessions.Session.request'i TEK bir sarmalayıcıyla değiştirir
  (requests.get/post ve Session'lar dahil). Sarmalayıcı:
    - çağrıdan ÖNCE: URL'nin sağlayıcısı şu an engelliyse ağa hiç çıkmadan
      ProviderUnavailable (requests.RequestException alt sınıfı) fırlatır →
      mevcut `except Exception` yolları [] döndürür.
    - çağrıdan SONRA: yanıtı sınıflandırır (429 → cooldown, 402/kota → quota,
      401/403 → auth, 5xx/bağlantı hatası ×3 → down).
* Durumlar: ok | cooldown | quota | auth | down
* Anahtarlar asla loglanmaz (URL'lerin query string'i atılır).
"""
import json
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import requests

# (etiket, KEY_SCHEMA sağlayıcı-id, hostlar) — etiketler /api/status ve dashboard ile aynı
PROVIDERS = [
    ("Shodan",     "shodan",     ("api.shodan.io",)),
    ("FOFA",       "fofa",       ("fofa.info",)),
    ("Censys",     "censys",     ("search.censys.io",)),
    ("ZoomEye",    "zoomeye",    ("api.zoomeye.ai", "api.zoomeye.org")),
    ("Hunter.how", "hunterhow",  ("api.hunter.how",)),
    ("Netlas",     "netlas",     ("app.netlas.io",)),
    ("LeakIX",     "leakix",     ("leakix.net",)),
    ("CriminalIP", "criminalip", ("api.criminalip.io",)),
    ("BinaryEdge", "binaryedge", ("api.binaryedge.io",)),
    ("Windy",      "windy",      ("api.windy.com",)),
    ("WiGLE",      "wigle",      ("api.wigle.net",)),
    ("OpenCellID", "opencellid", ("opencellid.org",)),
    ("AbuseIPDB",  "abuseipdb",  ("api.abuseipdb.com",)),
    ("Gemini",     "gemini",     ("generativelanguage.googleapis.com",)),
    ("APRS.fi",    "aprs",       ("api.aprs.fi",)),
]
HOST_MAP = {h: label for label, _pid, hosts in PROVIDERS for h in hosts}
ID_TO_LABEL = {pid: label for label, pid, _h in PROVIDERS}
LABELS = [p[0] for p in PROVIDERS]

COOLDOWN_429 = 15 * 60
COOLDOWN_429_CAP = 6 * 3600
DOWN_AFTER = 3
DOWN_COOLDOWN = 5 * 60
QUOTA_CAP = 24 * 3600

_QUOTA_WORDS = ("credit", "quota", "limit", "balance", "insufficient", "exceed",
                "余额", "不足", "f点", "次数")
_RATE_WORDS = ("rate limit", "too many requests", "ratelimit")
_AUTH_WORDS = ("key", "auth", "invalid", "unauthor", "forbidden", "账号", "email", "token", "-700")


class ProviderUnavailable(requests.RequestException):
    """Sağlayıcı geçici olarak devre dışı (kota/yetki/cooldown) — ağa çıkılmadı."""
    def __init__(self, provider, state, reason="", until=None):
        self.provider, self.state, self.reason, self.until = provider, state, reason, until
        when = ""
        if until:
            when = " until " + datetime.fromtimestamp(until, timezone.utc).strftime("%H:%M UTC")
        super().__init__(f"{provider} unavailable ({state}{when}): {reason}"[:240])


_lock = threading.RLock()
_state = {}                 # label → dict
_tls = threading.local()
_key_fp_fn = None           # label → anahtar parmak izi (anahtar değişince auth bloğu kalkar)
_orig_request = None


def _blank():
    return {"state": "ok", "reason": "", "until": None, "last_error": None,
            "last_ok": None, "fails": 0, "fp": None, "last_change": None}


def provider_for_url(url):
    try:
        host = (urlsplit(str(url)).hostname or "").lower()
    except Exception:
        return None
    if not host:
        return None
    if host in HOST_MAP:
        return HOST_MAP[host]
    for h, label in HOST_MAP.items():
        if host.endswith("." + h):
            return label
    return None


def safe_url(url):
    """Loglama için: query string ve kullanıcı bilgisi atılır (anahtarlar sızmasın)."""
    try:
        p = urlsplit(str(url))
        return f"{p.scheme}://{p.hostname or ''}{p.path}"
    except Exception:
        return "<url>"


def set_key_fingerprint_fn(fn):
    global _key_fp_fn
    _key_fp_fn = fn


def _fp(label):
    try:
        return _key_fp_fn(label) if _key_fp_fn else None
    except Exception:
        return None


def _next_0005_utc(now):
    d = datetime.fromtimestamp(now, timezone.utc)
    t = d.replace(hour=0, minute=5, second=0, microsecond=0)
    if t <= d:
        t += timedelta(days=1)
    return min(t.timestamp(), now + QUOTA_CAP)


def _parse_retry_after(v, now):
    if not v:
        return None
    v = str(v).strip()
    try:
        secs = float(v)
    except ValueError:
        try:
            secs = parsedate_to_datetime(v).timestamp() - now
        except Exception:
            return None
    return max(1.0, min(float(secs), COOLDOWN_429_CAP))


def _effective(label, s, now=None):
    """Süresi dolmuş blokları kaldırır, anahtarı değişen auth bloğunu temizler (lock altında)."""
    now = now or time.time()
    if s["state"] in ("cooldown", "quota", "down") and s["until"] and now >= s["until"]:
        s["state"], s["reason"], s["until"] = "ok", "", None
    elif s["state"] == "auth" and s.get("fp") is not None and _fp(label) != s["fp"]:
        s["state"], s["reason"], s["until"], s["fails"] = "ok", "", None, 0
    return s


def _get(label):
    s = _state.get(label)
    if s is None:
        s = _state[label] = _blank()
    return s


def blocked(label):
    """Engelliyse (state, reason, until), değilse None."""
    if not label:
        return None
    with _lock:
        s = _state.get(label)
        if not s:
            return None
        _effective(label, s)
        if s["state"] == "ok":
            return None
        return s["state"], s["reason"], s["until"]


def is_blocked(label):
    return blocked(label) is not None


def _block(label, state, reason, until):
    with _lock:
        s = _get(label)
        prev = s["state"]
        s.update(state=state, reason=str(reason)[:200], until=until, last_error=str(reason)[:200],
                 last_change=time.time())
        if state == "auth":
            s["fp"] = _fp(label)
    if prev != state:
        u = (" until " + datetime.fromtimestamp(until, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")) if until else ""
        print(f"[health] {label}: {state}{u} — {str(reason)[:120]}")


def record_ok(label):
    with _lock:
        s = _get(label)
        s["last_ok"] = time.time()
        s["fails"] = 0
        if s["state"] != "ok":            # başarılı yanıt (ör. ayar testi) → engel kalkar
            s.update(state="ok", reason="", until=None, fp=None, last_change=time.time())


def record_failure(label, reason):
    """5xx / bağlantı hatası: art arda DOWN_AFTER kez → 5 dk down."""
    with _lock:
        s = _get(label)
        s["fails"] += 1
        s["last_error"] = str(reason)[:200]
        n = s["fails"]
    if n >= DOWN_AFTER:
        _block(label, "down", f"{n} consecutive failures: {reason}", time.time() + DOWN_COOLDOWN)


def record_error(label, reason):
    with _lock:
        _get(label)["last_error"] = str(reason)[:200]


def classify(label, status, body_text="", headers=None, now=None):
    """HTTP durum kodu + gövde → sağlık durumu güncellemesi. Engel kurulduysa state döner."""
    now = now or time.time()
    body = (body_text or "")[:4000]
    low = body.lower()
    short = " ".join(body.split())[:140]
    headers = headers or {}
    if status == 429:
        secs = _parse_retry_after(headers.get("Retry-After"), now) or COOLDOWN_429
        _block(label, "cooldown", f"HTTP 429 rate limited{(': ' + short) if short else ''}", now + secs)
        return "cooldown"
    if status == 402 or (status in (401, 403) and any(w in low for w in _QUOTA_WORDS)) \
            or "insufficient query credits" in low:
        if status in (401, 403) and any(w in low for w in _RATE_WORDS):
            _block(label, "cooldown", f"HTTP {status} rate limited: {short}", now + COOLDOWN_429)
            return "cooldown"
        _block(label, "quota", f"HTTP {status} quota exhausted{(': ' + short) if short else ''}", _next_0005_utc(now))
        return "quota"
    if status in (401, 403):
        _block(label, "auth", f"HTTP {status} auth failed{(': ' + short) if short else ''}", None)
        return "auth"
    if status >= 500:
        record_failure(label, f"HTTP {status}")
        return None
    record_ok(label)
    return None


def classify_fofa_error(label, errmsg, now=None):
    """FOFA HTTP 200 + {"error":true,"errmsg":...} — sadece kota/yetki hatalarında engeller."""
    now = now or time.time()
    msg = str(errmsg or "")
    low = msg.lower()
    if any(w in low for w in _QUOTA_WORDS):
        _block(label, "quota", f"quota exhausted: {msg[:140]}", _next_0005_utc(now))
        return "quota"
    if any(w in low for w in _AUTH_WORDS):
        _block(label, "auth", f"auth failed: {msg[:140]}", None)
        return "auth"
    record_error(label, msg[:140])     # sorgu sözdizimi vb. — engelleme yok
    return None


def classify_exception(label, exc):
    """SDK istisnaları (ör. google-genai) için: koddan/mesajdan durum çıkar."""
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    try:
        code = int(code)
    except (TypeError, ValueError):
        code = None
    msg = str(exc)
    if code is None:
        low = msg.lower()
        if "resource_exhausted" in low or " 429" in low:
            code = 429
        elif "permission_denied" in low or "api key not valid" in low:
            code = 403
        elif "unavailable" in low or "internal" in low:
            code = 503
    if code is None:
        record_failure(label, type(exc).__name__)
        return None
    if code == 429 and any(w in msg.lower() for w in ("per day", "perday", "daily")):
        _block(label, "quota", f"daily quota exhausted: {' '.join(msg.split())[:140]}", _next_0005_utc(time.time()))
        return "quota"
    return classify(label, code, msg)


def reset(label=None):
    with _lock:
        if label is None:
            _state.clear()
            return True
        if label not in LABELS:
            return False
        s = _get(label)
        s.update(state="ok", reason="", until=None, fails=0, fp=None, last_change=time.time())
    print(f"[health] {label}: reset")
    return True


def reset_provider_ids(ids):
    for pid in set(ids):
        label = ID_TO_LABEL.get(pid)
        if label:
            with _lock:
                had = label in _state and _state[label]["state"] != "ok"
            if had:
                reset(label)


def snapshot():
    out = {}
    now = time.time()
    with _lock:
        for label in LABELS:
            s = _state.get(label)
            if not s:
                out[label] = {"state": "ok", "reason": "", "until": None, "last_error": None,
                              "last_ok": None, "fails": 0}
                continue
            _effective(label, s, now)
            out[label] = {k: s[k] for k in ("state", "reason", "until", "last_error", "last_ok", "fails")}
    return out


def degraded():
    return {k: {"state": v["state"], "reason": v["reason"], "until": v["until"]}
            for k, v in snapshot().items() if v["state"] != "ok"}


@contextmanager
def probe():
    """Engeli atla (ayar testi / 'Retry now'): istek gider, sonuç yine sınıflandırılır."""
    prev = getattr(_tls, "bypass", False)
    _tls.bypass = True
    try:
        yield
    finally:
        _tls.bypass = prev


def _peek_body(resp, stream):
    if stream:
        return ""
    try:
        return resp.text[:4000]
    except Exception:
        return ""


def _wrapped_request(self, method, url, *args, **kwargs):
    label = provider_for_url(url)
    if label is None:
        return _orig_request(self, method, url, *args, **kwargs)
    if not getattr(_tls, "bypass", False):
        b = blocked(label)
        if b:
            raise ProviderUnavailable(label, *b)
    try:
        resp = _orig_request(self, method, url, *args, **kwargs)
    except requests.RequestException as e:
        if isinstance(e, (requests.ConnectionError, requests.Timeout)):
            record_failure(label, type(e).__name__)
        raise
    try:
        stream = bool(kwargs.get("stream"))
        st = resp.status_code
        if st in (401, 402, 403, 429) or st >= 500:
            classify(label, st, _peek_body(resp, stream), resp.headers)
        elif label == "FOFA" and st == 200 and not stream:
            # FOFA kota/yetki hatalarını HTTP 200 + {"error":true} ile döndürür.
            # resp.content önbelleğe alınır → çağıran r.json()'ı yine kullanabilir.
            j = None
            try:
                j = json.loads(resp.content or b"null")
            except Exception:
                pass
            if isinstance(j, dict) and j.get("error"):
                classify_fofa_error(label, j.get("errmsg"))
            else:
                record_ok(label)
        elif 200 <= st < 400:
            record_ok(label)
        else:
            with _lock:
                _get(label)["fails"] = 0          # sunucu yanıt verdi (400/404 vb.) — engel yok
    except Exception as e:                        # sınıflandırma hiçbir zaman çağrıyı bozmasın
        print(f"[health] classify error for {safe_url(url)}: {type(e).__name__}")
    return resp


def install():
    """Session.request sarmalayıcısını bir kez kurar (tekrar çağrılırsa no-op)."""
    global _orig_request
    cur = requests.sessions.Session.request
    if getattr(cur, "_so_health", False):
        return False
    _orig_request = cur
    _wrapped_request._so_health = True
    requests.sessions.Session.request = _wrapped_request
    return True


# ══════════════════════════════════════════════
#  Flask uç noktaları
# ══════════════════════════════════════════════
def init(app, ctx):
    from flask import Blueprint, jsonify, request
    if "health" in app.blueprints:
        return
    bp = Blueprint("health", __name__)
    rl = getattr(ctx, "rate_limit", None) or (lambda spec: (lambda f: f))

    def api_health():
        return jsonify(snapshot())

    def api_health_reset():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "JSON body {provider} required"}), 400
        prov = str(body.get("provider") or "")[:40]
        if prov == "*":
            reset(None)
            return jsonify({"ok": True, "provider": "*"})
        if prov not in LABELS:
            # id da kabul et (ör. "shodan")
            prov = ID_TO_LABEL.get(prov, prov)
        if not reset(prov):
            return jsonify({"ok": False, "error": "Unknown provider"}), 400
        return jsonify({"ok": True, "provider": prov, "health": snapshot()[prov]})

    bp.add_url_rule("/api/providers/health", "api_health", api_health)
    bp.add_url_rule("/api/providers/health/reset", "api_health_reset",
                    rl("30 per minute")(api_health_reset), methods=["POST"])
    app.register_blueprint(bp)
