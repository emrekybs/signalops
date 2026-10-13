"""
SignalOps — Alan izleme (Area Monitor).

Kullanıcı haritada bir çokgen çizer; zamanlayıcı her N dakikada bir alanı tarar, sonucu
store.save_scan ile kaydeder (area_key = "monitor:<id>"), bir önceki çalıştırmayla farkını
çıkarır ve kurallara göre webhook bildirimi gönderir.

Tasarım
  * Tek zamanlayıcı iş parçacığı (daemon). Birden çok süreç (gunicorn worker) varsa
    config_dir içindeki kilit dosyasını (fcntl.flock) alan tek süreç zamanlayıcıyı çalıştırır.
  * Çalıştırmalar asla eşzamanlı değil: _exec_lock tüm çalıştırmaları (zamanlayıcı + "Run now")
    sıraya sokar. Bir izleme zaten çalışıyor/sırada ise "Run now" 409 döner.
  * Çokgen veya tür değişirse sonraki çalıştırma yeni temel (baseline) sayılır
    (scan params içindeki "geom" özeti karşılaştırılır).
  * Gizli değerler (bot token, webhook URL) asla loglanmaz — _redact().
"""
import os, json, time, math, threading, hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Blueprint, jsonify, request, render_template

from . import store

bp = Blueprint("monitor", __name__)

KINDS = ("nearby", "cell", "cctv", "adsb")
INTERVALS_MIN, INTERVALS_MAX = 15, 1440
MAX_VERTICES = 100
MAX_SPAN_KM = 50.0
MAX_NAME = 100
TICK_SECONDS = 30
MSG_MAX = 3500
TOP_ITEMS = 10
HIGH_RISK = 70

NOTIFY_DEFAULTS = {
    "webhook": False,
    "on_watchlist": True, "on_new": True, "on_gone": False, "on_changed": False,
    "min_risk": 0, "quiet_baseline": True,
}

_ctx = None
_state_lock = threading.Lock()
_running = {}                 # monitor_id → "queued" | "running"
_exec_lock = threading.Lock()  # tüm çalıştırmaları sıraya sokar
_scheduler_started = False
_scheduler_thread = None
_lock_fd = None
_clock = time.time             # testlerde değiştirilebilir

def _now():
    return int(_clock())

# ── Gizli değer maskeleme / log ──────────────────────────
def _mask(v):
    v = str(v or "")
    if not v:
        return ""
    if len(v) <= 6:
        return "•" * len(v)
    return "•" * min(12, len(v) - 4) + v[-4:]

def _secrets():
    if not _ctx:
        return []
    out = []
    for k in ("NOTIFY_WEBHOOK_URL",):
        try:
            v = _ctx.get_key(k) or ""
        except Exception:
            v = ""
        if len(v) >= 4:
            out.append(v)
    return out

def _redact(text):
    s = str(text or "")
    for sec in _secrets():
        if sec in s:
            s = s.replace(sec, _mask(sec))
    return s

def _log(msg):
    print(f"[monitor] {_redact(msg)}")

# ── Geometri ─────────────────────────────────────────────
def _hav_km(a_lat, a_lon, b_lat, b_lon):
    r = 6371.0088
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp = p2 - p1
    dl = math.radians(b_lon - a_lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))

def centroid(poly):
    """Alan ağırlıklı merkez (düzlemsel yaklaşım; ≤50 km için yeterli). Dejenere ise köşe ortalaması."""
    n = len(poly)
    oy, ox = poly[0]                       # ilk köşeye göre → sayısal hassasiyet
    a = cx = cy = 0.0
    for i in range(n):
        y0, x0 = poly[i][0] - oy, poly[i][1] - ox
        y1, x1 = poly[(i + 1) % n][0] - oy, poly[(i + 1) % n][1] - ox
        cr = x0 * y1 - x1 * y0
        a += cr
        cx += (x0 + x1) * cr
        cy += (y0 + y1) * cr
    if abs(a) < 1e-12:
        return (sum(p[0] for p in poly) / n, sum(p[1] for p in poly) / n)
    a *= 0.5
    return (oy + cy / (6 * a), ox + cx / (6 * a))

def radius_km(poly, c=None):
    c = c or centroid(poly)
    return max(_hav_km(c[0], c[1], p[0], p[1]) for p in poly)

def point_in_polygon(lat, lon, poly):
    """Ray casting (x = lon, y = lat)."""
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        yi, xi = poly[i]
        yj, xj = poly[j]
        if (yi > lat) != (yj > lat):
            x_cross = (xj - xi) * (lat - yi) / (yj - yi) + xi
            if lon < x_cross:
                inside = not inside
        j = i
    return inside

def bbox_km(poly):
    lats = [p[0] for p in poly]
    lons = [p[1] for p in poly]
    mid = math.radians((min(lats) + max(lats)) / 2)
    h = (max(lats) - min(lats)) * 111.32
    w = (max(lons) - min(lons)) * 111.32 * max(0.01, math.cos(mid))
    return w, h

def _geom_sig(poly, kind):
    raw = json.dumps([kind, [[round(a, 6), round(b, 6)] for a, b in poly]])
    return hashlib.sha1(raw.encode()).hexdigest()[:12]

# ── Doğrulama ────────────────────────────────────────────
class VErr(ValueError):
    pass

def _num(v):
    if isinstance(v, bool):
        raise VErr("number expected")
    x = float(v)
    if not math.isfinite(x):
        raise VErr("number expected")
    return x

def _v_polygon(p):
    if not isinstance(p, list):
        raise VErr("polygon must be a list of [lat, lon] points")
    if len(p) < 3:
        raise VErr("polygon needs at least 3 points")
    if len(p) > MAX_VERTICES:
        raise VErr(f"polygon may have at most {MAX_VERTICES} points")
    out = []
    for pt in p:
        if not isinstance(pt, (list, tuple)) or len(pt) != 2:
            raise VErr("each polygon point must be [lat, lon]")
        try:
            la, lo = _num(pt[0]), _num(pt[1])
        except (TypeError, ValueError):
            raise VErr("polygon coordinates must be numbers")
        if not (-90 <= la <= 90) or not (-180 <= lo <= 180):
            raise VErr("polygon coordinate out of range")
        out.append([round(la, 7), round(lo, 7)])
    if out[0] == out[-1] and len(out) > 3:
        out = out[:-1]          # kapalı halka gönderildiyse son tekrarı at
    if len({(a, b) for a, b in out}) < 3:
        raise VErr("polygon needs at least 3 distinct points")
    w, h = bbox_km(out)
    if w > MAX_SPAN_KM or h > MAX_SPAN_KM:
        raise VErr(f"area too large ({w:.0f}×{h:.0f} km) — max {MAX_SPAN_KM:.0f}×{MAX_SPAN_KM:.0f} km. "
                   "Scan sources are local (WiFi/BT/cell ~1–2 km around the centre); draw a smaller area.")
    return out

def _v_notify(n, base=None):
    out = dict(NOTIFY_DEFAULTS)
    if base:
        out.update({k: base[k] for k in NOTIFY_DEFAULTS if k in base})
    if n is None:
        return out
    if not isinstance(n, dict):
        raise VErr("notify must be an object")
    for k, v in n.items():
        if k not in NOTIFY_DEFAULTS:
            continue
        if k == "min_risk":
            try:
                iv = int(_num(v))
            except (TypeError, ValueError):
                raise VErr("notify.min_risk must be 0–100")
            if not 0 <= iv <= 100:
                raise VErr("notify.min_risk must be 0–100")
            out[k] = iv
        else:
            if not isinstance(v, bool):
                raise VErr(f"notify.{k} must be true/false")
            out[k] = v
    return out

def _validate(body, partial=False, current=None):
    if not isinstance(body, dict):
        raise VErr("JSON object expected")
    out = {}
    if "name" in body or not partial:
        name = body.get("name")
        if not isinstance(name, str) or not name.strip():
            raise VErr("name is required")
        name = " ".join(name.split())
        if len(name) > MAX_NAME:
            raise VErr(f"name may be at most {MAX_NAME} characters")
        out["name"] = name
    if "polygon" in body or not partial:
        out["polygon"] = _v_polygon(body.get("polygon"))
    if "kind" in body or not partial:
        kind = body.get("kind", "nearby")
        if kind not in KINDS:
            raise VErr(f"kind must be one of: {', '.join(KINDS)}")
        out["kind"] = kind
    if "interval_min" in body or not partial:
        try:
            iv = body.get("interval_min", 60)
            if isinstance(iv, bool):
                raise ValueError
            iv = int(iv) if isinstance(iv, int) else int(_num(iv))
        except (TypeError, ValueError):
            raise VErr("interval_min must be an integer")
        if iv < INTERVALS_MIN or iv > INTERVALS_MAX:
            raise VErr(f"interval_min must be between {INTERVALS_MIN} and {INTERVALS_MAX}")
        out["interval_min"] = iv
    if "enabled" in body or not partial:
        en = body.get("enabled", True)
        if not isinstance(en, bool):
            raise VErr("enabled must be true/false")
        out["enabled"] = en
    if "case_id" in body or not partial:
        cid = body.get("case_id")
        if cid in (None, "", 0):
            out["case_id"] = None
        else:
            if isinstance(cid, bool):
                raise VErr("case_id must be an integer")
            try:
                cid = int(cid)
            except (TypeError, ValueError):
                raise VErr("case_id must be an integer")
            with store.db() as c:
                if not c.execute("SELECT 1 FROM cases WHERE id=?", (cid,)).fetchone():
                    raise VErr(f"case {cid} not found")
            out["case_id"] = cid
    if "notify" in body or not partial:
        out["notify"] = _v_notify(body.get("notify"), (current or {}).get("notify"))
    return out

# ── DB yardımcıları ──────────────────────────────────────
def _get(mid):
    with store.db() as c:
        return store.row(c.execute("SELECT * FROM monitors WHERE id=?", (mid,)).fetchone())

def _public(m, last_event=None):
    if not m:
        return None
    m = dict(m)
    m["enabled"] = bool(m.get("enabled"))
    m["notify"] = _v_notify(None, m.get("notify") if isinstance(m.get("notify"), dict) else {})
    with _state_lock:
        m["running"] = _running.get(m["id"])
    if last_event is not None:
        m["last_event"] = last_event
    return m

def _next_run_after_change(m, now_ts):
    """Etkinleştirme / periyot değişimi: son çalıştırmaya göre hesapla, geçmişe düşerse şimdi."""
    if m.get("last_run"):
        return max(now_ts, int(m["last_run"]) + int(m["interval_min"]) * 60)
    return now_ts

# ── Tarama ───────────────────────────────────────────────
def _scan(kind, lat, lon, rad_km):
    if kind == "nearby":
        return _ctx.run_parallel(lat, lon)
    if kind == "cell":
        return _ctx.run_cell_scan(lat, lon)
    if kind == "cctv":
        return _ctx.run_camera_scan(lat, lon)
    if kind == "adsb":
        r = max(5, min(int(math.ceil(rad_km)), 460))
        ac = _ctx.fetch_aircraft(lat, lon, r) or []
        try:
            ac = _ctx.apply_risk(ac)
        except Exception:
            pass
        return ac
    raise ValueError(f"unknown kind {kind}")

def _f(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None

def filter_devices(devices, poly):
    inside, approx, noloc, outside = [], 0, 0, 0
    for d in devices or []:
        if not isinstance(d, dict):
            continue
        if d.get("approx"):
            approx += 1
            continue
        la, lo = _f(d.get("lat")), _f(d.get("lon"))
        if la is None or lo is None:
            noloc += 1
            continue
        if point_in_polygon(la, lo, poly):
            inside.append(d)
        else:
            outside += 1
    return inside, {"skipped_approx": approx, "skipped_noloc": noloc, "outside": outside}

def _risk(x):
    try:
        return int(float(x.get("risk") or 0))
    except (TypeError, ValueError):
        return 0

def _hit_label(h):
    dev = h.get("device") or {}
    return {
        "name": str(dev.get("ssid") or dev.get("name") or dev.get("callsign") or h.get("value") or "?")[:80],
        "type": str(dev.get("type") or h.get("type") or "")[:30],
        "risk": _risk(dev),
        "why": f"watchlist {h.get('type')}={h.get('value')}" + (f" ({h.get('note')})" if h.get("note") else ""),
        "key": store.device_key(dev),
    }

def _changes_text(ch):
    parts = []
    for k, v in (ch or {}).items():
        if k == "moved_m":
            parts.append(f"moved {v} m")
        else:
            parts.append(k)
    return ", ".join(parts)[:80]

def build_items(diff, hits, min_risk, baseline_devices=None):
    """Bildirim/zaman çizelgesi için öncelikli öğe listesi (watchlist > yeni > değişen > kaybolan)."""
    items, seen = [], set()
    for h in hits:
        it = _hit_label(h)
        items.append(it); seen.add(it["key"])
    news = diff.get("new") or []
    if baseline_devices is not None:
        news = [{"key": store.device_key(d), "name": store.device_name(d), "type": d.get("type"),
                 "risk": _risk(d)} for d in baseline_devices]
        news.sort(key=lambda x: -(x["risk"] or 0))
    for d in news:
        if (d.get("risk") or 0) >= min_risk and d.get("key") not in seen:
            items.append({"name": str(d.get("name"))[:80], "type": d.get("type") or "", "risk": d.get("risk") or 0,
                          "why": "new", "key": d.get("key")}); seen.add(d.get("key"))
    for d in diff.get("changed") or []:
        if (d.get("risk") or 0) >= min_risk and d.get("key") not in seen:
            items.append({"name": str(d.get("name"))[:80], "type": d.get("type") or "", "risk": d.get("risk") or 0,
                          "why": "changed: " + _changes_text(d.get("changes")), "key": d.get("key")}); seen.add(d.get("key"))
    for d in diff.get("gone") or []:
        if d.get("key") not in seen:
            items.append({"name": str(d.get("name"))[:80], "type": d.get("type") or "", "risk": d.get("risk") or 0,
                          "why": "gone", "key": d.get("key")}); seen.add(d.get("key"))
    return items

def decide(summary, notify, filtered):
    """Hangi tetikleyiciler ateşlendi? → liste (boşsa bildirim yok)."""
    fired = []
    if notify.get("on_watchlist", True) and summary.get("watchlist_hits"):
        fired.append("watchlist")
    if summary.get("baseline") and notify.get("quiet_baseline", True):
        return fired           # temel çalıştırma: yalnızca watchlist isabeti bildirilir
    if notify.get("on_new") and filtered["new"]:
        fired.append("new")
    if notify.get("on_gone") and summary.get("gone"):
        fired.append("gone")
    if notify.get("on_changed") and filtered["changed"]:
        fired.append("changed")
    return fired

def _base_url():
    return os.getenv("SIGNALOPS_PUBLIC_URL") or f"http://localhost:{os.getenv('SIGNALOPS_PORT', '8080')}"

def format_message(m, scan_id, summary, items, ts=None, min_risk=0):
    t = datetime.fromtimestamp(ts or _now(), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    head = (f"SignalOps · {m['name']}\n{t}\n"
            f"+{summary.get('new', 0)} new · −{summary.get('gone', 0)} gone · "
            f"{summary.get('changed', 0)} changed · {summary.get('watchlist_hits', 0)} watchlist hits")
    extra = []
    if summary.get("baseline"):
        extra.append(f"baseline run · {summary.get('devices', 0)} devices in area")
    if min_risk:
        extra.append(f"items with risk ≥ {min_risk}")
    if extra:
        head += "\n(" + "; ".join(extra) + ")"
    link = f"{_base_url()}/cases?scan={scan_id}"
    lines = []
    for it in items[:TOP_ITEMS]:
        lines.append(f"• {it['name']} [{it.get('type') or '?'}] risk {it.get('risk') or 0} — {it['why']}")
    if len(items) > TOP_ITEMS:
        lines.append(f"… +{len(items) - TOP_ITEMS} more")
    body = "\n".join(lines)
    budget = MSG_MAX - len(head) - len(link) - 4
    if len(body) > budget:
        body = body[:max(0, budget - 1)] + "…"
    return head + ("\n\n" + body if body else "") + "\n\n" + link

# ── Bildirim kanalları ───────────────────────────────────

def _webhook_url():
    url = (_ctx.get_key("NOTIFY_WEBHOOK_URL") or "").strip()
    if not url:
        return None, "Webhook URL not configured"
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        return None, "Webhook URL must start with http:// or https://"
    return url, ""

def send_webhook(payload):
    url, err = _webhook_url()
    if not url:
        return False, err
    try:
        r = requests.post(url, json=payload, timeout=8, allow_redirects=False,
                          headers={"User-Agent": "SignalOps-Monitor/1"})
    except requests.RequestException as e:
        return False, _redact(f"Webhook: connection error ({type(e).__name__})")
    if 200 <= r.status_code < 300:
        return True, f"Webhook: HTTP {r.status_code}"
    return False, f"Webhook: HTTP {r.status_code}"


def _key_test_webhook():
    ok, msg = send_webhook({"event": "signalops.test", "message": "SignalOps webhook test", "ts": _now()})
    return ok, msg

# ── Çalıştırma ───────────────────────────────────────────
def _set_status(mid, status, ran_at=None, interval=None):
    with store.db() as c:
        if ran_at is not None:
            c.execute("UPDATE monitors SET last_run=?, next_run=?, last_status=? WHERE id=?",
                      (ran_at, ran_at + int(interval) * 60, str(status)[:300], mid))
        else:
            c.execute("UPDATE monitors SET last_status=? WHERE id=?", (str(status)[:300], mid))

def _prev_geom(scan_id):
    pid = store.previous_scan_id(scan_id)
    if not pid:
        return None, None
    s = store.get_scan(pid, with_devices=False) or {}
    p = s.get("params") if isinstance(s.get("params"), dict) else {}
    return pid, p.get("geom")

def execute(mid):
    """Bir izlemeyi şimdi çalıştırır (çağıran sıraya sokmayı/_running'i yönetir). Döner: event dict | None."""
    m = _get(mid)
    if not m:
        return None
    poly = m["polygon"]
    notify = _v_notify(None, m.get("notify") if isinstance(m.get("notify"), dict) else {})
    started = _now()
    c_lat, c_lon = centroid(poly)
    rad = radius_km(poly, (c_lat, c_lon))
    raw = _scan(m["kind"], c_lat, c_lon, rad) or []
    devices, skipped = filter_devices(raw, poly)
    sig = _geom_sig(poly, m["kind"])
    scan = store.save_scan(m["kind"], devices, c_lat, c_lon, case_id=m.get("case_id"),
                           label=f"Monitor · {m['name']}",
                           params={"monitor": mid, "geom": sig, "radius_km": round(rad, 2)}, monitor_id=mid)
    sid = scan["id"]
    prev_id, prev_sig = _prev_geom(sid)
    if prev_id and prev_sig == sig:
        diff = store.diff_scans(sid, prev_id)
    else:
        diff = {"new": [], "gone": [], "changed": [], "old_scan": None,
                "counts": {"new": 0, "gone": 0, "changed": 0, "baseline": True},
                "rebaseline": bool(prev_id)}
    try:
        hits = _ctx.watchlist_match(devices, f"monitor:{m['name']}") or []
    except Exception as e:
        _log(f"watchlist match failed for #{mid}: {e}")
        hits = []
    baseline = bool(diff["counts"].get("baseline"))
    min_risk = int(notify.get("min_risk") or 0)
    f_new = [d for d in diff["new"] if (d.get("risk") or 0) >= min_risk]
    f_chg = [d for d in diff["changed"] if (d.get("risk") or 0) >= min_risk]
    summary = {
        "devices": scan.get("device_count", len(devices)),
        "new": diff["counts"]["new"], "gone": diff["counts"]["gone"], "changed": diff["counts"]["changed"],
        "watchlist_hits": len(hits),
        "skipped_approx": skipped["skipped_approx"], "skipped_noloc": skipped["skipped_noloc"],
        "outside": skipped["outside"], "raw": len(raw),
        "high_risk_new": sum(1 for d in diff["new"] if (d.get("risk") or 0) >= HIGH_RISK),
        "baseline": baseline, "rebaseline": bool(diff.get("rebaseline")),
        "prev_scan": diff.get("old_scan"), "kind": m["kind"], "duration_s": max(0, _now() - started),
    }
    baseline_devs = devices if (baseline and not notify.get("quiet_baseline", True)) else None
    if baseline_devs is not None:
        f_new = [d for d in devices if _risk(d) >= min_risk]
    items = build_items(diff, hits, min_risk, baseline_devs)
    summary["top"] = [{k: it.get(k) for k in ("name", "type", "risk", "why")} for it in items[:TOP_ITEMS]]
    fired = decide(summary, notify, {"new": f_new, "changed": f_chg})
    summary["triggers"] = fired

    if not _get(mid):            # çalışırken silindi
        return None
    with store.db() as c:
        cur = c.execute("INSERT INTO monitor_events(monitor_id, scan_id, ts, summary, notified) VALUES(?,?,?,?,0)",
                        (mid, sid, _now(), json.dumps(summary, default=str)))
        eid = cur.lastrowid

    status = (f"OK · {summary['devices']} dev" + (" · baseline" if baseline else
              f" · +{summary['new']} −{summary['gone']} ~{summary['changed']}")
              + (f" · {len(hits)} watchlist" if hits else ""))
    notified = False
    if fired:
        channels = [ch for ch in ("webhook",) if notify.get(ch)]
        if not channels:
            status += " · no channel enabled"
        else:
            errors, oks = [], 0
            if "webhook" in channels:
                payload = {"event": "signalops.monitor",
                           "monitor": {"id": mid, "name": m["name"], "kind": m["kind"]},
                           "scan_id": sid, "summary": {k: v for k, v in summary.items() if k != "top"},
                           "triggers": fired, "items": items[:50],
                           "link": f"{_base_url()}/cases?scan={sid}", "ts": _now()}
                ok, msg = send_webhook(payload)
                oks += ok
                if not ok: errors.append(msg)
            notified = not errors
            if notified:
                status += " · notified"
            else:
                status += " · notify failed: " + "; ".join(errors)
            if oks and errors:
                status += f" ({oks} sent)"
            if notified:
                with store.db() as c:
                    c.execute("UPDATE monitor_events SET notified=1 WHERE id=?", (eid,))
    ev = {"id": eid, "monitor_id": mid, "scan_id": sid, "summary": summary, "notified": int(notified)}
    return ev, _redact(status)

def run_monitor(mid, mode="scheduled"):
    """_running işaretli izlemeyi _exec_lock altında çalıştırır; durum/next_run günceller."""
    ev = None
    with _exec_lock:
        with _state_lock:
            _running[mid] = "running"
        m = _get(mid)
        try:
            if not m:
                return None
            res = execute(mid)
            if res:
                ev, status = res
            else:
                status = "deleted during run"
        except Exception as e:
            status = _redact(f"error: {type(e).__name__}: {e}")[:300]
            _log(f"run #{mid} failed: {status}")
        finally:
            with _state_lock:
                _running.pop(mid, None)
        m2 = _get(mid)
        if m2:
            _set_status(mid, status, ran_at=_now(), interval=m2["interval_min"])
    return ev

def _claim(mid, how="queued"):
    with _state_lock:
        if mid in _running:
            return False
        _running[mid] = how
        return True

def tick(now_ts=None):
    """Zamanı gelmiş etkin izlemeleri sırayla çalıştırır. Döner: çalıştırılan id listesi."""
    now_ts = int(now_ts if now_ts is not None else _now())
    with store.db() as c:
        due = [r["id"] for r in c.execute(
            "SELECT id FROM monitors WHERE enabled=1 AND (next_run IS NULL OR next_run<=?)"
            " ORDER BY COALESCE(next_run, 0), id", (now_ts,))]
    ran = []
    for mid in due:
        m = _get(mid)
        if not m or not m["enabled"] or (m["next_run"] is not None and m["next_run"] > now_ts):
            continue
        if not _claim(mid):
            continue
        run_monitor(mid)
        ran.append(mid)
    return ran

def _scheduler_loop():
    time.sleep(10)          # uygulama açılışını bekle
    while True:
        try:
            tick()
        except Exception as e:
            _log(f"scheduler tick failed: {type(e).__name__}: {e}")
        time.sleep(TICK_SECONDS)

def _acquire_process_lock(config_dir):
    global _lock_fd
    try:
        import fcntl
    except ImportError:
        return True                  # Windows: tek süreç varsay
    try:
        os.makedirs(config_dir, exist_ok=True)
        fd = os.open(os.path.join(config_dir, "monitor-scheduler.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as e:
        _log(f"lock file unavailable ({e}); starting scheduler anyway")
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    try:
        os.ftruncate(fd, 0); os.write(fd, str(os.getpid()).encode())
    except OSError:
        pass
    _lock_fd = fd                     # süreç ömrü boyunca açık kalır → kilit tutulur
    return True

def start_scheduler(app, ctx):
    global _scheduler_started, _scheduler_thread
    if _scheduler_started:
        return False
    if app.config.get("TESTING") or os.getenv("SIGNALOPS_DISABLE_SCHEDULER") == "1":
        _log("scheduler disabled")
        return False
    if not _acquire_process_lock(ctx.config_dir):
        _log(f"scheduler lock held by another process (pid file in {ctx.config_dir}) — not starting here")
        return False
    _scheduler_started = True
    _scheduler_thread = threading.Thread(target=_scheduler_loop, name="signalops-monitor", daemon=True)
    _scheduler_thread.start()
    _log("scheduler started")
    return True

# ── API ──────────────────────────────────────────────────
def _err(msg, code=400):
    return jsonify({"error": msg}), code

def _last_events(ids):
    if not ids:
        return {}
    with store.db() as c:
        rs = c.execute(
            f"SELECT e.* FROM monitor_events e JOIN (SELECT monitor_id, MAX(id) AS mid FROM monitor_events"
            f" WHERE monitor_id IN ({','.join('?' * len(ids))}) GROUP BY monitor_id) x ON x.mid=e.id", ids)
        return {r["monitor_id"]: store.row(r) for r in rs}

@bp.route("/monitor")
def page_monitor():
    return render_template("monitor.html", active="Monitor")

@bp.route("/api/monitors", methods=["GET"])
def api_list():
    with store.db() as c:
        ms = store.rows(c.execute("SELECT * FROM monitors ORDER BY id DESC"))
    last = _last_events([m["id"] for m in ms])
    return jsonify({"monitors": [_public(m, last.get(m["id"])) for m in ms], "now": _now(),
                    "scheduler": _scheduler_started})

@bp.route("/api/monitors/<int:mid>", methods=["GET"])
def api_get(mid):
    m = _get(mid)
    if not m:
        return _err("monitor not found", 404)
    return jsonify(_public(m, _last_events([mid]).get(mid)))

@bp.route("/api/monitors", methods=["POST"])
def api_create():
    try:
        v = _validate(request.get_json(silent=True), partial=False)
    except VErr as e:
        return _err(str(e))
    ts = _now()
    with store.db() as c:
        cur = c.execute(
            "INSERT INTO monitors(name, polygon, kind, interval_min, enabled, case_id, notify, last_run, next_run,"
            " last_status, created_at) VALUES(?,?,?,?,?,?,?,NULL,?,?,?)",
            (v["name"], json.dumps(v["polygon"]), v["kind"], v["interval_min"], int(v["enabled"]), v["case_id"],
             json.dumps(v["notify"]), ts if v["enabled"] else None, "created", ts))
        mid = cur.lastrowid
    return jsonify(_public(_get(mid))), 201

@bp.route("/api/monitors/<int:mid>", methods=["PATCH"])
def api_patch(mid):
    m = _get(mid)
    if not m:
        return _err("monitor not found", 404)
    body = request.get_json(silent=True)
    try:
        v = _validate(body, partial=True, current=m)
    except VErr as e:
        return _err(str(e))
    if not v:
        return jsonify(_public(m))
    sets, args = [], []
    for k in ("name", "kind", "interval_min", "case_id"):
        if k in v:
            sets.append(f"{k}=?"); args.append(v[k])
    if "polygon" in v:
        sets.append("polygon=?"); args.append(json.dumps(v["polygon"]))
    if "notify" in v:
        sets.append("notify=?"); args.append(json.dumps(v["notify"]))
    if "enabled" in v:
        sets.append("enabled=?"); args.append(int(v["enabled"]))
    new_enabled = v.get("enabled", bool(m["enabled"]))
    newly_enabled = new_enabled and not m["enabled"]
    iv_changed = "interval_min" in v and v["interval_min"] != m["interval_min"]
    if not new_enabled:
        sets.append("next_run=?"); args.append(None)
    elif newly_enabled or iv_changed or m.get("next_run") is None:
        merged = dict(m, interval_min=v.get("interval_min", m["interval_min"]))
        sets.append("next_run=?"); args.append(_next_run_after_change(merged, _now()))
    with store.db() as c:
        c.execute(f"UPDATE monitors SET {', '.join(sets)} WHERE id=?", (*args, mid))
    return jsonify(_public(_get(mid)))

@bp.route("/api/monitors/<int:mid>", methods=["DELETE"])
def api_delete(mid):
    with store.db() as c:
        n = c.execute("DELETE FROM monitors WHERE id=?", (mid,)).rowcount
    if not n:
        return _err("monitor not found", 404)
    return jsonify({"ok": True, "deleted": mid})

@bp.route("/api/monitors/<int:mid>/events", methods=["GET"])
def api_events(mid):
    if not _get(mid):
        return _err("monitor not found", 404)
    try:
        limit = max(1, min(500, int(request.args.get("limit", 50))))
    except (TypeError, ValueError):
        limit = 50
    with store.db() as c:
        evs = store.rows(c.execute("SELECT * FROM monitor_events WHERE monitor_id=? ORDER BY ts DESC, id DESC LIMIT ?",
                                   (mid, limit)))
    return jsonify({"events": evs})

def _bg_run(mid):
    try:
        run_monitor(mid, mode="manual")
    except Exception as e:      # run_monitor zaten yakalar; emniyet
        _log(f"manual run #{mid} crashed: {type(e).__name__}")
        with _state_lock:
            _running.pop(mid, None)

def _routes_with_limits(ctx):
    """rate_limit'li uç noktalar (ctx gerektiği için init'te tanımlanır)."""
    @ctx.rate_limit("10 per minute")
    def api_run(mid):
        if not _get(mid):
            return _err("monitor not found", 404)
        if not _claim(mid):
            return _err("monitor is already running or queued", 409)
        queued = _exec_lock.locked()
        threading.Thread(target=_bg_run, args=(mid,), name=f"monitor-run-{mid}", daemon=True).start()
        return jsonify({"ok": True, "started": True, "queued": queued,
                        "message": "queued behind another run" if queued else "run started"}), 202

    @ctx.rate_limit("10 per minute")
    def api_notify_test():
        body = request.get_json(silent=True) or {}
        ch = body.get("channel")
        if ch == "webhook":
            ok, msg = send_webhook({"event": "signalops.test", "message": "SignalOps webhook test", "ts": _now()})
        else:
            return _err("channel must be webhook")
        return jsonify({"ok": bool(ok), "message": msg})

    bp.add_url_rule("/api/monitors/<int:mid>/run", "api_run", api_run, methods=["POST"])
    bp.add_url_rule("/api/notify/test", "api_notify_test", api_notify_test, methods=["POST"])

def init(app, ctx):
    global _ctx
    _ctx = ctx
    if "monitor" not in app.blueprints:
        _routes_with_limits(ctx)
        app.register_blueprint(bp)
    ctx.register_key_test("webhook", ("NOTIFY_WEBHOOK_URL",), _key_test_webhook)
    start_scheduler(app, ctx)
