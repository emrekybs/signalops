"""
SignalOps — kalıcı depo (SQLite).

Tablolar
  cases          vaka (operasyon) kayıtları
  scans          kaydedilmiş taramalar (bir vakaya bağlı olabilir, izleme çalıştırmaları da buraya yazılır)
  scan_devices   bir taramadaki cihazların anlık görüntüsü (dev_key ile)
  notes          vaka / tarama / cihaz notları
  flags          vaka içinde işaretlenmiş cihazlar
  profiles       sunucu taraflı cihaz profilleri (eskiden tarayıcı localStorage)
  monitors       alan izleme tanımları (çokgen + periyot + bildirim ayarları)
  monitor_events izleme çalıştırma sonuçları

Kimlik (dev_key): aynı fiziksel cihaz farklı taramalarda/kaynaklarda aynı anahtarı alır → değişim
tespiti ve korelasyon bunun üzerine kurulu.
"""
import os, json, time, sqlite3, threading, math, ipaddress
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    from .. import paths as _paths
    DB_PATH = _paths.db_path()
except ImportError:
    DB_PATH = os.getenv("SIGNALOPS_DB", os.path.join(BASE_DIR, "db", "signalops.db"))
_init_lock = threading.Lock()
_initialized = False

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  status TEXT DEFAULT 'open',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
  monitor_id INTEGER REFERENCES monitors(id) ON DELETE SET NULL,
  kind TEXT NOT NULL,
  label TEXT DEFAULT '',
  lat REAL, lon REAL,
  area_key TEXT,
  params TEXT DEFAULT '{}',
  device_count INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_scans_area ON scans(area_key, created_at);
CREATE INDEX IF NOT EXISTS ix_scans_case ON scans(case_id, created_at);
CREATE INDEX IF NOT EXISTS ix_scans_monitor ON scans(monitor_id, created_at);
CREATE TABLE IF NOT EXISTS scan_devices(
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  dev_key TEXT NOT NULL,
  type TEXT, source TEXT, name TEXT,
  lat REAL, lon REAL, risk INTEGER,
  data TEXT NOT NULL,
  PRIMARY KEY(scan_id, dev_key)
);
CREATE INDEX IF NOT EXISTS ix_sd_key ON scan_devices(dev_key);
CREATE INDEX IF NOT EXISTS ix_sd_name ON scan_devices(name);
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
  scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  dev_key TEXT,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS flags(
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  dev_key TEXT NOT NULL,
  label TEXT DEFAULT '',
  color TEXT DEFAULT 'red',
  data TEXT DEFAULT '{}',
  created_at INTEGER NOT NULL,
  PRIMARY KEY(case_id, dev_key)
);
CREATE TABLE IF NOT EXISTS profiles(
  dev_key TEXT PRIMARY KEY,
  name TEXT DEFAULT '',
  note TEXT DEFAULT '',
  data TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS monitors(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  polygon TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'nearby',
  interval_min INTEGER NOT NULL DEFAULT 60,
  enabled INTEGER NOT NULL DEFAULT 1,
  case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
  notify TEXT NOT NULL DEFAULT '{}',
  last_run INTEGER, next_run INTEGER,
  last_status TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS monitor_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
  ts INTEGER NOT NULL,
  summary TEXT NOT NULL DEFAULT '{}',
  notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_me_mon ON monitor_events(monitor_id, ts);
"""

def now():
    return int(time.time())

def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn

def init_db():
    global _initialized
    with _init_lock:
        if _initialized:
            return
        conn = _connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()
        try: os.chmod(DB_PATH, 0o600)
        except OSError: pass
        _initialized = True

@contextmanager
def db():
    """with db() as c: c.execute(...) — commit otomatik, hata olursa rollback."""
    init_db()
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def row(r):
    if r is None:
        return None
    d = dict(r)
    for k in ("data", "params", "polygon", "notify", "summary"):
        if k in d and isinstance(d[k], str):
            try: d[k] = json.loads(d[k])
            except Exception: pass
    return d

def rows(rs):
    return [row(r) for r in rs]

# ── Cihaz kimliği ─────────────────────────────────────────
def _norm_mac(v):
    h = "".join(c for c in str(v) if c.isalnum()).lower()
    if len(h) == 12 and all(c in "0123456789abcdef" for c in h):
        return ":".join(h[i:i+2] for i in range(0, 12, 2))
    return None

def device_key(d):
    """Kaynaktan bağımsız, kararlı cihaz anahtarı. Bulunamazsa None."""
    if not isinstance(d, dict):
        return None
    t = (d.get("type") or "").lower()
    if t == "cell_tower" and d.get("cell_id"):
        return f"cell:{d.get('mcc')}:{d.get('mnc')}:{d.get('lac')}:{d.get('cell_id')}"
    if t in ("aircraft", "drone") and d.get("icao"):
        return f"icao:{str(d['icao']).upper()}"
    if d.get("mmsi"):
        return f"mmsi:{d['mmsi']}"
    if d.get("icao"):
        return f"icao:{str(d['icao']).upper()}"
    mac = _norm_mac(d.get("bssid") or d.get("mac") or "")
    if mac:
        return f"mac:{mac}"
    ip = str(d.get("ip") or "")
    try:
        ipaddress.ip_address(ip)
        return f"ip:{ip}:{d.get('port') or ''}"
    except ValueError:
        pass
    if ip and ":" in ip:            # osm:123, tfl_jamcam:JamCams_1, windy:… gibi kaynak kimlikleri
        return f"ref:{ip}"
    if d.get("callsign"):
        return f"call:{str(d['callsign']).upper()}"
    if d.get("lat") is not None and d.get("lon") is not None:
        return f"geo:{d.get('source','')}:{round(float(d['lat']),5)}:{round(float(d['lon']),5)}:{d.get('ssid') or ''}"
    return None

def device_name(d):
    return str(d.get("ssid") or d.get("name") or d.get("callsign") or d.get("ip")
               or d.get("bssid") or d.get("cell_id") or d.get("icao") or d.get("mmsi") or "?")[:200]

def area_key(kind, lat, lon, monitor_id=None, params=None):
    if monitor_id:
        return f"monitor:{monitor_id}"
    if lat is None or lon is None:
        # Koordinatsız taramalar (ülke / IP / SSID araması): sorgunun kendisi bölge anahtarı olur,
        # böylece "TR kamera taraması" sadece önceki "TR kamera taraması" ile karşılaştırılır
        p = params or {}
        q = p.get("country") or p.get("query") or p.get("q")
        return f"{kind}:q:{str(q).strip().lower()[:80]}" if q else f"{kind}:none:{now()}"
    return f"{kind}:{round(float(lat), 2)}:{round(float(lon), 2)}"

def _f(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None

# ── Tarama kaydet / oku ──────────────────────────────────
MAX_DEVICES_PER_SCAN = 20000

def save_scan(kind, devices, lat=None, lon=None, case_id=None, label="", params=None, monitor_id=None):
    """Tarama + cihazları yazar. Döner: scan dict (id, device_count, area_key …)."""
    devices = [d for d in (devices or []) if isinstance(d, dict)][:MAX_DEVICES_PER_SCAN]
    lat, lon = _f(lat), _f(lon)
    ak = area_key(kind, lat, lon, monitor_id, params if isinstance(params, dict) else None)
    seen = {}
    for d in devices:
        k = device_key(d)
        if k and k not in seen:
            seen[k] = d
    with db() as c:
        cur = c.execute(
            "INSERT INTO scans(case_id, monitor_id, kind, label, lat, lon, area_key, params, device_count, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (case_id, monitor_id, str(kind)[:30], str(label or "")[:200], lat, lon, ak,
             json.dumps(params or {}), len(seen), now()))
        sid = cur.lastrowid
        c.executemany(
            "INSERT OR REPLACE INTO scan_devices(scan_id, dev_key, type, source, name, lat, lon, risk, data)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            [(sid, k, str(d.get("type") or "")[:40], str(d.get("source") or "")[:60], device_name(d),
              _f(d.get("lat")), _f(d.get("lon")), int(_f(d.get("risk")) or 0),
              json.dumps(d, ensure_ascii=False, default=str)) for k, d in seen.items()])
        if case_id:
            c.execute("UPDATE cases SET updated_at=? WHERE id=?", (now(), case_id))
        return row(c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone())

def get_scan(scan_id, with_devices=True):
    with db() as c:
        s = row(c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
        if s and with_devices:
            s["devices"] = [dict(r["data"] if isinstance(r["data"], dict) else json.loads(r["data"]), _key=r["dev_key"])
                            for r in c.execute("SELECT dev_key, data FROM scan_devices WHERE scan_id=? ORDER BY risk DESC", (scan_id,))]
        return s

def previous_scan_id(scan_id):
    with db() as c:
        s = c.execute("SELECT area_key, created_at, id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not s:
            return None
        p = c.execute("SELECT id FROM scans WHERE area_key=? AND id<? ORDER BY id DESC LIMIT 1",
                      (s["area_key"], s["id"])).fetchone()
        return p["id"] if p else None

# ── Değişim tespiti ──────────────────────────────────────
def _hav_m(a_lat, a_lon, b_lat, b_lon):
    r = 6371000.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp = p2 - p1; dl = math.radians(b_lon - a_lon)
    h = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))

_WATCH_FIELDS = ("ssid", "encryption", "risk", "operator", "radio", "org", "port", "squawk")

def diff_scans(new_id, old_id=None, move_threshold_m=150):
    """new_id ile (verilmezse aynı bölgedeki bir önceki) tarama arasındaki fark.
    Döner: {new_scan, old_scan, new:[…], gone:[…], changed:[…], counts}"""
    old_id = old_id or previous_scan_id(new_id)
    with db() as c:
        new_rows = {r["dev_key"]: r for r in c.execute(
            "SELECT dev_key, type, source, name, lat, lon, risk, data FROM scan_devices WHERE scan_id=?", (new_id,))}
        old_rows = {r["dev_key"]: r for r in c.execute(
            "SELECT dev_key, type, source, name, lat, lon, risk, data FROM scan_devices WHERE scan_id=?", (old_id,))} if old_id else {}
    def brief(r):
        return {"key": r["dev_key"], "type": r["type"], "source": r["source"], "name": r["name"],
                "lat": r["lat"], "lon": r["lon"], "risk": r["risk"]}
    out = {"new_scan": new_id, "old_scan": old_id, "new": [], "gone": [], "changed": []}
    if not old_id:
        out["counts"] = {"new": 0, "gone": 0, "changed": 0, "baseline": True}
        return out
    for k, r in new_rows.items():
        if k not in old_rows:
            out["new"].append(brief(r)); continue
        o = old_rows[k]
        nd, od = json.loads(r["data"]), json.loads(o["data"])
        changes = {}
        for f in _WATCH_FIELDS:
            if nd.get(f) != od.get(f) and (nd.get(f) not in (None, "") or od.get(f) not in (None, "")):
                changes[f] = [od.get(f), nd.get(f)]
        if None not in (r["lat"], r["lon"], o["lat"], o["lon"]) \
                and not nd.get("approx") and not od.get("approx"):
            moved = _hav_m(o["lat"], o["lon"], r["lat"], r["lon"])
            if moved > move_threshold_m:
                changes["moved_m"] = round(moved)
        if changes:
            b = brief(r); b["changes"] = changes
            out["changed"].append(b)
    out["gone"] = [brief(r) for k, r in old_rows.items() if k not in new_rows]
    for lst in (out["new"], out["gone"], out["changed"]):
        lst.sort(key=lambda x: -(x.get("risk") or 0))
    out["counts"] = {"new": len(out["new"]), "gone": len(out["gone"]), "changed": len(out["changed"]), "baseline": False}
    return out

# ── Korelasyon ───────────────────────────────────────────
def device_history(dev_key, limit=500):
    """Bir cihazın tüm taramalardaki izi + birlikte görüldüğü cihazlar."""
    with db() as c:
        sightings = [dict(r) for r in c.execute(
            "SELECT s.id AS scan_id, s.kind, s.label, s.case_id, s.monitor_id, s.created_at,"
            "       d.source, d.lat, d.lon, d.risk, d.name, d.type"
            "  FROM scan_devices d JOIN scans s ON s.id=d.scan_id"
            " WHERE d.dev_key=? ORDER BY s.created_at DESC, s.id DESC LIMIT ?", (dev_key, limit))]
        latest = c.execute(
            "SELECT d.data FROM scan_devices d JOIN scans s ON s.id=d.scan_id WHERE d.dev_key=?"
            " ORDER BY s.created_at DESC, s.id DESC LIMIT 1", (dev_key,)).fetchone()
        co = [dict(r) for r in c.execute(
            "SELECT d2.dev_key AS key, MAX(d2.name) AS name, MAX(d2.type) AS type, COUNT(DISTINCT d2.scan_id) AS together"
            "  FROM scan_devices d1 JOIN scan_devices d2 ON d1.scan_id=d2.scan_id AND d2.dev_key<>d1.dev_key"
            " WHERE d1.dev_key=? GROUP BY d2.dev_key HAVING together>=2 ORDER BY together DESC LIMIT 15", (dev_key,))]
        case_ids = sorted({s["case_id"] for s in sightings if s["case_id"]})
        cases_ = rows(c.execute(f"SELECT id, name FROM cases WHERE id IN ({','.join('?'*len(case_ids))})", case_ids)) if case_ids else []
        prof = row(c.execute("SELECT * FROM profiles WHERE dev_key=?", (dev_key,)).fetchone())
        flags_ = rows(c.execute("SELECT f.case_id, f.label, f.color, c.name AS case_name FROM flags f JOIN cases c ON c.id=f.case_id WHERE f.dev_key=?", (dev_key,)))
    data = json.loads(latest["data"]) if latest else None
    related = []
    if data:
        related = related_devices(dev_key, data)
    locs = {(round(s["lat"], 4), round(s["lon"], 4)) for s in sightings if s["lat"] is not None}
    return {
        "key": dev_key, "latest": data, "profile": prof, "flags": flags_, "cases": cases_,
        "sightings": sightings, "co_occurring": co, "related": related,
        "summary": {
            "count": len(sightings),
            "first_seen": min((s["created_at"] for s in sightings), default=None),
            "last_seen": max((s["created_at"] for s in sightings), default=None),
            "sources": sorted({s["source"] for s in sightings if s["source"]}),
            "distinct_locations": len(locs),
            "scan_kinds": sorted({s["kind"] for s in sightings}),
        },
    }

def _prefix_range(prefix):
    """'abc' → ('abc', 'abd'): ix_sd_key indeksini kullanan önek araması (LIKE indeks kullanmıyordu)."""
    return prefix, prefix[:-1] + chr(ord(prefix[-1]) + 1)

def related_devices(dev_key, data, limit=20):
    """Aynı SSID'yi yayınlayan farklı BSSID'ler, aynı /24 içindeki IP'ler, aynı operatör+LAC kuleleri."""
    out = []
    with db() as c:
        if data.get("ssid") and (data.get("type") in ("router", "bluetooth", "ble")):
            for r in c.execute("SELECT dev_key, MAX(name) AS name, MAX(type) AS type, COUNT(*) AS n FROM scan_devices"
                               " WHERE name=? AND dev_key<>? GROUP BY dev_key LIMIT ?", (data["ssid"], dev_key, limit)):
                out.append({"key": r["dev_key"], "name": r["name"], "type": r["type"], "why": "same SSID", "seen": r["n"]})
        ip = str(data.get("ip") or "")
        try:
            net = ipaddress.ip_network(f"{ip}/24", strict=False) if ipaddress.ip_address(ip).version == 4 else None
        except ValueError:
            net = None
        if net:
            prefix = "ip:" + ".".join(ip.split(".")[:3]) + "."
            for r in c.execute("SELECT dev_key, MAX(name) AS name, MAX(type) AS type, COUNT(*) AS n FROM scan_devices"
                               " WHERE dev_key>=? AND dev_key<? AND dev_key<>? GROUP BY dev_key LIMIT ?", (*_prefix_range(prefix), dev_key, limit)):
                out.append({"key": r["dev_key"], "name": r["name"], "type": r["type"], "why": f"same /24 ({net})", "seen": r["n"]})
        if dev_key.startswith("cell:"):
            parts = dev_key.split(":")
            if len(parts) >= 5:
                prefix = ":".join(parts[:4]) + ":"
                for r in c.execute("SELECT dev_key, MAX(name) AS name, MAX(type) AS type, COUNT(*) AS n FROM scan_devices"
                                   " WHERE dev_key>=? AND dev_key<? AND dev_key<>? GROUP BY dev_key LIMIT ?", (*_prefix_range(prefix), dev_key, limit)):
                    out.append({"key": r["dev_key"], "name": r["name"], "type": r["type"], "why": "same operator + LAC", "seen": r["n"]})
    return out[:limit]
