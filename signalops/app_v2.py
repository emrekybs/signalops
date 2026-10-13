"""
Signal OPS — app_v2.py  (PATCHED)

Tüm fix listesi (v2 üzeri):
  BUG-01  classify(): "TV" keyword "CCTV" kameralarını yutuyordu → sıra düzeltildi
  BUG-02  ADSB_KEY request'e geçmiyordu → params={"api_key": ADSB_KEY} eklendi
  BUG-03  fetch_cameras_binaryedge: country filter eksikti → cf eklendi
  BUG-04  fetch_cameras_fofa: index guard < 2 yetersizdi → < 9 yapıldı
  SEC-07  ip-api.com HTTP çağrılıyordu → ipinfo.io HTTPS primary yapıldı
  SEC-08  /api/cctv rate limit yoktu → flask-limiter ile 10/min limit eklendi
  BUG-09  dedup() jitter çakışması → composite key (ip:port:source) kullanıldı
  BUG-10  _geo_cache sınırsız büyüyordu → TTLCache (maxsize=1024, ttl=3600) eklendi
  BUG-11  fetch_hunterhow start_time hardcode 2024-01-01 → rolling 365 gün
  BUG-12  as_completed timeout sonrası futures temizlenmiyordu → cancel_futures
  ARC-13  /dashboard ve /map-w Jinja'yı bypass ediyordu → render_template'e taşındı
  ARC-14  score() tags sadece LeakIX içindi → Shodan vulns + CriminalIP score eklendi
  ARC-15  lat/lon koordinat validation yoktu → validate_coords() eklendi
  ARC-16  Gemini system prompt fake turn ile veriliyordu → system_instruction eklendi
  BUG-17  /api/cctv erken return → Gemini + alt kod ölü kalıyordu → düzeltildi
  BUG-18  country modu Insecam/EarthCam çağırmıyordu → eklendi
  BUG-19  fetch_cameras_insecam_by_country eksikti → yazıldı
  BUG-20  fetch_earthcam_by_country hiç yoktu → yazıldı

Stabilizasyon turu (A):
  STB-01  ThreadPool timeout'ları gerçekten uygulanıyor (shutdown cancel_futures, TimeoutError yakalanıyor)
  STB-02  /api/adsb, /api/ip-intel, /api/gps-jamming, TLE fetch timeout'ta 500 yerine kısmi sonuç
  STB-03  Girdi doğrulama: radius/grid/limit/bbox/country/ip/mac/mcc parse + clamp
  STB-04  Watchlist: mutlak yol, atomik yazım, bozuk dosyada veri silmeme, mark-read endpoint
  STB-05  Kaynağın verdiği risk (aircraft/insecam/osm) score() tarafından ezilmiyor
  STB-06  Şifreleme normalize (WiGLE küçük harf / "none") → açık ağ tespiti çalışıyor
  STB-07  Gemini risk seviyesi "RISK LEVEL:" satırından ayrıştırılıyor
  STB-08  IMSI: signal=0 (bilinmeyen) sahte kule sayılmıyor; bilinmeyen radio "gsm" değil
  STB-09  adsb.fi v3 endpoint + deniz mili; nac_p/nic/category aktarılıyor → GPS jamming çalışıyor
  STB-10  Drone tespiti ADS-B emitter category (B6) öncelikli
  STB-11  Uydular NORAD ID ile tekilleştiriliyor; boş TLE grubu cache'lenmiyor; sgp4 yoksa hata
  STB-12  Windy v3 include=, Hunter.how api.hunter.how/search, ZoomEye None banner
  STB-13  /api/search BSSID desteği, /nearby?mode=cell (sadece kule — kota tasarrufu)
  STB-14  Ölü /static route ve /log-activity kaldırıldı; private IP filtresi ipaddress ile
  STB-15  device_history / mcc cache sınırlı; anomaly bölge bazlı
  STB-16  Rate limit: pahalı endpoint'lere flask-limiter (varsa)

Yerel kullanım turu (B):
  LOC-01  API anahtarları Settings arayüzünden (config/keys.json, .env'in önünde), anında devreye girer
  LOC-02  Sağlayıcı bağlantı testleri (/api/settings/test)
  LOC-03  Varsayılan 127.0.0.1 bind (SIGNALOPS_HOST/PORT), kalıcı secret key (config/secret_key)
  LOC-04  Host (DNS rebinding) + Origin (CSRF) koruması — SIGNALOPS_ALLOWED_HOSTS
  LOC-05  Koordinatsız cihazlar approx=True + loc_quality (exact/ip/approx) — haritada '≈'
  LOC-06  Overpass sorguları görünen alan (bbox) ile; geniş alanda merkezde kırpma + clipped bayrağı
"""

import os, json, random, base64, requests, threading, time, re, tempfile, ipaddress, socket
import builtins as _builtins

# Log'lara API anahtarı sızmasın: requests hata mesajları tam URL'yi (…?key=XXXX) içerir.
_SECRET_QS = re.compile(r"(?i)((?:api[_-]?key|apikey|key|token|access[_-]?code|authenticationkey|email)=)[^&\s'\"]+")
_BOT_PATH = re.compile(r"(?i)(/bot)\d+:[A-Za-z0-9_-]+")
def print(*args, **kwargs):  # noqa: A001 — bu modüldeki tüm print çağrılarını maskeler
    clean = [_BOT_PATH.sub(r"\1•••", _SECRET_QS.sub(r"\1•••", a)) if isinstance(a, str) else a for a in args]
    if any(not isinstance(a, str) for a in args):
        clean = [_SECRET_QS.sub(r"\1•••", str(a)) for a in args]
    _builtins.print(*clean, **kwargs)
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
from concurrent.futures import TimeoutError as FuturesTimeout

try:
    from . import paths as _paths
except ImportError:                     # run as a plain script from inside the package folder
    import paths as _paths
try:
    from dotenv import load_dotenv
    if os.path.exists(_paths.ENV_FILE):
        load_dotenv(_paths.ENV_FILE)
    load_dotenv()                       # ./.env in the working directory (does not override)
except ImportError:
    pass

try:
    from cachetools import TTLCache
    _geo_cache = TTLCache(maxsize=1024, ttl=3600)
    _ttlcache_available = True
except ImportError:
    _geo_cache = {}
    _ttlcache_available = False

from flask import Flask, request, jsonify, render_template, redirect

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _limiter_available = True
except ImportError:
    _limiter_available = False

app = Flask(__name__, template_folder="templates")
def _persistent_secret():
    """FLASK_SECRET_KEY yoksa config/secret_key'de bir kez üretilip saklanır (yeniden başlatmada sabit)."""
    v = (os.getenv("FLASK_SECRET_KEY") or "").strip()
    if v:
        return v
    d = _paths.config_dir()
    path = os.path.join(d, "secret_key")
    try:
        with open(path, "r") as f:
            v = f.read().strip()
        if v:
            return v
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[config] secret_key okunamadı: {e}")
    v = os.urandom(32).hex()
    try:
        os.makedirs(d, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(v)
    except Exception as e:
        print(f"[config] secret_key yazılamadı (oturumlar her başlatmada sıfırlanır): {e}")
    return v

app.secret_key = _persistent_secret()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

limiter = None
if _limiter_available:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[],
        storage_uri="memory://",
    )

def rate_limit(spec):
    """flask-limiter kuruluysa limit uygular, değilse no-op (STB-16)."""
    def deco(fn):
        return limiter.limit(spec)(fn) if limiter else fn
    return deco

# ── Yerel çalışma koruması (giriş ekranı yok → tarayıcı tabanlı saldırılara karşı) ──
# 1) Host kontrolü: DNS rebinding ile kötü niyetli bir sitenin localhost API'ye erişmesini engeller.
# 2) Origin kontrolü: başka bir siteden gelen POST/DELETE isteklerini (CSRF) reddeder.
# LAN'dan erişmek istersen: SIGNALOPS_ALLOWED_HOSTS="192.168.1.20,mypc.local"
_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"} | {
    h.strip().lower() for h in (os.getenv("SIGNALOPS_ALLOWED_HOSTS") or "").split(",") if h.strip()}

def _host_only(h):
    h = (h or "").strip().lower()
    if h.startswith("["):
        return h.split("]")[0] + "]"
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h

@app.before_request
def _local_guard():
    if app.config.get("TESTING"):
        return None
    host = _host_only(request.host)
    if host not in _ALLOWED_HOSTS and "*" not in _ALLOWED_HOSTS:
        return jsonify({"error": f"Host '{host}' not allowed. Add it to SIGNALOPS_ALLOWED_HOSTS to permit."}), 403
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and origin != "null":
            from urllib.parse import urlparse
            o = urlparse(origin)
            if _host_only(o.netloc) != host:
                return jsonify({"error": "Cross-origin request blocked"}), 403
    return None

@app.context_processor
def _inject_map_keys():
    # Harita altlığı anahtarı tarayıcıya gitmek zorunda (tile istekleri tarayıcıdan yapılır)
    return {"carto_key": globals().get("CARTO_API_KEY") or ""}

@app.errorhandler(429)
def _too_many(e):
    return jsonify({"error": "Rate limit exceeded — slow down", "detail": str(getattr(e, "description", ""))}), 429

# ── Girdi yardımcıları (STB-03) ──
def arg_int(name, default, lo, hi):
    try:
        v = int(float(request.args.get(name, default)))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))

def arg_float(name, default, lo, hi):
    try:
        v = float(request.args.get(name, default))
        if v != v:  # NaN
            v = default
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))

def parse_bbox():
    """lat1/lon1/lat2/lon2 zorunlu, aralık kontrollü, en fazla ~5°x5° (grid DoS koruması)."""
    try:
        lat1 = float(request.args["lat1"]); lon1 = float(request.args["lon1"])
        lat2 = float(request.args["lat2"]); lon2 = float(request.args["lon2"])
    except (KeyError, TypeError, ValueError):
        return None
    for la in (lat1, lat2):
        if not -90 <= la <= 90: return None
    for lo in (lon1, lon2):
        if not -180 <= lo <= 180: return None
    clat = (lat1 + lat2) / 2; clon = (lon1 + lon2) / 2
    MAX_SPAN = 5.0
    if abs(lat2 - lat1) > MAX_SPAN:
        lat1, lat2 = clat - MAX_SPAN / 2, clat + MAX_SPAN / 2
    if abs(lon2 - lon1) > MAX_SPAN:
        lon1, lon2 = clon - MAX_SPAN / 2, clon + MAX_SPAN / 2
    return lat1, lon1, lat2, lon2

# Overpass canlı sorguları için görünen alan; çok büyükse merkezde bu boyuta kırpılır
OVERPASS_MAX_SPAN = float(os.getenv("OVERPASS_MAX_SPAN", "0.5"))   # derece (~55 km)
_OVERPASS_ENDPOINTS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
]

def overpass_bbox(lat1, lon1, lat2, lon2, max_span=None):
    """Overpass (s,w,n,e) filtresi + kırpıldı mı bilgisi."""
    max_span = max_span or OVERPASS_MAX_SPAN
    s_, n_ = min(lat1, lat2), max(lat1, lat2)
    w_, e_ = min(lon1, lon2), max(lon1, lon2)
    clipped = False
    if n_ - s_ > max_span:
        c = (s_ + n_) / 2; s_, n_ = c - max_span / 2, c + max_span / 2; clipped = True
    if e_ - w_ > max_span:
        c = (w_ + e_) / 2; w_, e_ = c - max_span / 2, c + max_span / 2; clipped = True
    return f"{s_:.6f},{w_:.6f},{n_:.6f},{e_:.6f}", clipped

def overpass_query(query, timeout=28, ua="SignalOps/2.1"):
    """Overpass'a POST; ana sunucu meşgulse (429/504) aynaya geçer. Döner: (elements|None, hata)"""
    last = None
    for ep in _OVERPASS_ENDPOINTS:
        try:
            r = requests.post(ep, data={"data": query}, headers={"User-Agent": ua}, timeout=timeout)
            if r.status_code == 200:
                return r.json().get("elements", []), None
            last = f"HTTP {r.status_code}"
            if r.status_code not in (429, 502, 503, 504):
                break
        except Exception as e:
            last = str(e)[:40]
    return None, last

_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")

def clean_country(v):
    v = (v or "").strip().upper()
    return v if _COUNTRY_RE.match(v) else None

def norm_enc(e):
    """WiGLE 'none'/'wpa2'/'unknown' → 'OPEN'/'WPA2'/'UNKNOWN' (STB-06)."""
    e = str(e or "").strip().upper()
    if e in ("", "NONE", "OPEN", "NULL"):
        return "OPEN"
    return e

def parse_risk_level(text, fallback="LOW"):
    """Gemini cevabındaki 'RISK LEVEL: X' satırını ayrıştırır (STB-07)."""
    if not text:
        return fallback
    hits = re.findall(r"RISK\s*LEVEL\s*[:\-–]?\s*[*_#\s]*\b(CRITICAL|HIGH|MEDIUM|LOW)\b(?!\s*/)",
                      text.upper())
    return hits[-1] if hits else fallback

def gather_futures(futs, timeout, label="executor"):
    """as_completed + timeout; zaman aşımında biten sonuçları döndürür, kalanları bırakır.
    futs: {future: name}. Döner: {name: result}"""
    out = {}
    try:
        for fut in as_completed(futs, timeout=timeout):
            name = futs[fut]
            try:
                out[name] = fut.result()
            except CancelledError:
                pass
            except Exception as e:
                print(f"[{label}/{name}] error: {e}")
    except FuturesTimeout:
        pending = [futs[f] for f in futs if not f.done()]
        print(f"[{label}] timeout after {timeout}s — pending: {pending}")
    return out

# ══════════════════════════════════════════════
#  STATIC DATASETS (cameras / precincts / networks)
# ══════════════════════════════════════════════
# Large GeoJSON/JSON files loaded once at startup into RAM + grid spatial index.
# Files live under ./data/ by default (override with DATA_DIR env var).
#
# Expected files:
#   data/CAMERAS_WITH_NETWORK_DATA.geojson  — Point features, ~178k cameras
#   data/police_precincts_usa.geojson       — MultiPolygon features, ~272 precincts
#   data/camera_networks.json               — list of network-sharing records
#
# If files are missing, endpoints fall back to OSM Overpass alone (previous behavior).

DATA_DIR = _paths.data_dir()

_STATIC = {
    "cameras":         [],    # list of Point features
    "cameras_grid":    {},    # (row,col) -> [feature_idx, ...]
    "precincts":       [],    # list of MultiPolygon features (with precomputed bbox)
    "camera_networks": [],    # list of network-sharing records
    "loaded":          False,
}

_GRID_DEG = 0.5  # grid cell size in degrees (~55 km; small enough for speed, big enough to cap cell count)

def _grid_key(lat, lon):
    return (int(lat // _GRID_DEG), int(lon // _GRID_DEG))

def _grid_cells_in_bbox(lat1, lon1, lat2, lon2):
    la_lo, la_hi = min(lat1, lat2), max(lat1, lat2)
    lo_lo, lo_hi = min(lon1, lon2), max(lon1, lon2)
    r_lo = int(la_lo // _GRID_DEG); r_hi = int(la_hi // _GRID_DEG)
    c_lo = int(lo_lo // _GRID_DEG); c_hi = int(lo_hi // _GRID_DEG)
    return [(r, c) for r in range(r_lo, r_hi+1) for c in range(c_lo, c_hi+1)]

def _bbox_of_multipolygon(geom):
    """Compute [minLon, minLat, maxLon, maxLat] for a MultiPolygon or Polygon."""
    coords = geom.get("coordinates") or []
    xs, ys = [], []
    gtype = geom.get("type")
    if gtype == "Polygon":
        polys = [coords]
    elif gtype == "MultiPolygon":
        polys = coords
    else:
        return None
    for poly in polys:
        for ring in poly:
            for pt in ring:
                if len(pt) >= 2:
                    xs.append(pt[0]); ys.append(pt[1])
    if not xs:
        return None
    return [min(xs), min(ys), max(xs), max(ys)]

def _bboxes_overlap(a, b):
    """a,b = [minLon, minLat, maxLon, maxLat]"""
    return not (a[2] < b[0] or a[0] > b[2] or a[3] < b[1] or a[1] > b[3])

def _load_static_datasets():
    """Load static datasets into memory. Silent if files missing; logs counts otherwise."""
    if _STATIC["loaded"]:
        return

    # Cameras
    cam_path = os.path.join(DATA_DIR, "CAMERAS_WITH_NETWORK_DATA.geojson")
    if os.path.isfile(cam_path):
        try:
            t0 = time.time()
            with open(cam_path, "r", encoding="utf-8") as f:
                gj = json.load(f)
            grid = {}
            valid = []
            for feat in gj.get("features", []):
                geom = feat.get("geometry") or {}
                if geom.get("type") != "Point":
                    continue
                coords = geom.get("coordinates") or []
                if len(coords) < 2:
                    continue
                try:
                    lon, lat = float(coords[0]), float(coords[1])
                except (TypeError, ValueError):
                    continue
                idx = len(valid)
                valid.append(feat)
                grid.setdefault(_grid_key(lat, lon), []).append(idx)
            _STATIC["cameras"] = valid
            _STATIC["cameras_grid"] = grid
            print(f"[datasets] cameras: {len(valid)} points in {len(grid)} grid cells ({time.time()-t0:.1f}s)")
        except Exception as e:
            print(f"[datasets] cameras load error: {e}")
    else:
        print(f"[datasets] cameras file not found at {cam_path} (OSM-only mode)")

    # Cameras — tile-based dataset (data/tiles/{z}/{x}/{y}.json)
    # Merges into the same grid index. Dedup by rounded coord to avoid double-counting
    # between this dataset and the CAMERAS_WITH_NETWORK_DATA.geojson above.
    tiles_dir = os.path.join(DATA_DIR, "tiles")
    if os.path.isdir(tiles_dir):
        try:
            t0 = time.time()
            # Build a set of existing coords (rounded to 5 decimals ≈ 1.1 m precision)
            # so the tile data can dedup against the primary cameras file.
            existing = set()
            for feat in _STATIC["cameras"]:
                c = feat["geometry"]["coordinates"]
                existing.add((round(c[1], 5), round(c[0], 5)))

            tile_added = 0
            net_added  = 0
            networks_out = list(_STATIC.get("camera_networks", []))
            tiles_scanned = 0

            for z in os.listdir(tiles_dir):
                z_path = os.path.join(tiles_dir, z)
                if not os.path.isdir(z_path):
                    continue
                for x in os.listdir(z_path):
                    x_path = os.path.join(z_path, x)
                    if not os.path.isdir(x_path):
                        continue
                    for y in os.listdir(x_path):
                        if not y.endswith(".json"):
                            continue
                        try:
                            with open(os.path.join(x_path, y), "r", encoding="utf-8") as tf:
                                td = json.load(tf)
                        except Exception:
                            continue
                        tiles_scanned += 1
                        # Camera features
                        for feat in td.get("features", []):
                            geom = feat.get("geometry") or {}
                            if geom.get("type") != "Point":
                                continue
                            coords = geom.get("coordinates") or []
                            if len(coords) < 2:
                                continue
                            try:
                                lon, lat = float(coords[0]), float(coords[1])
                            except (TypeError, ValueError):
                                continue
                            key = (round(lat, 5), round(lon, 5))
                            if key in existing:
                                continue
                            existing.add(key)
                            idx = len(_STATIC["cameras"])
                            _STATIC["cameras"].append(feat)
                            _STATIC["cameras_grid"].setdefault(_grid_key(lat, lon), []).append(idx)
                            tile_added += 1
                        # Network records (tile-scoped)
                        for net in td.get("networks", []) or []:
                            if isinstance(net, dict):
                                networks_out.append(net)
                                net_added += 1
            _STATIC["camera_networks"] = networks_out
            print(f"[datasets] tiles: scanned {tiles_scanned} tiles, added {tile_added} new cameras + {net_added} networks ({time.time()-t0:.1f}s)")
            print(f"[datasets] cameras total: {len(_STATIC['cameras'])} in {len(_STATIC['cameras_grid'])} grid cells")
        except Exception as e:
            print(f"[datasets] tiles load error: {e}")

    # Precincts (MultiPolygon)
    pre_path = os.path.join(DATA_DIR, "police_precincts_usa.geojson")
    if os.path.isfile(pre_path):
        try:
            t0 = time.time()
            with open(pre_path, "r", encoding="utf-8") as f:
                gj = json.load(f)
            precincts = []
            for feat in gj.get("features", []):
                geom = feat.get("geometry") or {}
                if geom.get("type") not in ("Polygon", "MultiPolygon"):
                    continue
                bbox = _bbox_of_multipolygon(geom)
                if bbox is None:
                    continue
                feat["_bbox"] = bbox  # cache for fast intersect test
                precincts.append(feat)
            _STATIC["precincts"] = precincts
            print(f"[datasets] precincts: {len(precincts)} polygons ({time.time()-t0:.1f}s)")
        except Exception as e:
            print(f"[datasets] precincts load error: {e}")
    else:
        print(f"[datasets] precincts file not found at {pre_path} (OSM-only mode)")

    # Camera networks (sharing metadata — keyed lookups by source camera id)
    net_path = os.path.join(DATA_DIR, "camera_networks.json")
    if os.path.isfile(net_path):
        try:
            t0 = time.time()
            with open(net_path, "r", encoding="utf-8") as f:
                cn = json.load(f)
            if isinstance(cn, list):
                # tile'lardan gelen network kayıtlarını ezme — birleştir
                _STATIC["camera_networks"] = cn + list(_STATIC.get("camera_networks") or [])
                print(f"[datasets] camera_networks: {len(cn)} records ({time.time()-t0:.1f}s)")
            else:
                print(f"[datasets] camera_networks: unexpected type {type(cn).__name__}")
        except Exception as e:
            print(f"[datasets] camera_networks load error: {e}")

    _STATIC["loaded"] = True

def _cameras_in_bbox(lat1, lon1, lat2, lon2, limit=1000):
    """Fast grid-based bbox lookup for camera points. Returns list of features."""
    la_lo, la_hi = min(lat1, lat2), max(lat1, lat2)
    lo_lo, lo_hi = min(lon1, lon2), max(lon1, lon2)
    out = []
    cells = _grid_cells_in_bbox(lat1, lon1, lat2, lon2)
    grid = _STATIC["cameras_grid"]
    cams = _STATIC["cameras"]
    for cell in cells:
        for idx in grid.get(cell, []):
            feat = cams[idx]
            coords = feat["geometry"]["coordinates"]
            lon, lat = coords[0], coords[1]
            if la_lo <= lat <= la_hi and lo_lo <= lon <= lo_hi:
                out.append(feat)
                if len(out) >= limit:
                    return out
    return out

def _is_alpr_camera(props):
    """Detect if a camera feature is an ALPR / Flock-style device based on OSM tags."""
    if not props:
        return False
    # Primary tags (DeFlock tagging convention)
    for key in ("surveillance:type", "camera:type", "surveillance:zone"):
        v = str(props.get(key, "")).lower()
        if "alpr" in v or "lpr" in v:
            return True
    # Manufacturer / operator hints
    for key in ("manufacturer", "operator", "brand"):
        v = str(props.get(key, "")).lower()
        if "flock" in v or "motorola alpr" in v or "rekor" in v or "genetec" in v or "vigilant" in v:
            return True
    return False

def _alpr_cameras_in_bbox(lat1, lon1, lat2, lon2, limit=1000):
    """Like _cameras_in_bbox but filters to ALPR / Flock-style devices only."""
    la_lo, la_hi = min(lat1, lat2), max(lat1, lat2)
    lo_lo, lo_hi = min(lon1, lon2), max(lon1, lon2)
    out = []
    cells = _grid_cells_in_bbox(lat1, lon1, lat2, lon2)
    grid = _STATIC["cameras_grid"]
    cams = _STATIC["cameras"]
    for cell in cells:
        for idx in grid.get(cell, []):
            feat = cams[idx]
            coords = feat["geometry"]["coordinates"]
            lon, lat = coords[0], coords[1]
            if not (la_lo <= lat <= la_hi and lo_lo <= lon <= lo_hi):
                continue
            if _is_alpr_camera(feat.get("properties")):
                out.append(feat)
                if len(out) >= limit:
                    return out
    return out

def _precincts_in_bbox(lat1, lon1, lat2, lon2, limit=200):
    """Bbox-intersect test against precinct polygons (via cached feature bbox)."""
    query_bbox = [min(lon1, lon2), min(lat1, lat2), max(lon1, lon2), max(lat1, lat2)]
    out = []
    for feat in _STATIC["precincts"]:
        if _bboxes_overlap(feat.get("_bbox"), query_bbox):
            # Strip the cached bbox from the feature we return to the client
            clean = {k: v for k, v in feat.items() if k != "_bbox"}
            out.append(clean)
            if len(out) >= limit:
                break
    return out

# Kick off the load now (blocking at import-time — files are only read once).
_load_static_datasets()

# ══════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════
# ── API anahtarları: Settings arayüzü (config/keys.json) > .env ──────────
# Arayüzden kaydedilen değer .env'deki değerin önüne geçer. Arayüzde "temizle"
# denirse .env'deki değere (varsa) geri dönülür. Değişiklikler yeniden başlatma
# gerektirmeden anında uygulanır (_apply_keys modül global'lerini günceller).

CONFIG_DIR  = _paths.config_dir()
KEYS_FILE   = os.path.join(CONFIG_DIR, "keys.json")
_keys_lock  = threading.Lock()

# (env adı, modül global adı, etiket, grup, sağlayıcı-id, gizli mi, anahtar alma linki)
KEY_SCHEMA = [
    ("WIGLE_API_NAME",     "WIGLE_USER",     "WiGLE API Name",       "WiFi / Bluetooth / Cell", "wigle",      False, "https://wigle.net/account"),
    ("WIGLE_API_TOKEN",    "WIGLE_TOKEN",    "WiGLE API Token",      "WiFi / Bluetooth / Cell", "wigle",      True,  "https://wigle.net/account"),
    ("OPENCELLID_API_KEY", "OPENCELLID_KEY", "OpenCellID",           "WiFi / Bluetooth / Cell", "opencellid", True,  "https://opencellid.org/register.php"),
    ("SHODAN_API_KEY",     "SHODAN_KEY",     "Shodan",               "Internet Scanners",       "shodan",     True,  "https://account.shodan.io"),
    ("CENSYS_API_ID",      "CENSYS_ID",      "Censys API ID",        "Internet Scanners",       "censys",     False, "https://search.censys.io/account/api"),
    ("CENSYS_API_SECRET",  "CENSYS_SECRET",  "Censys API Secret",    "Internet Scanners",       "censys",     True,  "https://search.censys.io/account/api"),
    ("ZOOMEYE_API_KEY",    "ZOOMEYE_KEY",    "ZoomEye",              "Internet Scanners",       "zoomeye",    True,  "https://www.zoomeye.ai/profile"),
    ("FOFA_EMAIL",         "FOFA_EMAIL",     "FOFA Email",           "Internet Scanners",       "fofa",       False, "https://fofa.info/userInfo"),
    ("FOFA_API_KEY",       "FOFA_KEY",       "FOFA API Key",         "Internet Scanners",       "fofa",       True,  "https://fofa.info/userInfo"),
    ("HUNTERHOW_API_KEY",  "HUNTERHOW_KEY",  "Hunter.how",           "Internet Scanners",       "hunterhow",  True,  "https://hunter.how/search-api"),
    ("NETLAS_API_KEY",     "NETLAS_KEY",     "Netlas",               "Internet Scanners",       "netlas",     True,  "https://app.netlas.io/profile/"),
    ("LEAKIX_API_KEY",     "LEAKIX_KEY",     "LeakIX",               "Internet Scanners",       "leakix",     True,  "https://leakix.net/settings/api"),
    ("CRIMINALIP_API_KEY", "CRIMINALIP_KEY", "Criminal IP",          "Internet Scanners",       "criminalip", True,  "https://www.criminalip.io/mypage/information"),
    ("BINARYEDGE_API_KEY", "BINARYEDGE_KEY", "BinaryEdge",           "Internet Scanners",       "binaryedge", True,  "https://app.binaryedge.io/account/api"),
    ("WINDY_API_KEY",      "WINDY_KEY",      "Windy Webcams",        "Cameras & Reputation",    "windy",      True,  "https://api.windy.com/keys"),
    ("ABUSEIPDB_API_KEY",  "ABUSEIPDB_KEY",  "AbuseIPDB",            "Cameras & Reputation",    "abuseipdb",  True,  "https://www.abuseipdb.com/account/api"),
    ("ADSB_API_KEY",       "ADSB_KEY",       "adsb.fi (opsiyonel)",  "Air & Radio",             "adsb",       True,  "https://adsb.fi"),
    ("APRS_FI_KEY",        "APRS_FI_KEY",    "APRS.fi",              "Air & Radio",             "aprs",       True,  "https://aprs.fi/page/api"),
    ("GEMINI_API_KEY",     "GEMINI_KEY",     "Gemini API Key",       "AI",                      "gemini",     True,  "https://aistudio.google.com/apikey"),
    ("GEMINI_MODEL",       "GEMINI_MODEL",   "Gemini Model",         "AI",                      "gemini",     False, "https://ai.google.dev/gemini-api/docs/models"),
    ("WSDOT_ACCESS_CODE",  "WSDOT_ACCESS_CODE", "WSDOT Cameras (WA, US)", "Cameras & Reputation", "wsdot",     True,  "https://wsdot.wa.gov/traffic/api/"),
    ("TRAFIKVERKET_API_KEY", "TRAFIKVERKET_API_KEY", "Trafikverket Cameras (SE)", "Cameras & Reputation", "trafikverket", True, "https://data.trafikverket.se/"),
    ("CARTO_API_KEY",      "CARTO_API_KEY",  "CARTO Basemaps (opsiyonel)", "Maps",              "carto",      True,  "https://www.carto.com/basemaps/apikey/"),
    ("AISSTREAM_API_KEY",  "AISSTREAM_KEY",  "aisstream.io (AIS)",   "Maritime",                "aisstream",  True,  "https://aisstream.io/apikeys"),
    ("NOTIFY_WEBHOOK_URL", "NOTIFY_WEBHOOK_URL", "Webhook URL",        "Notifications",         "webhook",    True,  "https://en.wikipedia.org/wiki/Webhook"),
    ("NPS_API_KEY",        "NPS_API_KEY",    "NPS Webcams (US parks)", "Cameras & Reputation",  "nps",        True,  "https://www.nps.gov/subjects/developer/get-started.htm"),
    ("ONTARIO511_KEY",     "ONTARIO511_KEY", "511 Ontario Cameras (CA)", "Cameras & Reputation", "on511",      True,  "https://511on.ca/developers/doc"),
    ("ALBERTA511_KEY",     "ALBERTA511_KEY", "511 Alberta Cameras (CA)", "Cameras & Reputation", "ab511",      True,  "https://511.alberta.ca/developers/doc"),
    ("GEORGIA511_KEY",     "GEORGIA511_KEY", "511 Georgia Cameras (US)", "Cameras & Reputation", "ga511",      True,  "https://511ga.org/developers/doc"),
    ("FL511_KEY",          "FL511_KEY",      "FL511 Cameras (US)",   "Cameras & Reputation",    "fl511",      True,  "https://fl511.com/developers/doc"),
    ("REPEATERBOOK_TOKEN", "REPEATERBOOK_TOKEN", "RepeaterBook App Token", "Air & Radio",       "repeaterbook", True, "https://www.repeaterbook.com/wiki/doku.php?id=api"),
    ("PSKREPORTER_CONTACT", "PSKREPORTER_CONTACT", "PSKReporter contact e-mail (opsiyonel)", "Air & Radio", "pskreporter", False, "https://pskreporter.info/pskdev.html"),
]
_KEY_IDS   = {k[0] for k in KEY_SCHEMA}
_DEFAULTS  = {"GEMINI_MODEL": "gemini-2.0-flash"}
_ENV_SNAPSHOT = {k[0]: (os.getenv(k[0]) or "").strip() for k in KEY_SCHEMA}  # .env/ortam değerleri (başlangıç)

def _load_ui_keys():
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        return {k: str(v).strip() for k, v in d.items() if k in _KEY_IDS and isinstance(v, (str, int)) and str(v).strip()}
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[settings] {KEYS_FILE} okunamadı: {e}")
        return {}

def _save_ui_keys(d):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    try: os.chmod(CONFIG_DIR, 0o700)
    except OSError: pass
    fd, tmp = tempfile.mkstemp(prefix=".keys-", suffix=".json", dir=CONFIG_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, sort_keys=True)
        try: os.chmod(tmp, 0o600)
        except OSError: pass
        os.replace(tmp, KEYS_FILE)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise

def _effective_keys():
    ui = _load_ui_keys()
    out = {}
    for env_name, *_ in KEY_SCHEMA:
        if ui.get(env_name):
            out[env_name] = (ui[env_name], "ui")
        elif _ENV_SNAPSHOT.get(env_name):
            out[env_name] = (_ENV_SNAPSHOT[env_name], "env")
        else:
            out[env_name] = (_DEFAULTS.get(env_name, ""), "default" if env_name in _DEFAULTS else None)
    return out

def _apply_keys():
    """Etkin anahtarları modül global'lerine yazar — fetcher'lar çağrı anında okur."""
    with _keys_lock:
        eff = _effective_keys()
        g = globals()
        for env_name, gname, *_ in KEY_SCHEMA:
            g[gname] = eff[env_name][0]
        return eff

# Açık tanımlar (okunabilirlik/linter için) — gerçek değerleri _apply_keys() yazar
WIGLE_USER = WIGLE_TOKEN = OPENCELLID_KEY = SHODAN_KEY = CENSYS_ID = CENSYS_SECRET = ""
ZOOMEYE_KEY = FOFA_EMAIL = FOFA_KEY = HUNTERHOW_KEY = NETLAS_KEY = LEAKIX_KEY = ""
CRIMINALIP_KEY = BINARYEDGE_KEY = WINDY_KEY = ABUSEIPDB_KEY = ADSB_KEY = APRS_FI_KEY = ""
GEMINI_KEY = AISSTREAM_KEY = NOTIFY_WEBHOOK_URL = CARTO_API_KEY = ""
WSDOT_ACCESS_CODE = TRAFIKVERKET_API_KEY = ""
NPS_API_KEY = ONTARIO511_KEY = ALBERTA511_KEY = GEORGIA511_KEY = FL511_KEY = REPEATERBOOK_TOKEN = PSKREPORTER_CONTACT = ""
GEMINI_MODEL = _DEFAULTS["GEMINI_MODEL"]
_apply_keys()

def get_key(env_name):
    """Modüller için: anahtarın etkin (UI > .env) değeri."""
    for e, gname, *_ in KEY_SCHEMA:
        if e == env_name:
            return globals().get(gname) or ""
    return ""

# ── Sağlayıcı sağlık katmanı: kota/yetki/hız sınırı → sağlayıcı geçici atlanır (modules/health.py) ──
try:
    from .modules import health as _health
    _health.install()
    def _key_fp(label):
        import hashlib
        pid = next((p[1] for p in _health.PROVIDERS if p[0] == label), None)
        vals = "|".join(globals().get(g) or "" for _e, g, _l, _gr, prov, *_ in KEY_SCHEMA if prov == pid)
        return hashlib.sha256(vals.encode()).hexdigest()[:16]
    _health.set_key_fingerprint_fn(_key_fp)
except Exception as _e:          # modül yoksa uygulama eskisi gibi çalışır
    print(f"[health] disabled: {_e}")
    _health = None

def _hblocked(label):
    """Sağlayıcı şu an engelli mi (kota/yetki/cooldown)? Fetcher'lar döngüye girmeden çıkar."""
    return bool(_health and _health.is_blocked(label))

def _ai_unavailable(e=None):
    """Gemini hatası → kullanıcıya gösterilen 'AI unavailable' metni; sağlık durumunu günceller."""
    reason = ""
    if _health is not None:
        if e is not None and not isinstance(e, ImportError):
            try: _health.classify_exception("Gemini", e)
            except Exception: pass
        b = _health.blocked("Gemini")
        if b:
            st, _r, until = b
            label = {"quota": "quota exhausted", "auth": "API key rejected",
                     "cooldown": "rate limited", "down": "service unreachable"}.get(st, st)
            when = (" — retry after " + datetime.fromtimestamp(until, timezone.utc).strftime("%H:%M UTC")) if until else ""
            reason = f" ({label}{when})"
    if not reason and e is not None:
        reason = f" ({type(e).__name__})"
    return f"⚠ AI unavailable{reason} — scan results are shown without AI analysis."

T = 8  # default timeout

# ══════════════════════════════════════════════
#  ARC-15: Koordinat validation
# ══════════════════════════════════════════════
def validate_coords(lat, lon):
    try:
        lat = float(lat); lon = float(lon)
        if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            return None, None
        return lat, lon
    except (TypeError, ValueError):
        return None, None


# ══════════════════════════════════════════════
#  GEO HELPERS (BUG-10: TTLCache)
# ══════════════════════════════════════════════
_geo_lock = threading.Lock()

def get_country_iso(lat, lon) -> str:
    key = (round(lat, 1), round(lon, 1))
    with _geo_lock:
        if key in _geo_cache:
            return _geo_cache[key]
    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json", "zoom": 5},
            headers={"User-Agent": "SignalOPS/2.0 (security-research)"},
            timeout=5
        )
        if r.status_code == 200:
            cc = r.json().get("address", {}).get("country_code", "").upper()
            with _geo_lock:
                try: _geo_cache[key] = cc
                except Exception: pass
            return cc
    except Exception:
        pass
    with _geo_lock:
        try: _geo_cache[key] = ""
        except Exception: pass
    return ""

# ══════════════════════════════════════════════
#  DEVICE TRACKING
# ══════════════════════════════════════════════
try:
    device_history = TTLCache(maxsize=50000, ttl=7 * 24 * 3600)
except NameError:
    device_history = {}
device_lock = threading.Lock()

def track_devices(devices):
    now = int(time.time())
    for d in devices:
        key = d.get("ip") or d.get("bssid") or f"{d.get('ssid')}_{d.get('lat')}_{d.get('lon')}"
        if not key:
            continue
        with device_lock:
            if key not in device_history:
                device_history[key] = {"first_seen": now, "last_seen": now, "count": 1}
            else:
                device_history[key]["last_seen"] = now
                device_history[key]["count"] += 1
            d["seen_count"] = device_history[key]["count"]
            d["last_seen"]  = device_history[key]["last_seen"]
    return devices

# ══════════════════════════════════════════════
#  COUNTRY-BASED FETCHERS (Shodan / ZoomEye)
# ══════════════════════════════════════════════
def fetch_shodan_country(country):
    if not SHODAN_KEY or _hblocked("Shodan"): return []
    results = []
    try:
        query = f"port:554 country:{country}"
        r = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": SHODAN_KEY, "query": query},
            timeout=10)
        if r.status_code == 200:
            for m in r.json().get("matches", []):
                results.append({
                    "ip": m.get("ip_str"), "port": m.get("port"),
                    "country": country, "type": "camera",
                    "source": "shodan", "risk": 80
                })
    except Exception as e:
        print(f"[Shodan country] {e}")
    return results

def fetch_zoomeye_country(country):
    if not ZOOMEYE_KEY: return []
    results = []
    try:
        r = requests.get(
            "https://api.zoomeye.org/host/search",
            params={"query": f"port:554 country:{country}"},
            headers={"API-KEY": ZOOMEYE_KEY}, timeout=10)
        if r.status_code == 200:
            for m in r.json().get("matches", []):
                results.append({
                    "ip": m.get("ip"),
                    "port": m.get("portinfo", {}).get("port"),
                    "country": country, "type": "camera",
                    "source": "zoomeye", "risk": 75
                })
    except Exception as e:
        print(f"[ZoomEye country] {e}")
    return results

# ══════════════════════════════════════════════
#  BUG-19: Insecam — country-code tabanlı fetcher
# ══════════════════════════════════════════════
def fetch_cameras_insecam_by_country(country: str) -> list:
    """
    insecam.org ülke dizin sayfalarını parse eder (max 3 sayfa).
    country : ISO-2 kodu  örn. TR, US, DE
    HTTP zorunlu — insecam.org HTTPS sunmuyor.
    """
    out = []
    if not country:
        return out

    country = country.upper()
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    }

    def _extract(html: str) -> list:
        pairs = re.findall(
            r'http://((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})',
            html
        )
        def _public(ip):
            try:
                o = ipaddress.ip_address(ip)
                return not (o.is_private or o.is_loopback or o.is_reserved or o.is_link_local)
            except ValueError:
                return False
        return [(ip, port) for ip, port in pairs if _public(ip)]

    try:
        base_url = f"http://www.insecam.org/en/bycountry/{country}/"
        r = requests.get(base_url, headers=headers, timeout=12)
        if r.status_code != 200:
            print(f"[Insecam] HTTP {r.status_code} country={country}")
            return []

        m = re.search(r'pagenavigator\("\?page=",\s*(\d+)', r.text)
        total_pages = min(int(m.group(1)), 3) if m else 1

        raw = _extract(r.text)
        for page in range(1, total_pages):
            try:
                rp = requests.get(f"{base_url}?page={page}",
                                  headers=headers, timeout=10)
                if rp.status_code == 200:
                    raw.extend(_extract(rp.text))
            except Exception as e:
                print(f"[Insecam] page {page}: {e}")
                break

        seen, unique = set(), []
        for ip, port in raw:
            k = f"{ip}:{port}"
            if k not in seen:
                seen.add(k)
                unique.append((ip, port))

        for ip, port in unique[:30]:
            out.append({
                "lat": None, "lon": None,
                "ip": ip, "port": int(port),
                "ssid": f"Insecam [{country}]",
                "banner": f"Open CCTV stream — {country}",
                "country": country,
                "type": "camera", "source": "insecam",
                "stream_url": f"http://{ip}:{port}/",
                "risk": 85, "auth": False,
            })
    except Exception as e:
        print(f"[Insecam] {e}")

    print(f"[Insecam] country={country} → {len(out)} cameras")
    return out

# ══════════════════════════════════════════════
#  BUG-20: EarthCam — country-code tabanlı fetcher
# ══════════════════════════════════════════════
# EarthCam uses two URL formats:
#   1. US states:  /network/?country=US&page=NY       (state code)
#   2. World:       /network/?page=world&country=<Full Name>
#
# The old /network/<slug>/ format returns 404 — was removed from EarthCam a while back.
# Query params match the country selector on https://www.earthcam.com/network/

# ISO country code → full country name used by EarthCam's /network/?page=world selector
_EARTHCAM_COUNTRY_NAMES = {
    "US": "__US_STATES__",    # Special: handled via page=<STATE_CODE>
    "GB": "England",          # EarthCam uses England (also Wales exists separately)
    "DE": "Germany",
    "IT": "Italy",
    "ES": "Spain",
    "NL": "Netherlands",
    "IE": "Ireland",
    "IL": "Israel",
    "HU": "Hungary",
    "RU": "Russian Federation",
    "KR": "South Korea",
    "ZA": "South Africa",
    "CA": "Canada",
    "NZ": "New Zealand",
    "ID": "Indonesia",
    "CR": "Costa Rica",
    "TW": "Taiwan",
    "TZ": "Tanzania",
    "HN": "Honduras",
    "HK": "Hong Kong",
    "PE": "Peru",
    "JM": "Jamaica",
    "BW": "Botswana",
    "BS": "Bahamas",
    "BM": "Bermuda",
    "AW": "Aruba",
    "AI": "Anguilla",
    "KY": "Cayman Islands",
    "PR": "Puerto Rico",
    "SX": "Sint Maarten",
    "VG": "Virgin Islands, British",
    "VI": "Virgin Islands, U.S.",
    "MP": "Northern Mariana Islands",
    "GE": "Georgia",
}

def fetch_earthcam_by_country(country: str) -> list:
    """
    Fetch public webcams from EarthCam for the given ISO country code.
    Uses the /network/ page with query params (since /network/<slug>/ URLs 404).
    Returns [] for countries not in EarthCam's network — this is expected behavior,
    NOT an error (e.g. Turkey has no EarthCam cameras).
    """
    out = []
    if not country:
        return out

    country = country.upper()
    mapped  = _EARTHCAM_COUNTRY_NAMES.get(country)

    if not mapped:
        # Not an EarthCam-supported country — silently return empty
        print(f"[EarthCam] country={country} not in EarthCam's network, skipping")
        return []

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": "https://www.earthcam.com/network/",
    }

    try:
        if mapped == "__US_STATES__":
            # US has 50 state pages; pull a small sample (NY, CA, TX, FL, WA) for country-wide scan
            html_chunks = []
            for state in ("NY", "CA", "TX", "FL", "WA"):
                try:
                    r = requests.get(
                        "https://www.earthcam.com/network/",
                        params={"country": "US", "page": state},
                        headers=headers, timeout=10,
                    )
                    if r.status_code == 200:
                        html_chunks.append(r.text)
                except Exception:
                    continue
            html = "\n".join(html_chunks)
        else:
            # World country: page=world, country=<Name>
            r = requests.get(
                "https://www.earthcam.com/network/",
                params={"page": "world", "country": mapped},
                headers=headers, timeout=12,
            )
            if r.status_code != 200:
                print(f"[EarthCam] HTTP {r.status_code} country={country}/{mapped}")
                return []
            html = r.text

        if not html:
            return []

        # EarthCam renders camera listings via JavaScript — static HTML usually doesn't contain
        # webid markers anymore. We try to parse what we can, but a 0-result response is normal
        # (not an error). The Insecam + OSM fetchers cover the same country-level use case.
        webids = list(dict.fromkeys(
            re.findall(r'"webid"\s*:\s*"(\w+)"', html) +
            re.findall(r'data-webid=["\'](\w+)["\']', html) +
            re.findall(r'/cams/embed/\?camid=(\w+)', html)
        ))
        if not webids:
            # Silent: EarthCam's dynamic pages return 0 IDs without JS execution.
            # This is expected — no need to log a warning.
            return []

        titles   = re.findall(r'"title"\s*:\s*"([^"]+)"', html)
        lats_raw = re.findall(r'"lat"\s*:\s*"?([\-\d\.]+)"?', html)
        lngs_raw = re.findall(r'"(?:lng|lon)"\s*:\s*"?([\-\d\.]+)"?', html)
        cities   = re.findall(r'"city"\s*:\s*"([^"]+)"', html)

        for i, wid in enumerate(webids[:25]):
            title = titles[i]    if i < len(titles)   else "EarthCam Webcam"
            lat   = sf(lats_raw[i]) if i < len(lats_raw) else None
            lon   = sf(lngs_raw[i]) if i < len(lngs_raw) else None
            city  = cities[i]    if i < len(cities)   else ""

            out.append({
                "lat": lat, "lon": lon,
                "ip": f"earthcam:{wid}", "port": 443,
                "ssid": title,
                "banner": "EarthCam: " + title + (f" — {city}" if city else ""),
                "country": country, "city": city,
                "type": "camera", "source": "earthcam",
                "stream_url": f"https://www.earthcam.com/cams/embed/?camid={wid}",
                "thumb_url":  f"https://www.earthcam.com/network/thumbnail.jpg?camid={wid}",
                "risk": 20, "auth": True,
            })
    except Exception as e:
        print(f"[EarthCam] {e}")

    print(f"[EarthCam] country={country}/{mapped} → {len(out)} cameras")
    return out

# ══════════════════════════════════════════════
#  CLASSIFY (BUG-01: kamera kontrolü TV'den önce)
# ══════════════════════════════════════════════
def classify(name, fallback="iot_device"):
    if not name: return fallback
    n = str(name).upper()
    if any(k in n for k in ["CAR","FORD","TOYOTA","BMW","TESLA","MAZDA","HONDA",
        "UCONNECT","HYUNDAI","LEXUS","NISSAN","MERCEDES","AUDI","VW","RENAULT","FIAT"]):
        return "car"
    if any(k in n for k in ["HEADPHONE","EARBUD","BOSE","SONY","BEATS","AUDIO",
        "AIRPOD","JBL","SENNHEISER","JABRA"]): return "headphone"
    if any(k in n for k in ["DASHCAM","DASH CAM","DVR","70MAI","VIOFO","NEXTBASE","BLACKVUE"]):
        return "dashcam"
    if any(k in n for k in ["CCTV","CAM","SURVEILLANCE","SECURITY","NEST","RING","ARLO",
        "HIKVISION","DAHUA","REOLINK","AMCREST","AXIS","FOSCAM","WYZE","EUFY","TAPO","RTSP",
        "WEBCAM","IP CAMERA","NETWORK CAMERA","LIVE VIEW","DVR LOGIN"]):
        return "camera"
    if any(k in n for k in ["BRAVIA","VIZIO","SAMSUNG","LG","ROKU","FIRE",
        "SMARTVIEW","KDL-","HISENSE","TCL","PHILIPS"]) or \
       n.strip().endswith(" TV") or " TV " in n or n.strip() == "TV":
        return "tv"
    if any(k in n for k in ["AIRTAG","TILE","SMARTTAG","CHIPOLO"]): return "tracker"
    if any(k in n for k in ["DJI","PHANTOM","MAVIC","DRONE","UAV","PARROT"]): return "drone"
    if any(k in n for k in ["ELM327","OBD","OBDII","VEEPEAK"]): return "obd"
    return fallback

def sf(v):
    try: return float(v) if v not in (None, "", "null") else None
    except: return None

def jit(r=0.004): return random.uniform(-r, r)

def _loc(rlat, rlon, lat, lon):
    """Kaynağın verdiği koordinat varsa onu kullanır. Yoksa cihaz arama noktasının
    yakınına konur ve approx=True ile işaretlenir — haritada 'yaklaşık' gösterilir."""
    if rlat and rlon:
        return {"lat": rlat, "lon": rlon}
    return {"lat": lat + jit(), "lon": lon + jit(), "approx": True}

# Konumu IP coğrafi konumundan gelen kaynaklar (şehir seviyesi, cihazın gerçek yeri değil)
IP_GEO_SOURCES = {"shodan", "censys", "zoomeye", "hunterhow", "netlas", "leakix",
                  "criminalip", "fofa", "binaryedge", "insecam"}

def tag_loc_quality(devices):
    """loc_quality: exact (WiGLE/OSM/Windy/hücre) · ip (IP geolocation) · approx (konum yok)."""
    for d in devices:
        if d.get("approx"):
            d["loc_quality"] = "approx"
        elif d.get("lat") is None or d.get("lon") is None:
            d["loc_quality"] = "none"
        elif (d.get("source") or "").split("+")[0] in IP_GEO_SOURCES:
            d["loc_quality"] = "ip"
        else:
            d["loc_quality"] = "exact"
    return devices

def dedup(lst):
    seen, out = set(), []
    # Cell towers get special treatment: same (mcc, mnc, lac, cell_id) = same tower
    # regardless of source. Merge sources.
    cell_index = {}  # key -> output index

    for d in lst:
        if d.get("type") == "cell_tower":
            mcc = d.get("mcc"); mnc = d.get("mnc")
            lac = d.get("lac"); cid = d.get("cell_id")
            if mcc and mnc and cid:
                k = f"cell:{mcc}:{mnc}:{lac}:{cid}"
                if k in cell_index:
                    # Duplicate tower — merge source labels
                    existing = out[cell_index[k]]
                    existing_src = existing.get("source", "")
                    new_src = d.get("source", "")
                    if new_src and new_src not in existing_src:
                        existing["source"] = f"{existing_src}+{new_src}"
                    # Prefer non-None signal/operator/radio if current has better data
                    for fld in ("signal", "operator", "radio", "timestamp"):
                        if not existing.get(fld) and d.get(fld):
                            existing[fld] = d[fld]
                    continue
                cell_index[k] = len(out)
                out.append(d)
                continue
            # Cell tower without full ID — fall through to generic dedup
        ip   = d.get("ip") or ""
        port = str(d.get("port") or "")
        src  = d.get("source") or ""
        if ip:
            k = f"{ip}:{port}:{src}"
        else:
            lat = round(d.get("lat") or 0, 4)
            lon = round(d.get("lon") or 0, 4)
            k = f"{lat}:{lon}:{src}"
        if k not in seen:
            seen.add(k); out.append(d)
    return out

def score(d):
    s = 0
    t = d.get("type", "")
    if d.get("leaked"):                      s += 50
    if t == "camera":                          s += 30
    if t in ("drone", "tracker"):              s += 25
    if t == "obd":                             s += 20
    if t == "router" and norm_enc(d.get("encryption")) in ("WEP", "OPEN"): s += 20
    tags = d.get("tags") or []
    if "default-credentials" in tags: s += 35
    if "open-directory" in tags:      s += 25
    if "exposure" in tags:            s += 20
    vulns = d.get("vulns") or []
    s += min(len(vulns) * 10, 30)
    s += int((d.get("cip_score") or 0) * 0.4)
    return min(s, 100)

def analyze_area(devices):
    stats = {"wifi": 0, "open_wifi": 0, "cameras": 0, "bluetooth": 0, "suspicious": 0}
    for d in devices:
        t = d.get("type")
        if t == "router":
            stats["wifi"] += 1
            if norm_enc(d.get("encryption")) in ("OPEN", "WEP"):
                stats["open_wifi"] += 1
        elif t == "camera":   stats["cameras"] += 1
        elif t == "bluetooth": stats["bluetooth"] += 1
        if d.get("risk", 0) > 70: stats["suspicious"] += 1
    sc = stats["open_wifi"] * 2 + stats["cameras"] * 1.5 + stats["suspicious"] * 3
    level = "HIGH" if sc > 50 else "MEDIUM" if sc > 20 else "LOW"
    return {"stats": stats, "score": round(sc, 1), "level": level}

def detect_rogue_aps(devices):
    """
    Detect potential rogue / evil-twin access points using multiple signals:
      - Same SSID, multiple BSSIDs (duplicate SSID = possible evil twin)
      - Same SSID advertised with conflicting encryption (open vs WPA — karma attack signature)
      - BSSID belongs to a vendor OUI commonly used in attack platforms (WiFi Pineapple, etc.)
      - SSID matches known hotspot-hijacking patterns (empty, "xfinitywifi", "attwifi", airport-style)
    Returns a list of findings with severity and reason.
    """
    ssid_groups = {}
    for d in devices:
        if d.get("type") != "router":
            continue
        ssid  = d.get("ssid")
        bssid = d.get("bssid")
        if not ssid or not bssid:
            continue
        ssid_groups.setdefault(ssid, []).append(d)

    # OUI prefixes commonly found on attack hardware (Hak5 Pineapple, etc.)
    ATTACK_OUIS = {"00:13:37", "00:c0:ca", "00:1f:33", "9c:ef:d5"}
    # SSIDs commonly karma-attacked (auto-reconnect targets)
    KARMA_TARGETS = {"xfinitywifi", "attwifi", "optimumwifi", "spectrumwifi",
                     "eduroam", "linksys", "netgear", "dlink", "belkin54g",
                     "free wifi", "guest", "default"}

    rogue = []
    for ssid, group in ssid_groups.items():
        reasons = []
        severity = 0

        # Duplicate SSID — always a candidate
        bssids = list({d["bssid"] for d in group if d.get("bssid")})
        if len(bssids) > 1:
            reasons.append(f"{len(bssids)} BSSIDs share SSID (possible evil twin)")
            severity += 35

        # Encryption mismatch — same SSID offered open AND secured → classic karma signature
        encs = {(d.get("encryption") or "").upper() for d in group}
        has_open = any(e in ("", "OPEN", "NONE") or "OPEN" in e for e in encs)
        has_sec  = any("WPA" in e or "WEP" in e for e in encs)
        if has_open and has_sec:
            reasons.append("SSID offered both open and encrypted (karma signature)")
            severity += 40

        # Karma-target SSID + open encryption
        ssid_lower = (ssid or "").lower()
        if ssid_lower in KARMA_TARGETS and has_open:
            reasons.append(f"Known karma-target SSID '{ssid}' running open")
            severity += 25

        # Attack-hardware OUI
        for d in group:
            b = (d.get("bssid") or "").lower()[:8]
            if b in ATTACK_OUIS:
                reasons.append(f"Attack-hardware OUI detected: {b}")
                severity += 45
                break

        # Hidden / empty SSID broadcast
        if not ssid.strip():
            reasons.append("Empty SSID broadcast (beacon flood signature)")
            severity += 20

        if reasons:
            severity = min(severity, 100)
            rogue.append({
                "ssid":      ssid or "<hidden>",
                "count":     len(bssids),
                "bssids":    bssids,
                "severity":  severity,
                "reasons":   reasons,
                "level":     "CRITICAL" if severity >= 70 else "HIGH" if severity >= 45 else "MEDIUM",
            })
    # Sort by severity descending
    rogue.sort(key=lambda x: -x["severity"])
    return rogue

# Known Bluetooth tracker signatures (BLE manufacturer-name / device-name patterns)
BT_TRACKER_PATTERNS = [
    # (pattern, tracker_brand, concern_level)
    ("airtag",            "Apple AirTag",           "HIGH"),
    ("findmy",            "Apple Find My accessory","HIGH"),
    ("tile",              "Tile tracker",           "MEDIUM"),
    ("smarttag",          "Samsung SmartTag",       "MEDIUM"),
    ("galaxy smarttag",   "Samsung SmartTag",       "MEDIUM"),
    ("chipolo",           "Chipolo tracker",        "MEDIUM"),
    ("pebblebee",         "Pebblebee tracker",      "MEDIUM"),
    ("nut find",          "Nut Find tracker",       "MEDIUM"),
    ("itag",              "Generic iTag",           "LOW"),
    ("trackr",            "TrackR",                 "LOW"),
]

# Apple's randomized "Offline Finding" broadcast — used by AirTags and Find My network
_APPLE_FINDMY_MAC_PREFIXES = ("4c:99:", "a4:ae:", "bc:ff:")

def detect_bt_trackers(devices):
    """
    Detect known Bluetooth tracker devices in a scan.
    Returns list of trackers with brand identification.
    """
    trackers = []
    for d in devices:
        # Only consider bluetooth / BLE devices
        t = (d.get("type") or "").lower()
        if t not in ("bluetooth", "ble"):
            continue
        name   = (d.get("ssid") or d.get("name") or "").lower()
        vendor = (d.get("vendor") or "").lower()
        bssid  = (d.get("bssid") or "").lower()
        haystack = name + " " + vendor

        brand    = None
        concern  = None
        reasons  = []

        for pat, b, c in BT_TRACKER_PATTERNS:
            if pat in haystack:
                brand   = b
                concern = c
                reasons.append(f"Name pattern matches '{pat}'")
                break

        # Apple Find My offline-finding MAC prefix (randomized but BLE-enabled)
        if not brand and d.get("ble") and bssid[:5] in _APPLE_FINDMY_MAC_PREFIXES:
            brand   = "Apple Find My (suspected)"
            concern = "MEDIUM"
            reasons.append(f"MAC prefix matches Apple Find My ({bssid[:5]})")

        if brand:
            trackers.append({
                "brand":     brand,
                "concern":   concern,
                "name":      d.get("ssid") or d.get("name") or "?",
                "bssid":     d.get("bssid"),
                "signal":    d.get("signal"),
                "lat":       d.get("lat"),
                "lon":       d.get("lon"),
                "reasons":   reasons,
                "timestamp": d.get("timestamp"),
            })
    # Deduplicate by BSSID if present
    seen = set()
    uniq = []
    for t in trackers:
        k = t.get("bssid") or (t.get("brand") + t.get("name"))
        if k in seen: continue
        seen.add(k); uniq.append(t)
    return uniq

def detect_imsi_catchers(towers):
    """
    Analyze cell tower scan results for IMSI catcher / Stingray signatures.
    Returns list of suspicious towers with reasons and severity.

    Detection heuristics (based on public research — Snoopsnitch, SeaGlass, etc.):
      1. Unrealistically strong signal (< -40 dBm) — indicates fake tower very close
      2. Radio downgrade — 2G (GSM) tower in an area dominated by 4G/5G
      3. Unknown / novel cell_id in an otherwise stable area
      4. MCC/MNC mismatch within same LAC — tower claims different operator
      5. Singleton LAC — one tower reports an LAC that no other tower uses
      6. Duplicate cell_id across different radios (cloned identity)
    """
    if not towers or len(towers) == 0:
        return []

    findings = []

    # Build aggregates
    radios_in_area = [t.get("radio", "").lower() for t in towers if t.get("radio")]
    radio_counts = {}
    for r in radios_in_area:
        radio_counts[r] = radio_counts.get(r, 0) + 1
    # Is this a modern area? (majority LTE/UMTS/NR)
    modern_count = sum(radio_counts.get(r, 0) for r in ("lte", "umts", "nr"))
    legacy_count = sum(radio_counts.get(r, 0) for r in ("gsm", "cdma"))
    area_is_modern = modern_count > legacy_count and modern_count >= 3

    # LAC occupancy map
    lac_map = {}        # lac -> list of towers
    cellid_map = {}     # cell_id -> list of towers
    mccmnc_in_lac = {}  # lac -> set of (mcc,mnc)
    for t in towers:
        lac = t.get("lac")
        cid = t.get("cell_id")
        mcc = t.get("mcc"); mnc = t.get("mnc")
        if lac is not None:
            lac_map.setdefault(str(lac), []).append(t)
            if mcc and mnc:
                mccmnc_in_lac.setdefault(str(lac), set()).add((str(mcc), str(mnc)))
        if cid:
            cellid_map.setdefault(str(cid), []).append(t)

    for t in towers:
        reasons = []
        severity = 0

        signal = t.get("signal")
        radio  = (t.get("radio") or "").lower()
        lac    = str(t.get("lac")) if t.get("lac") is not None else None
        cid    = str(t.get("cell_id")) if t.get("cell_id") else None
        mcc    = str(t.get("mcc")) if t.get("mcc") else None
        mnc    = str(t.get("mnc")) if t.get("mnc") else None

        # 1. Unrealistic signal strength (fake tower very close)
        try:
            sig = int(signal) if signal is not None else None
        except (ValueError, TypeError):
            sig = None
        # 0 = OpenCellID "bilinmiyor" değeri; pozitif değerler de geçersiz → yok say
        if sig is not None and -40 < sig < 0:
            reasons.append(f"Unrealistic signal ({sig} dBm) — fake tower likely very close")
            severity += 40

        # 2. Radio downgrade — GSM tower in modern area
        if area_is_modern and radio == "gsm":
            reasons.append("2G/GSM tower in a 4G/5G-dominated area (downgrade attack signature)")
            severity += 35

        # 3. Singleton LAC — LAC used by only this tower while rest of area uses other LACs
        if lac and len(lac_map.get(lac, [])) == 1 and len(lac_map) > 2:
            reasons.append(f"Isolated LAC {lac} — no other tower uses this LAC")
            severity += 25

        # 4. MCC/MNC mismatch within LAC (different operator in same LAC)
        if lac and mcc and mnc:
            operators = mccmnc_in_lac.get(lac, set())
            if len(operators) > 1:
                reasons.append(f"Multiple operators claim LAC {lac}: {', '.join(m+':'+n for m,n in operators)}")
                severity += 30

        # 5. Duplicate cell_id across radios (identity cloning)
        if cid:
            matching = cellid_map.get(cid, [])
            radios_for_cid = {(tt.get("radio") or "").lower() for tt in matching}
            if len(radios_for_cid) > 1:
                reasons.append(f"Cell ID {cid} appears across multiple radio types: {sorted(radios_for_cid)}")
                severity += 25

        # 6. Cell ID suspiciously low (common in test/fake towers, e.g. 1, 2, 65535)
        if cid and cid.isdigit():
            cid_int = int(cid)
            if cid_int in (1, 2, 3, 65534, 65535) or cid_int < 100:
                reasons.append(f"Suspicious cell ID value: {cid_int} (common in test/fake towers)")
                severity += 20

        if reasons:
            severity = min(severity, 100)
            findings.append({
                "cell_id":   t.get("cell_id"),
                "operator":  t.get("operator"),
                "radio":     t.get("radio"),
                "mcc":       t.get("mcc"),
                "mnc":       t.get("mnc"),
                "lac":       t.get("lac"),
                "signal":    t.get("signal"),
                "lat":       t.get("lat"),
                "lon":       t.get("lon"),
                "severity":  severity,
                "level":     "CRITICAL" if severity >= 70 else "HIGH" if severity >= 45 else "MEDIUM",
                "reasons":   reasons,
            })
    findings.sort(key=lambda x: -x["severity"])
    return findings

_last_scan_counts = {}
_anomaly_lock = threading.Lock()
def detect_anomaly(devices, lat=None, lon=None):
    """Aynı bölgenin (≈1 km) bir önceki taramasıyla karşılaştırır."""
    key = (round(lat, 2), round(lon, 2)) if lat is not None and lon is not None else "global"
    current = len(devices)
    with _anomaly_lock:
        prev = _last_scan_counts.get(key)
        _last_scan_counts[key] = current
        if len(_last_scan_counts) > 5000:
            _last_scan_counts.pop(next(iter(_last_scan_counts)))
    if prev is None:
        return None
    diff = current - prev
    if diff > 20:   return {"type": "SPIKE", "change": diff}
    elif diff < -20: return {"type": "DROP",  "change": diff}
    return None

def detect_open_cameras(devices):
    findings = []
    for d in devices:
        if d.get("type") == "camera" and not d.get("auth"):
            findings.append({
                "type": "camera_exposed", "severity": "HIGH",
                "title": "Open Camera",
                "description": f"{d.get('ip')} publicly accessible"
            })
    return findings

def run_modules(devices):
    return detect_open_cameras(devices)

# ══════════════════════════════════════════════
#  MCC/MNC → Operator + Country resolution
# ══════════════════════════════════════════════
# Offline database of most common MCC+MNC combinations.
# Avoids per-request external API calls and survives when mcc-mnc.net is down.
# Format: "MCC:MNC" → (operator, country_iso, country_name)
_MCC_MNC_DB = {
    # Turkey (286)
    "286:01": ("Turkcell",           "TR", "Turkey"),
    "286:02": ("Telsim / Vodafone",  "TR", "Turkey"),
    "286:03": ("Türk Telekom / Avea","TR", "Turkey"),
    "286:04": ("Aercell",            "TR", "Turkey"),
    # United States (310-316)
    "310:030": ("AT&T",       "US", "United States"),
    "310:070": ("AT&T",       "US", "United States"),
    "310:150": ("AT&T",       "US", "United States"),
    "310:170": ("AT&T",       "US", "United States"),
    "310:260": ("T-Mobile",   "US", "United States"),
    "310:410": ("AT&T",       "US", "United States"),
    "310:120": ("Sprint",     "US", "United States"),
    "311:480": ("Verizon",    "US", "United States"),
    "311:490": ("Sprint",     "US", "United States"),
    "312:530": ("Verizon",    "US", "United States"),
    # UK (234, 235)
    "234:10": ("O2",          "GB", "United Kingdom"),
    "234:15": ("Vodafone",    "GB", "United Kingdom"),
    "234:20": ("Three",       "GB", "United Kingdom"),
    "234:30": ("T-Mobile UK", "GB", "United Kingdom"),
    "234:33": ("Orange",      "GB", "United Kingdom"),
    "234:50": ("JT Global",   "GB", "United Kingdom"),
    "234:58": ("Manx Telecom","GB", "United Kingdom"),
    # Germany (262)
    "262:01": ("Telekom Deutschland", "DE", "Germany"),
    "262:02": ("Vodafone",           "DE", "Germany"),
    "262:03": ("O2 / Telefónica",    "DE", "Germany"),
    "262:07": ("O2",                 "DE", "Germany"),
    # France (208)
    "208:01": ("Orange",      "FR", "France"),
    "208:10": ("SFR",         "FR", "France"),
    "208:20": ("Bouygues",    "FR", "France"),
    "208:15": ("Free Mobile", "FR", "France"),
    # Italy (222)
    "222:01": ("TIM",         "IT", "Italy"),
    "222:10": ("Vodafone",    "IT", "Italy"),
    "222:88": ("Wind Tre",    "IT", "Italy"),
    "222:99": ("3 Italia",    "IT", "Italy"),
    # Spain (214)
    "214:01": ("Vodafone",    "ES", "Spain"),
    "214:03": ("Orange",      "ES", "Spain"),
    "214:07": ("Movistar",    "ES", "Spain"),
    # Russia (250)
    "250:01": ("MTS",         "RU", "Russia"),
    "250:02": ("Megafon",     "RU", "Russia"),
    "250:03": ("Rostelecom",  "RU", "Russia"),
    "250:11": ("Yota",        "RU", "Russia"),
    "250:20": ("Tele2 Russia","RU", "Russia"),
    "250:99": ("Beeline",     "RU", "Russia"),
    # Netherlands (204)
    "204:04": ("Vodafone",    "NL", "Netherlands"),
    "204:08": ("KPN",         "NL", "Netherlands"),
    "204:16": ("T-Mobile NL", "NL", "Netherlands"),
    # Poland (260)
    "260:01": ("Plus",        "PL", "Poland"),
    "260:02": ("T-Mobile PL", "PL", "Poland"),
    "260:03": ("Orange PL",   "PL", "Poland"),
    "260:06": ("Play",        "PL", "Poland"),
    # India (404, 405)
    "404:10": ("Airtel",      "IN", "India"),
    "404:45": ("Jio",         "IN", "India"),
    "405:840":("Jio",         "IN", "India"),
    # Japan (440, 441)
    "440:10": ("NTT Docomo",  "JP", "Japan"),
    "440:20": ("Softbank",    "JP", "Japan"),
    "440:51": ("KDDI au",     "JP", "Japan"),
    # Brazil (724)
    "724:02": ("TIM",         "BR", "Brazil"),
    "724:05": ("Claro",       "BR", "Brazil"),
    "724:06": ("Vivo",        "BR", "Brazil"),
    "724:10": ("Oi",          "BR", "Brazil"),
}

# MCC → country (fallback when MNC is unknown)
_MCC_COUNTRY = {
    "202": ("GR", "Greece"),       "204": ("NL", "Netherlands"),
    "206": ("BE", "Belgium"),      "208": ("FR", "France"),
    "212": ("MC", "Monaco"),       "213": ("AD", "Andorra"),
    "214": ("ES", "Spain"),        "216": ("HU", "Hungary"),
    "218": ("BA", "Bosnia"),       "219": ("HR", "Croatia"),
    "220": ("RS", "Serbia"),       "222": ("IT", "Italy"),
    "226": ("RO", "Romania"),      "228": ("CH", "Switzerland"),
    "230": ("CZ", "Czech"),        "231": ("SK", "Slovakia"),
    "232": ("AT", "Austria"),      "234": ("GB", "UK"),
    "235": ("GB", "UK"),           "238": ("DK", "Denmark"),
    "240": ("SE", "Sweden"),       "242": ("NO", "Norway"),
    "244": ("FI", "Finland"),      "246": ("LT", "Lithuania"),
    "247": ("LV", "Latvia"),       "248": ("EE", "Estonia"),
    "250": ("RU", "Russia"),       "255": ("UA", "Ukraine"),
    "257": ("BY", "Belarus"),      "259": ("MD", "Moldova"),
    "260": ("PL", "Poland"),       "262": ("DE", "Germany"),
    "266": ("GI", "Gibraltar"),    "268": ("PT", "Portugal"),
    "270": ("LU", "Luxembourg"),   "272": ("IE", "Ireland"),
    "274": ("IS", "Iceland"),      "276": ("AL", "Albania"),
    "278": ("MT", "Malta"),        "280": ("CY", "Cyprus"),
    "282": ("GE", "Georgia"),      "283": ("AM", "Armenia"),
    "284": ("BG", "Bulgaria"),     "286": ("TR", "Turkey"),
    "288": ("FO", "Faroe"),        "290": ("GL", "Greenland"),
    "292": ("SM", "San Marino"),   "293": ("SI", "Slovenia"),
    "294": ("MK", "Macedonia"),    "295": ("LI", "Liechtenstein"),
    "297": ("ME", "Montenegro"),   "302": ("CA", "Canada"),
    "308": ("PM", "St. Pierre"),   "310": ("US", "United States"),
    "311": ("US", "United States"),"312": ("US", "United States"),
    "313": ("US", "United States"),"314": ("US", "United States"),
    "315": ("US", "United States"),"316": ("US", "United States"),
    "334": ("MX", "Mexico"),       "338": ("JM", "Jamaica"),
    "342": ("BB", "Barbados"),     "346": ("KY", "Cayman"),
    "350": ("BM", "Bermuda"),      "352": ("GD", "Grenada"),
    "362": ("CW", "Curacao"),      "364": ("BS", "Bahamas"),
    "368": ("CU", "Cuba"),         "370": ("DO", "Dominican"),
    "372": ("HT", "Haiti"),        "374": ("TT", "Trinidad"),
    "376": ("TC", "Turks"),        "400": ("AZ", "Azerbaijan"),
    "401": ("KZ", "Kazakhstan"),   "402": ("BT", "Bhutan"),
    "404": ("IN", "India"),        "405": ("IN", "India"),
    "410": ("PK", "Pakistan"),     "412": ("AF", "Afghanistan"),
    "413": ("LK", "Sri Lanka"),    "414": ("MM", "Myanmar"),
    "415": ("LB", "Lebanon"),      "416": ("JO", "Jordan"),
    "417": ("SY", "Syria"),        "418": ("IQ", "Iraq"),
    "419": ("KW", "Kuwait"),       "420": ("SA", "Saudi Arabia"),
    "421": ("YE", "Yemen"),        "422": ("OM", "Oman"),
    "424": ("AE", "UAE"),          "425": ("IL", "Israel"),
    "426": ("BH", "Bahrain"),      "427": ("QA", "Qatar"),
    "428": ("MN", "Mongolia"),     "429": ("NP", "Nepal"),
    "430": ("AE", "UAE"),          "432": ("IR", "Iran"),
    "434": ("UZ", "Uzbekistan"),   "436": ("TJ", "Tajikistan"),
    "437": ("KG", "Kyrgyzstan"),   "438": ("TM", "Turkmenistan"),
    "440": ("JP", "Japan"),        "441": ("JP", "Japan"),
    "450": ("KR", "South Korea"),  "452": ("VN", "Vietnam"),
    "454": ("HK", "Hong Kong"),    "455": ("MO", "Macau"),
    "456": ("KH", "Cambodia"),     "457": ("LA", "Laos"),
    "460": ("CN", "China"),        "466": ("TW", "Taiwan"),
    "467": ("KP", "North Korea"),  "470": ("BD", "Bangladesh"),
    "472": ("MV", "Maldives"),     "502": ("MY", "Malaysia"),
    "505": ("AU", "Australia"),    "510": ("ID", "Indonesia"),
    "515": ("PH", "Philippines"),  "520": ("TH", "Thailand"),
    "525": ("SG", "Singapore"),    "528": ("BN", "Brunei"),
    "530": ("NZ", "New Zealand"),  "602": ("EG", "Egypt"),
    "604": ("MA", "Morocco"),      "605": ("TN", "Tunisia"),
    "606": ("LY", "Libya"),        "607": ("GM", "Gambia"),
    "608": ("SN", "Senegal"),      "610": ("ML", "Mali"),
    "620": ("GH", "Ghana"),        "621": ("NG", "Nigeria"),
    "624": ("CM", "Cameroon"),     "625": ("CV", "Cape Verde"),
    "630": ("CD", "Congo"),        "634": ("SD", "Sudan"),
    "636": ("ET", "Ethiopia"),     "639": ("KE", "Kenya"),
    "640": ("TZ", "Tanzania"),     "641": ("UG", "Uganda"),
    "646": ("MG", "Madagascar"),   "647": ("RE", "Reunion"),
    "652": ("BW", "Botswana"),     "655": ("ZA", "South Africa"),
    "702": ("BZ", "Belize"),       "706": ("SV", "El Salvador"),
    "708": ("HN", "Honduras"),     "710": ("NI", "Nicaragua"),
    "712": ("CR", "Costa Rica"),   "714": ("PA", "Panama"),
    "716": ("PE", "Peru"),         "722": ("AR", "Argentina"),
    "724": ("BR", "Brazil"),       "730": ("CL", "Chile"),
    "732": ("CO", "Colombia"),     "734": ("VE", "Venezuela"),
    "736": ("BO", "Bolivia"),      "738": ("GY", "Guyana"),
    "740": ("EC", "Ecuador"),      "744": ("PY", "Paraguay"),
    "746": ("SR", "Suriname"),     "748": ("UY", "Uruguay"),
}

# Cache for remote API results — avoid hitting mcc-mnc.net repeatedly
try:
    _mcc_mnc_cache = TTLCache(maxsize=4096, ttl=7 * 24 * 3600)
except NameError:
    _mcc_mnc_cache = {}

def resolve_op(mcc, mnc):
    """
    Returns operator name for MCC+MNC.
    Priority: offline DB > cache > remote API > None.
    """
    if mcc is None or mnc is None:
        return None
    # Normalize to strings (and pad MNC to match common formats)
    mcc_s = str(mcc).strip()
    mnc_s = str(mnc).strip()

    # Try offline DB first — with MNC as-is and zero-padded (3-digit / 2-digit variants)
    for mnc_variant in (mnc_s, mnc_s.zfill(2), mnc_s.zfill(3), mnc_s.lstrip("0") or "0"):
        k = f"{mcc_s}:{mnc_variant}"
        if k in _MCC_MNC_DB:
            return _MCC_MNC_DB[k][0]

    # Check cache
    cache_key = f"{mcc_s}:{mnc_s}"
    if cache_key in _mcc_mnc_cache:
        return _mcc_mnc_cache[cache_key]

    # Remote lookup — best-effort, cache result (even None) to avoid re-hits
    try:
        r = requests.get(f"https://mcc-mnc.net/api/v1/mccmnc/{mcc_s}/{mnc_s}", timeout=3)
        if r.status_code == 200:
            d = r.json()
            op = d.get("operator") or d.get("network")
            _mcc_mnc_cache[cache_key] = op
            return op
    except: pass
    _mcc_mnc_cache[cache_key] = None
    return None

def resolve_country(mcc, mnc=None):
    """Returns (iso2, country_name) tuple based on MCC (+ optional MNC for precision)."""
    if mcc is None:
        return (None, None)
    mcc_s = str(mcc).strip()
    # Try MCC+MNC combo first
    if mnc is not None:
        mnc_s = str(mnc).strip()
        for mnc_variant in (mnc_s, mnc_s.zfill(2), mnc_s.zfill(3)):
            k = f"{mcc_s}:{mnc_variant}"
            if k in _MCC_MNC_DB:
                _op, iso, name = _MCC_MNC_DB[k]
                return (iso, name)
    # Fall back to MCC-only lookup
    if mcc_s in _MCC_COUNTRY:
        return _MCC_COUNTRY[mcc_s]
    return (None, None)

# ══════════════════════════════════════════════
#  FETCHERS — WiFi / BT / Cell
# ══════════════════════════════════════════════
def fetch_wigle_wifi(lat, lon):
    if not WIGLE_USER or not WIGLE_TOKEN: return []
    out = []
    try:
        r = requests.get(
            "https://api.wigle.net/api/v2/network/search",
            params={"latrange1": lat-0.01, "latrange2": lat+0.01,
                    "longrange1": lon-0.01, "longrange2": lon+0.01,
                    "resultsPerPage": 100},
            auth=(WIGLE_USER, WIGLE_TOKEN), timeout=T)
        if r.status_code == 401:
            print("[WiGLE WiFi] 401 Unauthorized")
        elif r.status_code == 200:
            for net in r.json().get("results", []):
                enc = norm_enc(net.get("encryption")); bssid = net.get("netid", "")
                name = net.get("ssid") or bssid
                d = {"lat": net.get("trilat"), "lon": net.get("trilong"),
                     "ssid": name, "bssid": bssid,
                     "vendor": net.get("vendor"), "signal": net.get("level"),
                     "encryption": enc, "leaked": enc in ("OPEN", "WEP"),
                     "timestamp": net.get("lastupdt"),
                     "type": classify(name, "router"), "source": "wigle"}


                out.append(d)
    except Exception as e: print(f"[WiGLE WiFi] {e}")
    return out

def fetch_wigle_bt(lat, lon):
    if not WIGLE_USER or not WIGLE_TOKEN: return []
    out = []
    try:
        r = requests.get(
            "https://api.wigle.net/api/v2/bluetooth/search",
            params={"latrange1": lat-0.01, "latrange2": lat+0.01,
                    "longrange1": lon-0.01, "longrange2": lon+0.01},
            auth=(WIGLE_USER, WIGLE_TOKEN), timeout=T)
        if r.status_code == 200:
            for dev in r.json().get("results", []):
                name = dev.get("name") or dev.get("netid", "")
                bt = dev.get("type", ""); ble = "LE" in bt.upper() if bt else False
                out.append({"lat": dev.get("trilat"), "lon": dev.get("trilong"),
                    "ssid": name, "bssid": dev.get("netid"), "vendor": bt,
                    "signal": dev.get("level"), "timestamp": dev.get("lastupdt"),
                    "type": classify(name, "ble" if ble else "bluetooth"),
                    "ble": ble, "source": "wigle_bt"})
    except Exception as e: print(f"[WiGLE BT] {e}")
    return out

def fetch_wigle_cell(lat, lon):
    """
    Fetch cell towers from WiGLE's cell search endpoint.
    Runs in parallel with fetch_opencellid — dedup handles overlap.
    Free tier: ~100 queries/day, so only 1 request per scan.
    """
    if not WIGLE_USER or not WIGLE_TOKEN:
        print("[WiGLE Cell] SKIPPED — WIGLE credentials not set")
        return []
    out = []
    try:
        # WiGLE cell endpoint uses a bounding box ~2km on each side.
        # Cell endpoint is heavier than wifi/bt — allow up to 15s before timeout.
        r = requests.get(
            "https://api.wigle.net/api/v2/cell/search",
            params={"latrange1": lat-0.02, "latrange2": lat+0.02,
                    "longrange1": lon-0.02, "longrange2": lon+0.02,
                    "resultsPerPage": 100},
            auth=(WIGLE_USER, WIGLE_TOKEN), timeout=15)
        print(f"[WiGLE Cell] HTTP {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])
            print(f"[WiGLE Cell]   → {len(results)} towers returned")
            for cell in results:
                clat = sf(cell.get("trilat"))
                clon = sf(cell.get("trilong"))
                if not clat or not clon:
                    continue
                # WiGLE cell record: netid often encodes MCC_MNC_LAC_CID (or similar)
                # Normalized fields: mcc, mnc, lac, cid
                mcc = cell.get("mcc") or (cell.get("name", "").split("_")[0] if cell.get("name") else None)
                mnc = cell.get("net") or cell.get("mnc")
                lac = cell.get("lac") or cell.get("area")
                cid = cell.get("cid")  or cell.get("cell_id") or cell.get("netid")

                # Sometimes WiGLE packs identifiers into netid like "286_1_1234_56789"
                netid = cell.get("netid", "")
                if netid and (not mcc or not mnc or not lac or not cid):
                    parts = netid.split("_")
                    if len(parts) >= 4:
                        mcc = mcc or parts[0]
                        mnc = mnc or parts[1]
                        lac = lac or parts[2]
                        cid = cid or parts[3]

                radio_raw = (cell.get("type") or cell.get("name", "")).upper()
                # WiGLE encodes radio in type field: "LTE", "GSM", "CDMA", "WCDMA"→umts, "NR"→5G
                if "LTE" in radio_raw:       radio = "lte"
                elif "NR" in radio_raw:      radio = "nr"
                elif "WCDMA" in radio_raw or "UMTS" in radio_raw: radio = "umts"
                elif "CDMA" in radio_raw:    radio = "cdma"
                elif "GSM" in radio_raw:     radio = "gsm"
                else:                        radio = "unknown"

                # Try MCC/MNC conversion to int where possible
                try: mcc_int = int(mcc) if mcc else None
                except: mcc_int = None
                try: mnc_int = int(mnc) if mnc else None
                except: mnc_int = None

                # Resolve operator + country from MCC+MNC (offline-first)
                op_name = resolve_op(mcc_int, mnc_int) if mcc_int else None
                country_iso, country_name = resolve_country(mcc_int, mnc_int) if mcc_int else (None, None)

                out.append({
                    "lat": clat, "lon": clon,
                    "cell_id": str(cid) if cid else "",
                    "signal":  cell.get("level"),
                    "mcc": mcc_int, "mnc": mnc_int,
                    "lac": lac,
                    "radio": radio,
                    "operator": op_name,
                    "country": country_name or country_iso,
                    "country_iso": country_iso,
                    "timestamp": cell.get("lastupdt"),
                    "type": "cell_tower", "source": "wigle_cell"
                })
        elif r.status_code == 401:
            print("[WiGLE Cell] 401 Unauthorized — credentials invalid")
        elif r.status_code == 429:
            print("[WiGLE Cell] 429 — daily rate limit reached (~100 cell queries/day on free tier)")
        else:
            print(f"[WiGLE Cell] Unexpected status; body: {r.text[:200]}")
    except Exception as e:
        print(f"[WiGLE Cell] Exception: {e}")
    return out

def fetch_opencellid(lat, lon):
    if not OPENCELLID_KEY:
        print("[OpenCellID] SKIPPED — OPENCELLID_API_KEY not set in .env")
        return []
    out = []
    # OpenCellID free tier limit: BBOX must be ≤ 4,000,000 sq meters (2km × 2km total area).
    # We target ~0.9 km half-side per axis to keep area ≈ 1.8km × 1.8km ≈ 3.24M m² with safety margin.
    import math
    half_km = 0.9
    half_lat = half_km / 111.32
    half_lon = half_km / (111.32 * max(math.cos(math.radians(lat)), 0.1))
    bbox = f"{lat-half_lat:.5f},{lon-half_lon:.5f},{lat+half_lat:.5f},{lon+half_lon:.5f}"
    try:
        r = requests.get("https://opencellid.org/cell/getInArea",
            params={"key": OPENCELLID_KEY, "BBOX": bbox, "format": "json", "limit": 100},
            timeout=T)
        print(f"[OpenCellID] HTTP {r.status_code} for bbox={bbox}")
        if r.status_code == 200:
            try:
                data = r.json()
            except Exception as je:
                print(f"[OpenCellID] JSON parse failed: {je}; body: {r.text[:200]}")
                return []
            cells = data.get("cells", [])
            print(f"[OpenCellID]   → {len(cells)} cells returned, error field: {data.get('error') or 'none'}")
            # One-shot schema log so we can see any future field renames
            if cells and not _opencellid_schema_logged["done"]:
                print(f"[OpenCellID]   raw keys: {list(cells[0].keys())}")
                _opencellid_schema_logged["done"] = True
            for c in cells:
                # Field names vary across OpenCellID / UnwiredLabs / mirrors — try every known variant
                mcc = c.get("mcc")
                mnc = c.get("mnc") if c.get("mnc") is not None else c.get("net")
                lac = c.get("lac") if c.get("lac") is not None else c.get("area")
                cid = c.get("cellid")
                if cid is None: cid = c.get("cell")
                if cid is None: cid = c.get("cid")

                sig = c.get("averageSignalStrength")
                if sig is None: sig = c.get("averageSignal")
                if sig is None: sig = c.get("signal")

                clat = sf(c.get("lat")); clon = sf(c.get("lon"))
                if not clat or not clon: continue

                op_name = resolve_op(mcc, mnc) if mcc else None
                country_iso, country_name = resolve_country(mcc, mnc) if mcc else (None, None)

                out.append({
                    "lat": clat, "lon": clon,
                    "cell_id": str(cid) if cid is not None else "",
                    "signal":  sig,
                    "mcc": mcc, "mnc": mnc, "lac": lac,
                    "radio": (c.get("radio") or "unknown").lower(),
                    "operator": op_name,
                    "country": country_name or country_iso,
                    "country_iso": country_iso,
                    "timestamp": c.get("updated") or c.get("lastupdt"),
                    "type": "cell_tower", "source": "opencellid"
                })
        else:
            # Surface the actual error body so we know WHY
            print(f"[OpenCellID] ERROR body: {r.text[:300]}")
    except Exception as e:
        print(f"[OpenCellID] Exception: {e}")
    return out

# One-shot schema logger — prints OpenCellID raw field names on first hit
_opencellid_schema_logged = {"done": False}

# ══════════════════════════════════════════════
#  FETCHERS — IoT/Camera (lat/lon tabanlı)
# ══════════════════════════════════════════════
def fetch_shodan(lat, lon):
    if not SHODAN_KEY or _hblocked("Shodan"): return []
    country = get_country_iso(lat, lon); cf = f" country:{country}" if country else ""
    out = []
    for q in [f"port:554{cf}", f"product:Hikvision{cf}", f"product:Dahua{cf}", f"port:8080 has_screenshot:true{cf}"]:
        if _hblocked("Shodan"): break
        try:
            r = requests.get("https://api.shodan.io/shodan/host/search",
                params={"key": SHODAN_KEY, "query": q, "limit": 10}, timeout=T)
            if r.status_code == 200:
                for h in r.json().get("matches", []):
                    b = h.get("data", ""); p = h.get("product", ""); loc = h.get("location", {})
                    out.append({"lat": sf(loc.get("latitude")), "lon": sf(loc.get("longitude")),
                        "ip": h.get("ip_str"), "port": h.get("port"),
                        "banner": b[:100], "org": h.get("org"),
                        "country": loc.get("country_name", ""), "city": loc.get("city", ""),
                        "vulns": list((h.get("vulns") or {}).keys()),
                        "type": classify(b+" "+p, "iot_device"), "source": "shodan"})
            elif r.status_code == 429:
                print("[Shodan] Rate limited"); break
        except Exception as e: print(f"[Shodan] {e}")
    return dedup(out)

def fetch_censys(lat, lon):
    if not CENSYS_ID or not CENSYS_SECRET: return []
    out = []
    try:
        country = get_country_iso(lat, lon); cf = f" and location.country_code={country}" if country else ""
        q = f"(services.port=554 or services.port=8080 or services.port=37777){cf}"
        r = requests.post("https://search.censys.io/api/v2/hosts/search",
            json={"q": q, "per_page": 25}, auth=(CENSYS_ID, CENSYS_SECRET), timeout=T)
        if r.status_code == 200:
            for hit in r.json().get("result", {}).get("hits", []):
                loc = hit.get("location", {}); coords = loc.get("coordinates", {})
                for svc in hit.get("services", []):
                    b = svc.get("banner", "")
                    out.append({"lat": sf(coords.get("latitude")), "lon": sf(coords.get("longitude")),
                        "ip": hit.get("ip"), "port": svc.get("port"),
                        "banner": b[:100], "country": loc.get("country", ""), "city": loc.get("city", ""),
                        "type": classify(b, "iot_device"), "source": "censys"})
    except Exception as e: print(f"[Censys] {e}")
    return dedup(out)

def fetch_zoomeye(lat, lon):
    if not ZOOMEYE_KEY: return []
    out = []; country = get_country_iso(lat, lon); cf = f' +country:"{country}"' if country else ""
    for q in [f'app:"Hikvision"{cf}', f'app:"Dahua"{cf}', f'port:554{cf}', f'app:"webcam"{cf}']:
        try:
            r = requests.get("https://api.zoomeye.org/host/search",
                params={"query": q, "page": 1}, headers={"API-KEY": ZOOMEYE_KEY}, timeout=T)
            if r.status_code == 200:
                for m in r.json().get("matches", []):
                    geo = m.get("geoinfo", {}); pi = m.get("portinfo", {})
                    out.append({"lat": sf(geo.get("latitude")), "lon": sf(geo.get("longitude")),
                        "ip": m.get("ip"), "port": pi.get("port"),
                        "banner": (pi.get("banner") or "")[:100],
                        "country": (geo.get("country") or {}).get("names", {}).get("en", ""),
                        "city": (geo.get("city") or {}).get("names", {}).get("en", ""),
                        "type": classify((pi.get("app") or "")+" "+(pi.get("banner") or ""), "camera"),
                        "source": "zoomeye"})
        except Exception as e: print(f"[ZoomEye] {e}")
    return dedup(out)

def fetch_hunterhow(lat, lon):
    if not HUNTERHOW_KEY: return []
    out = []; country = get_country_iso(lat, lon); cf = f' AND country="{country}"' if country else ""
    start_time = (datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d")
    end_time   = datetime.now().strftime("%Y-%m-%d")
    for q in [f'port="554"{cf}', f'product.name="Hikvision"{cf}', f'port="37777"{cf}']:
        try:
            # STB-12: resmi endpoint api.hunter.how/search, query base64url
            qb64 = base64.urlsafe_b64encode(q.encode()).decode()
            r = requests.get("https://api.hunter.how/search",
                params={"api-key": HUNTERHOW_KEY, "query": qb64, "page": 1, "page_size": 20,
                        "start_time": start_time, "end_time": end_time}, timeout=T)
            if r.status_code == 200:
                data = r.json()
                if data.get("code") != 200:
                    print(f"[Hunter.how] code={data.get('code')} {str(data.get('message',''))[:80]}")
                    continue
                payload = data.get("data") or {}
                for item in (payload.get("list") or payload.get("arr") or []):
                    b = item.get("banner", "") or item.get("web_title", "") or ""
                    p = item.get("product") or item.get("app") or ""
                    if isinstance(p, dict): p = p.get("name", "")
                    if isinstance(p, list): p = " ".join(str(x.get("name", x)) if isinstance(x, dict) else str(x) for x in p)
                    geo = item.get("geo", {}) or {}
                    out.append({**_loc(sf(geo.get("lat")), sf(geo.get("lon")), lat, lon),
                        "ip": item.get("ip"), "port": item.get("port"),
                        "banner": str(b)[:100], "org": item.get("company") or item.get("isp"),
                        "country": item.get("country") or geo.get("country", ""),
                        "type": classify(str(p)+" "+str(b), "camera"), "source": "hunterhow"})
        except Exception as e: print(f"[Hunter.how] {e}")
    return dedup(out)

def fetch_netlas(lat, lon):
    if not NETLAS_KEY: return []
    out = []; rd = 0.15
    gq = f"geo.location:[{lon-rd},{lat-rd} TO {lon+rd},{lat+rd}]"
    for q in [f"port:554 AND {gq}", f"(app.name:Hikvision OR app.name:Dahua) AND {gq}"]:
        try:
            r = requests.get("https://app.netlas.io/api/responses/",
                params={"q": q, "fields": "ip,port,geo,app,banner", "start": 0, "size": 20},
                headers={"X-API-Key": NETLAS_KEY}, timeout=T)
            if r.status_code == 200:
                for hit in r.json().get("items", []):
                    d = hit.get("data", hit); geo = d.get("geo", {}) or {}
                    loc = geo.get("location", {}) or {}; b = d.get("banner", "") or ""
                    out.append({**_loc(sf(loc.get("lat")), sf(loc.get("lon")), lat, lon),
                        "ip": d.get("ip"), "port": d.get("port"), "banner": b[:100],
                        "org": geo.get("org"), "country": geo.get("country", ""),
                        "type": classify(str((d.get("app") or {}).get("name",""))+" "+b, "iot_device"),
                        "source": "netlas"})
        except Exception as e: print(f"[Netlas] {e}")
    return dedup(out)

def fetch_leakix(lat, lon):
    if not LEAKIX_KEY: return []
    out = []; country = get_country_iso(lat, lon); cf = f'+country:"{country}" ' if country else ""
    for q in [f'{cf}+port:"554"', f'{cf}+tag:"default-credentials"']:
        try:
            r = requests.get("https://leakix.net/search",
                params={"scope": "service", "q": q, "page": 0},
                headers={"api-key": LEAKIX_KEY, "Accept": "application/json"}, timeout=T)
            if r.status_code == 200:
                for item in (r.json() or []):
                    net = item.get("network", {}) or {}; geo = item.get("geoip", {}) or {}
                    loc = geo.get("location", {}) or {}; tags = item.get("tags", []) or []
                    s = item.get("summary", "") or ""
                    out.append({**_loc(sf(loc.get("lat")), sf(loc.get("lon")), lat, lon),
                        "ip": net.get("ip"), "port": item.get("port"),
                        "banner": s[:100], "org": geo.get("organization_name"),
                        "country": geo.get("country_name", ""), "tags": tags,
                        "leaked": any(t in tags for t in ["default-credentials","exposure","open-directory"]),
                        "type": classify(s, "iot_device"), "source": "leakix"})
        except Exception as e: print(f"[LeakIX] {e}")
    return dedup(out)

def fetch_criminalip(lat, lon):
    if not CRIMINALIP_KEY: return []
    out = []; country = get_country_iso(lat, lon); cf = f" country:{country}" if country else ""
    for q in [f"port:554{cf}", f"hikvision{cf}"]:
        try:
            r = requests.get("https://api.criminalip.io/v1/asset/search",
                params={"query": q, "offset": 0},
                headers={"x-api-key": CRIMINALIP_KEY}, timeout=T)
            if r.status_code == 200:
                data = r.json()
                if (data.get("status") or 200) != 200: continue
                for item in data.get("data", {}).get("result", []):
                    b = item.get("banner", "") or ""; geo = item.get("geolocation", {}) or {}
                    inb = (item.get("score", {}) or {}).get("inbound", 0) or 0
                    out.append({**_loc(sf(geo.get("latitude")), sf(geo.get("longitude")), lat, lon),
                        "ip": item.get("ip_address"), "port": item.get("open_port_no"),
                        "banner": b[:100], "org": geo.get("org_name"),
                        "country": geo.get("country", ""), "cip_score": inb,
                        "type": classify(b, "iot_device"), "source": "criminalip"})
        except Exception as e: print(f"[CriminalIP] {e}")
    return dedup(out)

# ══════════════════════════════════════════════
#  ADS-B HELPERS
# ══════════════════════════════════════════════
SQUAWK_TABLE = {
    "7500": "HIJACKING",
    "7600": "RADIO_FAILURE",
    "7700": "GENERAL_EMERGENCY",
    "1200": "VFR_FLIGHT",
    "2000": "IFR_ENTERING_CONTROLLED",
}
EMERGENCY_SQUAWKS = {"7500", "7600", "7700"}

def decode_squawk(sq):
    if not sq: return None
    return SQUAWK_TABLE.get(str(sq))

def score_aircraft(ac):
    s = 0
    sq  = str(ac.get("squawk") or "")
    t   = ac.get("type", "")
    alt = ac.get("altitude")
    spd = ac.get("velocity")
    if sq in EMERGENCY_SQUAWKS:                  s += 70
    if t == "drone":                             s += 40
    if alt is not None and alt < 300:            s += 20
    if alt is not None and alt < 1000:           s += 10
    if spd is not None and spd < 30:             s += 10
    icao = (ac.get("icao") or "").upper()
    cs   = (ac.get("callsign") or "").strip()
    if not cs or cs.upper() == icao:             s += 10
    return min(s, 100)

def dedup_aircraft(lst):
    seen = {}
    priority = {"adsb_fi": 0, "opensky": 1}
    for ac in lst:
        icao = (ac.get("icao") or "").upper()
        if not icao:
            seen[id(ac)] = ac; continue
        if icao not in seen:
            seen[icao] = ac
        else:
            ep = priority.get(seen[icao].get("source", ""), 99)
            np = priority.get(ac.get("source", ""), 99)
            if np < ep: seen[icao] = ac
    return list(seen.values())

_adsb_cache = {}
_adsb_lock = threading.Lock()
_ADSB_TTL = 5  # adsb.fi public limiti 1 istek/sn — kısa cache ile aynı bölge tekrarları birleşir

def _adsb_fi_raw(lat, lon, radius_km):
    """adsb.fi v3 (deniz mili, max 250 NM). 5 sn cache + single-flight (STB-09)."""
    dist_nm = max(1, min(250, int(round(radius_km / 1.852))))
    key = (round(lat, 2), round(lon, 2), dist_nm)
    with _adsb_lock:
        hit = _adsb_cache.get(key)
        if hit and time.time() - hit[0] < _ADSB_TTL:
            return hit[1]
        urls = [
            f"https://opendata.adsb.fi/api/v3/lat/{lat:.4f}/lon/{lon:.4f}/dist/{dist_nm}",
            f"https://opendata.adsb.fi/api/v2/lat/{lat:.4f}/lon/{lon:.4f}/dist/{dist_nm}",
        ]
        acs = None
        for u in urls:
            try:
                r = requests.get(u, timeout=8, headers={"User-Agent": "SignalOps/2.1"})
                if r.status_code == 200:
                    j = r.json()
                    acs = j.get("ac") or j.get("aircraft") or []
                    break
                print(f"[ADS-B] {u.split('/api/')[1][:3]} HTTP {r.status_code}")
                if r.status_code == 429:
                    break
            except Exception as e:
                print(f"[ADS-B] {e}")
        if acs is None:
            return []
        _adsb_cache[key] = (time.time(), acs)
        if len(_adsb_cache) > 200:
            for k in [k for k, v in _adsb_cache.items() if time.time() - v[0] > _ADSB_TTL]:
                _adsb_cache.pop(k, None)
        return acs

def fetch_adsb(lat, lon, radius_km=100):
    out = []
    try:
        for ac in _adsb_fi_raw(lat, lon, radius_km):
                alat = sf(ac.get("lat")); alon = sf(ac.get("lon"))
                if not alat or not alon: continue
                alt     = sf(ac.get("alt_baro") or ac.get("alt_geom"))
                spd     = sf(ac.get("gs"))
                heading = sf(ac.get("track"))
                squawk  = str(ac.get("squawk") or "").strip() or None
                icao    = (ac.get("hex") or "").upper().strip()
                cs      = (ac.get("flight") or "").strip()
                cat     = (ac.get("category") or "").upper() or None
                if cat:
                    # STB-10: emitter category varsa ona güven (B6 = UAV)
                    drone = cat == "B6"
                else:
                    drone = (alt is not None and alt < 400) or \
                            (spd is not None and spd < 60 and alt is not None and alt < 500)
                dev = {
                    "lat": alat, "lon": alon,
                    "icao": icao, "callsign": cs or None,
                    "altitude": int(alt) if alt is not None else None,
                    "velocity": int(spd) if spd is not None else None,
                    "heading":  int(heading) if heading is not None else None,
                    "squawk": squawk,
                    "squawk_meaning": decode_squawk(squawk),
                    "emergency": squawk in EMERGENCY_SQUAWKS if squawk else False,
                    "country": ac.get("c") or None,
                    "type": "drone" if drone else "aircraft",
                    "source": "adsb_fi",
                    "ssid": cs or icao, "bssid": icao,
                    "category": cat,
                    "nac_p": ac.get("nac_p"),
                    "nic": ac.get("nic"),
                    "gps_ok_before": ac.get("gpsOkBefore"),
                }
                dev["risk"] = score_aircraft(dev)
                out.append(dev)
    except Exception as e: print(f"[ADS-B] {e}")
    return out

def fetch_opensky(lat, lon, radius_km=100):
    out = []
    try:
        deg = radius_km / 111.0
        r = requests.get("https://opensky-network.org/api/states/all",
            params={"lamin": lat-deg, "lamax": lat+deg,
                    "lomin": lon-deg, "lomax": lon+deg}, timeout=10)
        if r.status_code == 200:
            for s in (r.json().get("states") or []):
                if len(s) < 7: continue
                alat = sf(s[6]); alon = sf(s[5])
                if not alat or not alon: continue
                if s[8]: continue  # skip on_ground
                icao   = (s[0] or "").upper().strip()
                cs     = (s[1] or "").strip() or None
                alt_m  = sf(s[7])
                alt_ft = int(alt_m * 3.28084) if alt_m is not None else None
                spd_ms = sf(s[9])
                spd_kt = int(spd_ms * 1.94384) if spd_ms is not None else None
                hdg    = sf(s[10])
                squawk = str(s[14] or "").strip() or None
                drone  = (alt_ft is not None and alt_ft < 400) or \
                         (spd_kt is not None and spd_kt < 60 and alt_ft is not None and alt_ft < 500)
                dev = {
                    "lat": alat, "lon": alon,
                    "icao": icao, "callsign": cs,
                    "altitude": alt_ft,
                    "velocity": spd_kt,
                    "heading": int(hdg) if hdg is not None else None,
                    "squawk": squawk,
                    "squawk_meaning": decode_squawk(squawk),
                    "emergency": squawk in EMERGENCY_SQUAWKS if squawk else False,
                    "country": s[2] or None,
                    "type": "drone" if drone else "aircraft",
                    "source": "opensky",
                    "ssid": cs or icao, "bssid": icao,
                }
                dev["risk"] = score_aircraft(dev)
                out.append(dev)
    except Exception as e: print(f"[OpenSky] {e}")
    return out

# ══════════════════════════════════════════════
#  CAMERA FETCHERS (lat/lon tabanlı)
# ══════════════════════════════════════════════
def fetch_cameras_shodan(lat, lon):
    if not SHODAN_KEY or _hblocked("Shodan"): return []
    country = get_country_iso(lat, lon); cf = f" country:{country}" if country else ""
    out = []
    queries = [
        f"port:554{cf}", f"port:37777{cf}", f"port:34567{cf}",
        f"product:Hikvision{cf}", f"product:Dahua{cf}", f"product:AXIS{cf}",
        f'http.title:"IP Camera"{cf}', f'http.title:"Network Camera"{cf}',
        f'http.title:"Live View"{cf}', f'http.title:"DVR Login"{cf}',
        f"http.favicon.hash:-1438220477{cf}", f"http.favicon.hash:-1616143106{cf}",
        f"http.favicon.hash:999357577{cf}", f"screenshot.label:webcam{cf}",
    ]
    for q in queries:
        if _hblocked("Shodan"): break      # kota/yetki hatası → kalan sorgular atlanır
        try:
            r = requests.get("https://api.shodan.io/shodan/host/search",
                params={"key": SHODAN_KEY, "query": q, "limit": 15}, timeout=T)
            if r.status_code == 200:
                for h in r.json().get("matches", []):
                    loc = h.get("location", {}); b = h.get("data", "")
                    out.append({**_loc(sf(loc.get("latitude")), sf(loc.get("longitude")), lat, lon),
                        "ip": h.get("ip_str"), "port": h.get("port"),
                        "banner": b[:120], "org": h.get("org"), "isp": h.get("isp"),
                        "country": loc.get("country_name", ""), "city": loc.get("city", ""),
                        "vulns": list((h.get("vulns") or {}).keys()),
                        "type": "camera", "source": "shodan"})
            elif r.status_code == 429:
                print("[CCTV Shodan] Rate limited"); break
        except Exception as e: print(f"[CCTV Shodan] {e}")
    return dedup(out)

def fetch_cameras_zoomeye(lat, lon):
    if not ZOOMEYE_KEY: return []
    out = []; country = get_country_iso(lat, lon); cf = f' +country:"{country}"' if country else ""
    for q in [f'app:"Hikvision"{cf}', f'app:"Dahua"{cf}', f'port:554{cf}',
              f'app:"webcam"{cf}', f'app:"IP Camera"{cf}']:
        try:
            r = requests.get("https://api.zoomeye.org/host/search",
                params={"query": q, "page": 1}, headers={"API-KEY": ZOOMEYE_KEY}, timeout=T)
            if r.status_code == 200:
                for m in r.json().get("matches", []):
                    geo = m.get("geoinfo", {}); pi = m.get("portinfo", {})
                    out.append({**_loc(sf(geo.get("latitude")), sf(geo.get("longitude")), lat, lon),
                        "ip": m.get("ip"), "port": pi.get("port"),
                        "banner": (pi.get("banner") or "")[:120],
                        "org": (geo.get("organization") or {}).get("name"),
                        "country": (geo.get("country") or {}).get("names", {}).get("en", ""),
                        "type": "camera", "source": "zoomeye"})
        except Exception as e: print(f"[CCTV ZoomEye] {e}")
    return dedup(out)

def fetch_cameras_fofa(lat, lon):
    if not FOFA_EMAIL or not FOFA_KEY or _hblocked("FOFA"): return []
    out = []; country = get_country_iso(lat, lon); cf = f' && country="{country}"' if country else ""
    queries = [f'port="554"{cf}', f'app="Hikvision-Web-Server"{cf}',
               f'app="Dahua-Web"{cf}', f'port="37777"{cf}',
               f'title="IP Camera"{cf}', f'title="Network Camera"{cf}']
    for q in queries:
        if _hblocked("FOFA"): break
        try:
            qb64 = base64.b64encode(q.encode()).decode()
            r = requests.get("https://fofa.info/api/v1/search/all",
                params={"email": FOFA_EMAIL, "key": FOFA_KEY, "qbase64": qb64, "size": 20,
                        "fields": "ip,port,host,title,country,city,latitude,longitude,org"},
                timeout=T)
            if r.status_code == 200:
                data = r.json()
                if data.get("error"): continue
                for item in data.get("results", []):
                    if len(item) < 9: continue
                    ip = item[0]; port = item[1]; title = item[3]
                    country_r = item[4]; city_r = item[5]
                    rlat = sf(item[6]); rlon = sf(item[7]); org = item[8]
                    out.append({**_loc(rlat, rlon, lat, lon),
                        "ip": ip, "port": port, "banner": title[:120],
                        "org": org, "country": country_r, "city": city_r,
                        "type": "camera", "source": "fofa"})
        except Exception as e: print(f"[FOFA] {e}")
    return dedup(out)

def fetch_cameras_criminalip(lat, lon):
    if not CRIMINALIP_KEY: return []
    out = []; country = get_country_iso(lat, lon); cf = f" country:{country}" if country else ""
    for q in [f"port:554 webcam{cf}", f"hikvision port:554{cf}", f"dahua port:37777{cf}"]:
        try:
            r = requests.get("https://api.criminalip.io/v1/asset/search",
                params={"query": q, "offset": 0},
                headers={"x-api-key": CRIMINALIP_KEY}, timeout=T)
            if r.status_code == 200:
                data = r.json()
                if (data.get("status") or 200) != 200: continue
                for item in data.get("data", {}).get("result", []):
                    geo = item.get("geolocation", {}) or {}; b = item.get("banner", "") or ""
                    out.append({**_loc(sf(geo.get("latitude")), sf(geo.get("longitude")), lat, lon),
                        "ip": item.get("ip_address"), "port": item.get("open_port_no"),
                        "banner": b[:120], "org": geo.get("org_name"),
                        "country": geo.get("country", ""),
                        "cip_score": (item.get("score", {}) or {}).get("inbound", 0) or 0,
                        "type": "camera", "source": "criminalip"})
        except Exception as e: print(f"[CCTV CriminalIP] {e}")
    return dedup(out)

def fetch_cameras_binaryedge(lat, lon):
    if not BINARYEDGE_KEY: return []
    out = []; country = get_country_iso(lat, lon); cf = f" country:{country}" if country else ""
    radius_deg = 0.5
    for q in [f"type:camera{cf}", f"port:554{cf}", f"port:37777{cf}"]:
        try:
            r = requests.get("https://api.binaryedge.io/v2/query/search",
                params={"query": q, "page": 1, "pagesize": 20},
                headers={"X-Key": BINARYEDGE_KEY}, timeout=T)
            if r.status_code == 200:
                for event in r.json().get("events", []):
                    target = event.get("target", {}); origin = event.get("origin", {})
                    geo = origin.get("geoip", {}) or {}
                    rlat = sf(geo.get("latitude")); rlon = sf(geo.get("longitude"))
                    if rlat and rlon:
                        if abs(rlat - lat) > radius_deg or abs(rlon - lon) > radius_deg * 1.5:
                            continue
                    result = event.get("result", {}).get("data", {})
                    banner = str(result)[:120]
                    out.append({**_loc(rlat, rlon, lat, lon),
                        "ip": target.get("ip"), "port": target.get("port"),
                        "banner": banner, "org": geo.get("as_name"),
                        "country": geo.get("country_name", ""),
                        "type": "camera", "source": "binaryedge"})
        except Exception as e: print(f"[BinaryEdge] {e}")
    return dedup(out)

def fetch_cameras_windy(lat, lon):
    if not WINDY_KEY: return []
    out = []
    try:
        r = requests.get("https://api.windy.com/webcams/api/v3/webcams",
            params={"lang": "en", "limit": 50, "offset": 0,
                    "nearby": f"{lat:.4f},{lon:.4f},50",
                    # STB-12: v3 'fields' değil 'include' kullanır
                    "include": "location,player,images"},
            headers={"x-windy-api-key": WINDY_KEY}, timeout=T)
        if r.status_code == 200:
            for wc in r.json().get("webcams", []):
                loc = wc.get("location", {}) or {}
                rlat = sf(loc.get("latitude")); rlon = sf(loc.get("longitude"))
                if not rlat or not rlon: continue
                player = wc.get("player") or {}
                stream = None
                for k in ("live", "day", "month", "year", "lifetime"):
                    v = player.get(k) if isinstance(player, dict) else None
                    if isinstance(v, dict): v = v.get("embed") or v.get("url")
                    if isinstance(v, str) and v:
                        stream = v; break
                imgs = ((wc.get("images") or {}).get("current") or {})
                out.append({"lat": rlat, "lon": rlon,
                    "ssid": wc.get("title", "Webcam"), "ip": f"windy:{wc.get('webcamId')}",
                    "banner": f"Status: {wc.get('status','?')} | {loc.get('city','')} {loc.get('country','')}",
                    "country": loc.get("country", ""), "city": loc.get("city", ""),
                    "type": "camera", "source": "windy", "auth": True,
                    "thumb_url": imgs.get("preview") or imgs.get("thumbnail"),
                    "stream_url": stream})
    except Exception as e: print(f"[Windy Webcams] {e}")
    return out

def fetch_cameras_osm(lat, lon):
    out = []
    radius = 3000
    query = f"""
[out:json][timeout:20];
(
  node["man_made"="surveillance"](around:{radius},{lat},{lon});
  node["surveillance"](around:{radius},{lat},{lon});
  node["surveillance:type"="camera"](around:{radius},{lat},{lon});
);
out body;
"""
    try:
        r = requests.post("https://overpass-api.de/api/interpreter",
            data={"data": query},
            headers={"User-Agent": "SignalOPS/2.0 (security-research)"}, timeout=25)
        if r.status_code == 200:
            for node in r.json().get("elements", []):
                tags = node.get("tags", {})
                nlat = sf(node.get("lat")); nlon = sf(node.get("lon"))
                if not nlat or not nlon: continue
                cam_type  = tags.get("surveillance:type", tags.get("surveillance", "camera"))
                direction = tags.get("camera:direction", tags.get("direction", ""))
                operator  = tags.get("operator", tags.get("owner", ""))
                mount     = tags.get("camera:mount", "")
                name      = tags.get("name", "") or tags.get("ref", "") or f"OSM Camera {node.get('id','')}"
                banner    = f"Type:{cam_type} Mount:{mount} Dir:{direction}".strip(" :")
                out.append({"lat": nlat, "lon": nlon,
                    "ssid": name, "ip": f"osm:{node.get('id')}",
                    "banner": banner[:120], "org": operator,
                    "type": "camera", "source": "osm",
                    "osm_id": node.get("id"), "tags": tags})
    except Exception as e: print(f"[OSM Overpass] {e}")
    return out

def fetch_cameras_osm_by_country(country: str) -> list:
    """
    OSM Overpass — ülke kodu ile surveillance kamera sorgusu.
    country: ISO-2 kodu (TR, DE, US …)
    Overpass area filtresi kullanır — ücretsiz, key gerektirmez.

    Büyük ülkelerde (RU, PL, US) ana Overpass endpoint 504 verebilir.
    Ana endpoint fail ederse mirror'lara fallback yapar.
    """
    out = []
    if not country:
        return out

    # Shorter server-side timeout (30s) — lets Overpass return partial data faster
    # instead of hanging until 504. Output cap 200 to prevent huge payloads.
    query = f"""
[out:json][timeout:30];
area["ISO3166-1"="{country.upper()}"]["admin_level"="2"];
(
  node["man_made"="surveillance"](area);
  node["surveillance:type"="camera"](area);
  node["surveillance"="camera"](area);
  node["surveillance"="outdoor"](area);
);
out body 200;
"""
    # Try endpoints in order. Main API goes down often for big queries (RU, PL, US).
    endpoints = [
        "https://overpass-api.de/api/interpreter",
        "https://overpass.kumi.systems/api/interpreter",
        "https://overpass.openstreetmap.fr/api/interpreter",
    ]
    response = None
    for ep in endpoints:
        try:
            r = requests.post(
                ep,
                data={"data": query},
                headers={"User-Agent": "SignalOPS/2.0 (security-research)"},
                timeout=40
            )
            if r.status_code == 200:
                response = r
                break
            else:
                print(f"[OSM country] HTTP {r.status_code} from {ep.split('/')[2]}, trying next")
        except Exception as e:
            print(f"[OSM country] {ep.split('/')[2]} failed: {type(e).__name__}, trying next")
            continue

    if not response:
        print(f"[OSM country] all mirrors failed for country={country.upper()}")
        return []

    try:
        for node in response.json().get("elements", []):
            tags = node.get("tags", {})
            nlat = sf(node.get("lat")); nlon = sf(node.get("lon"))
            if not nlat or not nlon: continue
            cam_type  = tags.get("surveillance:type", tags.get("surveillance", "camera"))
            direction = tags.get("camera:direction", tags.get("direction", ""))
            operator  = tags.get("operator", tags.get("owner", ""))
            mount     = tags.get("camera:mount", "")
            name      = tags.get("name", "") or tags.get("ref", "") or f"OSM {node.get('id','')}"
            banner    = f"Type:{cam_type} Mount:{mount} Dir:{direction}".strip(" :")
            out.append({
                "lat": nlat, "lon": nlon,
                "ip": f"osm:{node.get('id')}",
                "ssid": name,
                "banner": banner[:120],
                "org": operator,
                "country": country,
                "type": "camera",
                "source": "osm",
                "osm_id": node.get("id"),
                "risk": 30,
            })
    except Exception as e:
        print(f"[OSM country] parse error: {e}")

    print(f"[OSM country] country={country} → {len(out)} cameras")
    return out


def fetch_cameras_insecam(lat, lon):
    """lat/lon tabanlı — mevcut ülkeyi tespit edip insecam'dan çeker."""
    out = []
    try:
        country = get_country_iso(lat, lon)
        if not country:
            return []
        results = fetch_cameras_insecam_by_country(country)
        # lat/lon bilgisi yoksa jitter ekle
        for item in results:
            if item.get("lat") is None or item.get("lon") is None:
                item.update(_loc(item.get("lat"), item.get("lon"), lat, lon))
        return results
    except Exception as e:
        print(f"[Insecam lat/lon] {e}")
    return out

# ══════════════════════════════════════════════
#  KAMU WEBCAM AĞLARI (anahtarsız, resmî açık veri)
# ══════════════════════════════════════════════
# Her kaynak bir bölgeyi kapsar; sadece arama noktası o bölgedeyse sorgulanır.
# İstasyon listeleri 1 saat cache'lenir, sonra noktaya en yakın kameralar seçilir.
import math as _math

def _haversine_km(a_lat, a_lon, b_lat, b_lon):
    r = 6371.0
    p1, p2 = _math.radians(a_lat), _math.radians(b_lat)
    dp = p2 - p1; dl = _math.radians(b_lon - a_lon)
    h = _math.sin(dp / 2) ** 2 + _math.cos(p1) * _math.cos(p2) * _math.sin(dl / 2) ** 2
    return 2 * r * _math.asin(min(1.0, _math.sqrt(h)))

def _pub_tfl():
    r = requests.get("https://api.tfl.gov.uk/Place/Type/JamCam", timeout=20,
                     headers={"User-Agent": "SignalOps/2.1"})
    out = []
    if r.status_code != 200:
        print(f"[TfL JamCam] HTTP {r.status_code}"); return out
    for p in r.json() or []:
        props = {a.get("key"): a.get("value") for a in (p.get("additionalProperties") or []) if isinstance(a, dict)}
        la, lo = sf(p.get("lat")), sf(p.get("lon"))
        if la is None or lo is None: continue
        out.append({"id": p.get("id"), "name": p.get("commonName") or "TfL JamCam", "lat": la, "lon": lo,
                    "thumb": props.get("imageUrl"), "stream": props.get("videoUrl") or props.get("imageUrl"),
                    "online": str(props.get("available", "true")).lower() == "true",
                    "view": props.get("view")})
    return out

def _pub_nyc():
    r = requests.get("https://webcams.nyctmc.org/api/cameras", timeout=20,
                     headers={"User-Agent": "SignalOps/2.1"})
    out = []
    if r.status_code != 200:
        print(f"[NYC DOT] HTTP {r.status_code}"); return out
    for c in r.json() or []:
        la, lo = sf(c.get("latitude")), sf(c.get("longitude"))
        if la is None or lo is None: continue
        out.append({"id": c.get("id"), "name": c.get("name") or "NYC DOT camera", "lat": la, "lon": lo,
                    "thumb": c.get("imageUrl"), "stream": c.get("imageUrl"),
                    "online": str(c.get("isOnline", "true")).lower() == "true", "view": c.get("area")})
    return out

def _pub_caltrans():
    def one(d):
        url = f"https://cwwp2.dot.ca.gov/data/d{d}/cctv/cctvStatusD{d:02d}.json"
        try:
            r = requests.get(url, timeout=20, headers={"User-Agent": "SignalOps/2.1"})
            if r.status_code != 200:
                return []
            res = []
            for item in (r.json().get("data") or []):
                c = item.get("cctv") or {}
                loc = c.get("location") or {}
                img = c.get("imageData") or {}
                la, lo = sf(loc.get("latitude")), sf(loc.get("longitude"))
                if la is None or lo is None: continue
                still = (img.get("static") or {}).get("currentImageURL")
                res.append({"id": f"D{d}-{c.get('index')}", "name": loc.get("locationName") or loc.get("nearbyPlace") or "Caltrans CCTV",
                            "lat": la, "lon": lo, "thumb": still,
                            "stream": img.get("streamingVideoURL") or still,
                            "online": str(c.get("inService", "true")).lower() == "true",
                            "view": " ".join(x for x in (loc.get("route"), loc.get("direction")) if x)})
            return res
        except Exception as e:
            print(f"[Caltrans D{d}] {e}"); return []
    pool = ThreadPoolExecutor(max_workers=6)
    try:
        futs = {pool.submit(one, d): d for d in range(1, 13)}
        got = gather_futures(futs, 30, "caltrans")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return [c for lst in got.values() for c in (lst or [])]

def _pub_digitraffic():
    r = requests.get("https://tie.digitraffic.fi/api/weathercam/v1/stations", timeout=20,
                     headers={"User-Agent": "SignalOps/2.1", "Digitraffic-User": "SignalOps",
                              "Accept-Encoding": "gzip"})
    out = []
    if r.status_code != 200:
        print(f"[Digitraffic] HTTP {r.status_code}"); return out
    j = r.json()
    feats = j.get("features") if isinstance(j, dict) else j
    for f in feats or []:
        props = f.get("properties") or f
        coords = (f.get("geometry") or {}).get("coordinates") or []
        if len(coords) < 2: continue
        lo, la = sf(coords[0]), sf(coords[1])
        if la is None or lo is None: continue
        presets = [pr for pr in (props.get("presets") or []) if isinstance(pr, dict) and pr.get("inCollection", True)]
        pid = presets[0].get("id") if presets else None
        img = f"https://weathercam.digitraffic.fi/{pid}.jpg" if pid else None
        out.append({"id": props.get("id"), "name": props.get("name") or "Digitraffic weathercam", "lat": la, "lon": lo,
                    "thumb": (img + "?thumbnail=true") if img else None, "stream": img,
                    "online": (props.get("collectionStatus") or "GATHERING") == "GATHERING",
                    "view": f"{len(presets)} preset" if presets else None})
    return out

def _xml_children(el):
    """XML etiketlerinden namespace'i atıp {etiket: metin} sözlüğü döndürür."""
    return {c.tag.split('}')[-1]: (c.text or "").strip() for c in list(el)}

def _pub_singapore():
    r = requests.get("https://api.data.gov.sg/v1/transport/traffic-images", timeout=20,
                     headers={"User-Agent": "SignalOps/2.1"})
    out = []
    if r.status_code != 200:
        print(f"[data.gov.sg] HTTP {r.status_code}"); return out
    for it in (r.json().get("items") or [])[:1]:
        for c in it.get("cameras") or []:
            loc = c.get("location") or {}
            la, lo = sf(loc.get("latitude")), sf(loc.get("longitude"))
            if la is None or lo is None: continue
            out.append({"id": c.get("camera_id"), "name": f"LTA camera {c.get('camera_id')}", "lat": la, "lon": lo,
                        "thumb": c.get("image"), "stream": c.get("image"), "online": True,
                        "view": c.get("timestamp")})
    return out

def _pub_hongkong():
    import xml.etree.ElementTree as ET
    r = requests.get("https://static.data.gov.hk/td/traffic-snapshot-images/code/Traffic_Camera_Locations_En.xml",
                     timeout=20, headers={"User-Agent": "SignalOps/2.1"})
    out = []
    if r.status_code != 200:
        print(f"[HK TD] HTTP {r.status_code}"); return out
    root = ET.fromstring(r.content)
    for el in root.iter():
        if el.tag.split('}')[-1] != "image": continue
        c = _xml_children(el)
        la, lo = sf(c.get("latitude")), sf(c.get("longitude"))
        if la is None or lo is None: continue
        out.append({"id": c.get("key"), "name": c.get("description") or c.get("key"), "lat": la, "lon": lo,
                    "thumb": c.get("url"), "stream": c.get("url"), "online": True,
                    "view": " · ".join(x for x in (c.get("region"), c.get("district")) if x)})
    return out

def _pub_nzta():
    import xml.etree.ElementTree as ET
    base = "https://trafficnz.info"
    r = requests.get(base + "/service/traffic/rest/4/cameras/all", timeout=20,
                     headers={"User-Agent": "SignalOps/2.1", "Accept": "application/xml"})
    out = []
    if r.status_code != 200:
        print(f"[NZTA] HTTP {r.status_code}"); return out
    root = ET.fromstring(r.content)
    for el in root.iter():
        if el.tag.split('}')[-1] != "camera": continue
        c = _xml_children(el)
        la, lo = sf(c.get("latitude")), sf(c.get("longitude"))
        if la is None or lo is None: continue
        img = c.get("imageUrl") or ""
        thumb = c.get("thumbUrl") or img
        if img.startswith("/"): img = base + img
        if thumb.startswith("/"): thumb = base + thumb
        out.append({"id": c.get("id"), "name": (c.get("name") or "NZTA camera").strip(), "lat": la, "lon": lo,
                    "thumb": thumb or None, "stream": img or None,
                    "online": str(c.get("offline", "false")).lower() != "true"
                              and str(c.get("underMaintenance", "false")).lower() != "true",
                    "view": " · ".join(x for x in (c.get("region"), c.get("highway"), c.get("direction")) if x)})
    return out

def _pub_dc_ddot():
    """DC DDOT trafik kameraları (ArcGIS) — görüntü URL'si yayınlanmıyor, sadece konum/kimlik."""
    r = requests.get("https://maps2.dcgis.dc.gov/dcgis/rest/services/DDOT/TrafficOperations/MapServer/2/query",
                     params={"where": "1=1", "outFields": "*", "f": "json", "outSR": 4326, "resultRecordCount": 1000},
                     timeout=20, headers={"User-Agent": "SignalOps/2.1"})
    out = []
    if r.status_code != 200:
        print(f"[DC DDOT] HTTP {r.status_code}"); return out
    for f in (r.json().get("features") or []):
        a = f.get("attributes") or {}
        g = f.get("geometry") or {}
        la = sf(a.get("Latitude")) or sf(g.get("y"))
        lo = sf(a.get("Longitude")) or sf(g.get("x"))
        if la is None or lo is None: continue
        out.append({"id": a.get("CameraID") or a.get("OBJECTID"), "name": a.get("Location") or "DDOT camera",
                    "lat": la, "lon": lo, "thumb": None, "stream": None,
                    "online": str(a.get("Operation_Status") or "").lower() not in ("inactive", "offline", "removed"),
                    "view": " · ".join(str(x) for x in (a.get("Make"), a.get("Description")) if x)})
    return out

def _pub_wsdot():
    """WSDOT (Washington eyaleti) — ücretsiz AccessCode gerekir (Settings)."""
    if not WSDOT_ACCESS_CODE: return []
    r = requests.get("https://wsdot.wa.gov/Traffic/api/HighwayCameras/HighwayCamerasREST.svc/GetCamerasAsJson",
                     params={"AccessCode": WSDOT_ACCESS_CODE}, timeout=25, headers={"User-Agent": "SignalOps/2.1"})
    out = []
    if r.status_code != 200:
        print(f"[WSDOT] HTTP {r.status_code}"); return out
    for c in r.json() or []:
        loc = c.get("CameraLocation") or {}
        la, lo = sf(loc.get("Latitude") or c.get("Latitude")), sf(loc.get("Longitude") or c.get("Longitude"))
        if la is None or lo is None: continue
        img = c.get("ImageURL") or c.get("ImageUrl")
        out.append({"id": c.get("CameraID"), "name": c.get("Title") or loc.get("Description") or "WSDOT camera",
                    "lat": la, "lon": lo, "thumb": img, "stream": img,
                    "online": bool(c.get("IsActive", True)),
                    "view": " · ".join(str(x) for x in (loc.get("RoadName"), loc.get("Direction")) if x)})
    return out

def _pub_trafikverket():
    """Trafikverket (İsveç) — ücretsiz API anahtarı gerekir (Settings)."""
    if not TRAFIKVERKET_API_KEY: return []
    from xml.sax.saxutils import quoteattr
    body = (f'<REQUEST><LOGIN authenticationkey={quoteattr(TRAFIKVERKET_API_KEY)}/>'
            '<QUERY objecttype="Camera" schemaversion="1"><FILTER><EQ name="Active" value="true"/></FILTER></QUERY>'
            '</REQUEST>')
    r = requests.post("https://api.trafikinfo.trafikverket.se/v2/data.json", data=body.encode(), timeout=25,
                      headers={"Content-Type": "text/xml", "User-Agent": "SignalOps/2.1"})
    out = []
    if r.status_code != 200:
        print(f"[Trafikverket] HTTP {r.status_code}"); return out
    for res in ((r.json().get("RESPONSE") or {}).get("RESULT") or []):
        for c in res.get("Camera") or []:
            wkt = ((c.get("Geometry") or {}).get("WGS84") or "")
            m = re.search(r"POINT\s*\(\s*(-?[\d.]+)\s+(-?[\d.]+)", wkt)
            if not m: continue
            lo, la = float(m.group(1)), float(m.group(2))
            img = c.get("PhotoUrl")
            out.append({"id": c.get("Id"), "name": c.get("Name") or "Trafikverket camera", "lat": la, "lon": lo,
                        "thumb": (img + "?type=thumbnail") if img else None, "stream": img,
                        "online": bool(c.get("Active", True)), "view": c.get("Direction") and f"dir {c.get('Direction')}°"})
    return out

# kaynak: (etiket, operatör, ülke, bbox [güney, batı, kuzey, doğu], yükleyici)
PUBLIC_WEBCAM_SOURCES = {
    "tfl_jamcam":  ("TfL JamCams",          "Transport for London",  "GB", (51.20, -0.65, 51.80, 0.40),   _pub_tfl),
    "nyc_dot":     ("NYC DOT",              "NYC DOT",               "US", (40.45, -74.30, 40.95, -73.65), _pub_nyc),
    "caltrans":    ("Caltrans CCTV",        "Caltrans",              "US", (32.40, -124.60, 42.10, -114.00), _pub_caltrans),
    "digitraffic": ("Digitraffic Weathercam", "Fintraffic / Digitraffic", "FI", (59.40, 19.00, 70.20, 31.70), _pub_digitraffic),
    "sg_lta":      ("Singapore LTA",        "Land Transport Authority (data.gov.sg)", "SG", (1.15, 103.55, 1.50, 104.10), _pub_singapore),
    "hk_td":       ("Hong Kong TD",         "HK Transport Department",  "HK", (22.13, 113.80, 22.60, 114.45), _pub_hongkong),
    "nzta":        ("NZTA Traffic Cameras", "NZ Transport Agency",      "NZ", (-47.60, 166.00, -34.00, 179.00), _pub_nzta),
    "dc_ddot":     ("DC DDOT",              "District DOT",             "US", (38.79, -77.13, 39.00, -76.90), _pub_dc_ddot),
    "wsdot":       ("WSDOT",                "Washington State DOT",     "US", (45.50, -124.90, 49.10, -116.90), _pub_wsdot),
    "trafikverket": ("Trafikverket",        "Swedish Transport Administration", "SE", (55.20, 10.90, 69.10, 24.20), _pub_trafikverket),
}
# Anahtar isteyen kamu kaynakları: anahtar yoksa sorgulanmaz / listede gösterilmez
PUBLIC_SOURCE_KEYS = {"wsdot": "WSDOT_ACCESS_CODE", "trafikverket": "TRAFIKVERKET_API_KEY"}

def _pub_enabled(key):
    k = PUBLIC_SOURCE_KEYS.get(key)
    return not k or bool(globals().get(k))
_pub_cache = {}
_pub_lock = threading.Lock()
_PUB_TTL = 3600
PUBLIC_RADIUS_KM = 30

def _pub_stations(key):
    with _pub_lock:
        hit = _pub_cache.get(key)
        if hit and time.time() - hit[0] < _PUB_TTL:
            return hit[1]
    try:
        data = PUBLIC_WEBCAM_SOURCES[key][4]() or []
    except Exception as e:
        print(f"[public/{key}] {e}"); data = []
    if data:
        with _pub_lock:
            _pub_cache[key] = (time.time(), data)
    print(f"[public/{key}] {len(data)} cameras")
    return data

def _pub_to_device(key, c, dist_km=None):
    label, operator, cc, _bbox, _fn = PUBLIC_WEBCAM_SOURCES[key]
    return {
        "lat": c["lat"], "lon": c["lon"],
        "ssid": c.get("name") or label, "ip": f"{key}:{c.get('id')}",
        "banner": f"{label}" + (f" · {c['view']}" if c.get("view") else "") + ("" if c.get("online", True) else " · OFFLINE"),
        "org": operator, "country": cc,
        "type": "camera", "source": key, "auth": True, "public": True,
        "thumb_url": c.get("thumb"), "stream_url": c.get("stream"),
        "online": c.get("online", True),
        "distance_km": round(dist_km, 2) if dist_km is not None else None,
        "risk": 5,
    }

def fetch_cameras_public(lat, lon, limit=150):
    """Arama noktasını kapsayan kamu webcam ağlarından en yakın kameralar."""
    out = []
    for key, (_l, _o, _cc, (s_, w_, n_, e_), _fn) in PUBLIC_WEBCAM_SOURCES.items():
        if not (s_ <= lat <= n_ and w_ <= lon <= e_) or not _pub_enabled(key):
            continue
        near = []
        for c in _pub_stations(key):
            dkm = _haversine_km(lat, lon, c["lat"], c["lon"])
            if dkm <= PUBLIC_RADIUS_KM:
                near.append((dkm, c))
        near.sort(key=lambda x: x[0])
        out.extend(_pub_to_device(key, c, dkm) for dkm, c in near[:limit])
    return out

def fetch_cameras_public_by_country(country, limit=300):
    out = []
    for key, (_l, _o, cc, _b, _fn) in PUBLIC_WEBCAM_SOURCES.items():
        if cc == country and _pub_enabled(key):
            out.extend(_pub_to_device(key, c) for c in _pub_stations(key)[:limit])
    return out

# ── Anahtarlı tarayıcı kaynakları: kamera odaklı sarmalayıcılar (sadece CCTV taraması) ──
def _as_cameras(devs, ports=(554, 37777, 34567, 8000, 8554)):
    out = []
    for d in devs or []:
        try: port = int(d.get("port") or 0)
        except (TypeError, ValueError): port = 0
        if d.get("type") == "camera" or port in ports:
            d["type"] = "camera"; out.append(d)
    return out

def fetch_cameras_netlas(lat, lon):    return _as_cameras(fetch_netlas(lat, lon))
def fetch_cameras_censys(lat, lon):    return _as_cameras(fetch_censys(lat, lon))
def fetch_cameras_hunterhow(lat, lon): return _as_cameras(fetch_hunterhow(lat, lon))

def fetch_cameras_zoomeye_v2(lat, lon):
    """ZoomEye v2 (api.zoomeye.ai) — eski api.zoomeye.org yerine. Alan adları sürüme göre değişebildiği
    için savunmacı ayrıştırma yapılır."""
    if not ZOOMEYE_KEY: return []
    country = get_country_iso(lat, lon)
    cf = f' && country="{country}"' if country else ""
    out = []
    for q in [f'port=554{cf}', f'app="Hikvision IP Camera"{cf}', f'app="Dahua"{cf}']:
        try:
            r = requests.post("https://api.zoomeye.ai/v2/search",
                headers={"API-KEY": ZOOMEYE_KEY, "Content-Type": "application/json", "User-Agent": "SignalOps/2.1"},
                json={"qbase64": base64.b64encode(q.encode()).decode(), "page": 1, "pagesize": 20}, timeout=T)
            if r.status_code != 200:
                print(f"[ZoomEye v2] HTTP {r.status_code}"); break
            for m in (r.json().get("data") or []):
                geo = m.get("geoinfo") or {}
                gl = geo.get("location") or {}
                rlat = sf(m.get("latitude") or m.get("lat") or gl.get("lat"))
                rlon = sf(m.get("longitude") or m.get("lon") or gl.get("lon"))
                ctry = m.get("country.name") or (m.get("country") if isinstance(m.get("country"), str) else "") \
                       or ((geo.get("country") or {}).get("names") or {}).get("en", "")
                out.append({**_loc(rlat, rlon, lat, lon),
                    "ip": m.get("ip"), "port": m.get("port"),
                    "banner": str(m.get("banner") or m.get("title") or m.get("product") or "")[:120],
                    "org": m.get("organization.name") or m.get("isp.name") or m.get("organization"),
                    "country": ctry, "type": "camera", "source": "zoomeye"})
        except Exception as e:
            print(f"[ZoomEye v2] {e}")
    return dedup(out)

# ── IP / host görünürlüğü ──
# Gerçek IP'si bilinen kameralarda ip_addr doldurulur. Kamu webcam'lerinde (IP yok) görüntü/yayın
# sunucusunun host adı çözülür — bu genelde bir CDN/sunucu IP'sidir, kameranın kendisi değil (ip_kind).
_dns_cache = {}
_dns_lock = threading.Lock()

def _resolve_host(host):
    with _dns_lock:
        if host in _dns_cache:
            return _dns_cache[host]
    ip = None
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
        ip = (v4 or [infos[0][4][0]])[0] if infos else None
    except Exception:
        ip = None
    with _dns_lock:
        _dns_cache[host] = ip
        if len(_dns_cache) > 2000:
            _dns_cache.pop(next(iter(_dns_cache)))
    return ip

def annotate_ips(devices, max_hosts=40):
    from urllib.parse import urlparse
    hosts = {}
    for d in devices:
        raw = str(d.get("ip") or "")
        try:
            d["ip_addr"] = str(ipaddress.ip_address(raw)); d["ip_kind"] = "device"
            continue
        except ValueError:
            pass
        url = d.get("stream_url") or d.get("thumb_url")
        h = urlparse(str(url)).hostname if url else None
        if h:
            d["host"] = h
            try:
                d["ip_addr"] = str(ipaddress.ip_address(h)); d["ip_kind"] = "device"
            except ValueError:
                hosts.setdefault(h, []).append(d)
    todo = list(hosts)[:max_hosts]
    if todo:
        pool = ThreadPoolExecutor(max_workers=8)
        try:
            futs = {pool.submit(_resolve_host, h): h for h in todo}
            got = gather_futures(futs, 6, "dns")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        for h, ip in got.items():
            if ip:
                for d in hosts[h]:
                    d["ip_addr"] = ip; d["ip_kind"] = "host"
    return devices

CAMERA_FETCHERS = [
    fetch_cameras_shodan, fetch_cameras_fofa,
    fetch_cameras_binaryedge, fetch_cameras_windy,
    fetch_cameras_osm, fetch_cameras_insecam,
    fetch_cameras_public, fetch_cameras_zoomeye_v2,
    # Disabled due to TR ISP TLS interference (WRONG_VERSION_NUMBER SSL errors):
    #   fetch_cameras_zoomeye, fetch_cameras_criminalip
    # To re-enable: use VPN/proxy then add back to list above.
]

def _run_with_executor(fns, lat, lon, max_workers, timeout):
    """STB-01: 'with' bloğu tüm thread'leri beklediği için timeout uygulanmıyordu.
    Havuz elle kapatılıyor; zaman aşımında biten sonuçlar döner, kalanlar arka planda biter."""
    results = []
    pool = ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = {pool.submit(fn, lat, lon): fn.__name__ for fn in fns}
        for name, res in gather_futures(futures, timeout, "executor").items():
            if res:
                results.extend(res)
                print(f"[{name}] +{len(res)}")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results

def apply_risk(devices):
    """STB-05: kaynağın kendi risk değeri (aircraft squawk, Insecam 85, OSM 30) korunur,
    score() ile hesaplanandan büyük olan alınır."""
    for d in devices:
        src_risk = d.get("risk")
        calc = score(d)
        try:
            d["risk"] = max(int(src_risk), calc) if src_risk is not None else calc
        except (TypeError, ValueError):
            d["risk"] = calc
    return tag_loc_quality(devices)

# Sadece CCTV sayfası için: /nearby zaten genel fetch_netlas/censys/hunterhow çağırıyor (çift kota olmasın)
CAMERA_ONLY_FETCHERS = [fetch_cameras_netlas, fetch_cameras_censys, fetch_cameras_hunterhow]

def camera_sources_for(lat=None, lon=None, country=None):
    """Bu taramada gerçekten sorgulanan kaynaklar [etiket, source-anahtarı] — arayüzdeki sayaçlar için."""
    out = []
    if country:
        if SHODAN_KEY and not _hblocked("Shodan"): out.append(["Shodan", "shodan"])
        out += [["Insecam", "insecam"], ["OpenStreetMap", "osm"]]
        out += [[v[0], k] for k, v in PUBLIC_WEBCAM_SOURCES.items() if v[2] == country and _pub_enabled(k)]
        return out
    keyed = [("Shodan", "shodan", SHODAN_KEY), ("FOFA", "fofa", FOFA_EMAIL and FOFA_KEY),
             ("BinaryEdge", "binaryedge", BINARYEDGE_KEY), ("Windy", "windy", WINDY_KEY),
             ("ZoomEye", "zoomeye", ZOOMEYE_KEY), ("Netlas", "netlas", NETLAS_KEY),
             ("Censys", "censys", CENSYS_ID and CENSYS_SECRET), ("Hunter.how", "hunterhow", HUNTERHOW_KEY)]
    # Kotası biten / yetkisi düşen sağlayıcılar listelenmez (tarama kalan kaynaklarla sürer)
    out += [[l, k] for l, k, on in keyed if on and not _hblocked(l)]
    out += [["OSM", "osm"], ["Insecam", "insecam"]]
    for k, (label, _o, _cc, (s_, w_, n_, e_), _fn) in PUBLIC_WEBCAM_SOURCES.items():
        if lat is not None and s_ <= lat <= n_ and w_ <= lon <= e_ and _pub_enabled(k):
            out.append([label, k])
    return out

def run_camera_scan(lat, lon):
    cameras = _run_with_executor(CAMERA_FETCHERS + CAMERA_ONLY_FETCHERS, lat, lon, max_workers=10, timeout=40)
    return annotate_ips(apply_risk(cameras))

ALL_FETCHERS = [
    fetch_wigle_wifi, fetch_wigle_bt, fetch_wigle_cell, fetch_opencellid,
    fetch_shodan, fetch_censys, fetch_hunterhow,
    fetch_netlas, fetch_leakix, fetch_adsb, fetch_opensky
    # Disabled due to TR ISP TLS interference (wrong version number SSL errors):
    #   fetch_zoomeye, fetch_criminalip
    # To re-enable: use VPN or selective proxy, then add back to list above.
]

def run_parallel(lat, lon):
    """
    Full unified RF/OSINT scan for a location.
    Combines ALL_FETCHERS (general device/tower/aircraft) with CAMERA_FETCHERS
    (Shodan/FOFA/BinaryEdge/Windy/OSM/Insecam cameras) so /nearby really returns
    everything — WiFi, BT, cell towers, IoT, aircraft, AND cameras from all sources.
    """
    combined = ALL_FETCHERS + CAMERA_FETCHERS
    devices = _run_with_executor(combined, lat, lon, max_workers=14, timeout=45)
    # Dedup to avoid double-counting cameras that appear in both general Shodan
    # and camera-specific Shodan queries (same IP+port)
    devices = dedup(devices)
    return apply_risk(devices)

CELL_FETCHERS = [fetch_wigle_cell, fetch_opencellid]

def run_cell_scan(lat, lon):
    """STB-13: Geo/Mobile sayfaları için sadece baz istasyonu kaynakları (kota tasarrufu)."""
    towers = _run_with_executor(CELL_FETCHERS, lat, lon, max_workers=2, timeout=20)
    return apply_risk(dedup(towers))

# ══════════════════════════════════════════════
#  STARTUP
# ══════════════════════════════════════════════
_startup_done = False

def _startup():
    global _startup_done
    if _startup_done: return
    _startup_done = True
    print("[SignalOPS v2-patched] Startup complete")

with app.app_context():
    _startup()

# ══════════════════════════════════════════════
#  ROUTES — Pages
# ══════════════════════════════════════════════
@app.route("/")
def root(): return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", active="Overview")

@app.route("/map-w")
def sigint_map():
    return render_template("wifi_search.html", active="SIGINT Map")

@app.route("/surveillance")
def surveillance():
    return render_template("surveillance.html", active="Surveillance")

@app.route("/cctv")
def cctv():
    return render_template("cctv.html", active="CCTV")

@app.route("/geo")
def geo():
    return render_template("geo.html", active="Geo Track")

@app.route("/mobile")
def mobile():
    return render_template("mobile.html", active="Mobile")

@app.route("/profiles")
def profiles():
    return render_template("profiles.html", active="Profiles")

@app.route("/social")
def social():
    return render_template("social.html", active="Social")

@app.route("/settings")
def settings():
    return render_template("settings.html", active="Settings")

# ══════════════════════════════════════════════
#  API ROUTES
# ══════════════════════════════════════════════
@app.route("/nearby")
@rate_limit("20 per minute")
def nearby():
    lat, lon = validate_coords(request.args.get("lat"), request.args.get("lon"))
    if lat is None:
        return jsonify({"error": "Valid lat/lon required (-90..90, -180..180)"}), 400

    mode = request.args.get("mode", "wifi")
    if mode == "bluetooth":
        devices = apply_risk(fetch_wigle_bt(lat, lon))
    elif mode == "cell":
        devices = run_cell_scan(lat, lon)
    else:
        devices = run_parallel(lat, lon)

    devices  = track_devices(devices)
    analysis = analyze_area(devices)
    rogue    = detect_rogue_aps(devices)
    anomaly  = detect_anomaly(devices, lat, lon)
    findings = run_modules(devices)
    trackers = detect_bt_trackers(devices)

    # IMSI catcher detection on cell_tower subset
    towers = [d for d in devices if d.get("type") == "cell_tower"]
    imsi_findings = detect_imsi_catchers(towers) if towers else []

    # Annotate device list with tracker flag (for surveillance table highlighting)
    tracker_bssids = {t.get("bssid") for t in trackers if t.get("bssid")}
    imsi_cellids   = {str(f.get("cell_id")) for f in imsi_findings if f.get("cell_id")}
    for d in devices:
        if d.get("bssid") in tracker_bssids:
            d["is_tracker"] = True
        if d.get("type") == "cell_tower" and str(d.get("cell_id")) in imsi_cellids:
            # Attach IMSI finding details to the device
            for f in imsi_findings:
                if str(f.get("cell_id")) == str(d.get("cell_id")):
                    d["imsi_suspect"]  = True
                    d["imsi_severity"] = f["severity"]
                    d["imsi_level"]    = f["level"]
                    d["imsi_reasons"]  = f["reasons"]
                    break
        # Flag rogue-group members too
        for r in rogue:
            if d.get("ssid") == r["ssid"] and d.get("bssid") in r.get("bssids", []):
                d["rogue_severity"] = r["severity"]
                d["rogue_level"] = r["level"]
                break

    return jsonify({
        "devices": devices, "analysis": analysis,
        "rogue": rogue, "anomaly": anomaly, "findings": findings,
        "trackers": trackers, "imsi_findings": imsi_findings
    })

# ══════════════════════════════════════════════
#  BUG-17 + BUG-18 FIX: /api/cctv tam rewrite
# ══════════════════════════════════════════════
@app.route("/api/cctv")
@rate_limit("10 per minute")
def api_cctv():
    lat_param = request.args.get("lat")
    lon_param = request.args.get("lon")
    raw_country = (request.args.get("country") or "").strip()
    country   = clean_country(raw_country)
    if raw_country and not country:
        return jsonify({"error": "country must be an ISO-2 code (e.g. TR, US)"}), 400

    cameras = []

    # ── COUNTRY MODE ──────────────────────────────────────────────
    if country and not lat_param:
        country_fns = [
            lambda c=country: fetch_shodan_country(c),
            lambda c=country: fetch_cameras_insecam_by_country(c),
            lambda c=country: fetch_cameras_osm_by_country(c),   # OSM ücretsiz, her zaman çalışır
            lambda c=country: fetch_cameras_public_by_country(c), # resmî trafik/hava kameraları (GB/US/FI)
            # EarthCam country pages are JS-rendered — the public HTML only contains the country
            # menu, not the actual camera list. Returns 0 cameras but costs 10s of wait time.
            # To use EarthCam, hit individual cam URLs directly (location mode only).
            #   lambda c=country: fetch_earthcam_by_country(c),
            # ZoomEye disabled — TR ISP TLS interference (WRONG_VERSION_NUMBER).
            #   lambda c=country: fetch_zoomeye_country(c),
        ]
        pool = ThreadPoolExecutor(max_workers=4)
        try:
            futs = [pool.submit(fn) for fn in country_fns]
            try:
                for fut in as_completed(futs, timeout=30):
                    try:
                        res = fut.result()
                        if res:
                            cameras.extend(res)
                    except Exception as e:
                        print(f"[api/cctv country] {e}")
            except FuturesTimeout:
                # Some fetchers didn't finish in time (usually ZoomEye SSL fail or slow Overpass).
                # Collect results from futures that DID complete, then cancel the rest.
                done_count = 0
                for fut in futs:
                    if fut.done():
                        try:
                            res = fut.result(timeout=0)
                            if res:
                                cameras.extend(res)
                                done_count += 1
                        except Exception as e:
                            print(f"[api/cctv country late] {e}")
                    else:
                        fut.cancel()
                print(f"[api/cctv country] timeout after 30s — {done_count}/{len(futs)} fetchers finished, continuing")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        lat, lon = None, None

    # ── LOCATION MODE ─────────────────────────────────────────────
    else:
        lat, lon = validate_coords(lat_param, lon_param)
        if lat is None:
            return jsonify({"error": "Valid lat/lon required"}), 400
        cameras = run_camera_scan(lat, lon)

    # ── Dedup + risk ──────────────────────────────────────────────
    cameras = dedup(cameras)
    for c in cameras:
        if not c.get("risk"):
            c["risk"] = score(c)
    tag_loc_quality(cameras)
    annotate_ips(cameras)

    # ── Gemini analizi ────────────────────────────────────────────
    analysis   = None
    risk_level = "LOW"

    if cameras and GEMINI_KEY and _hblocked("Gemini"):
        analysis = _ai_unavailable()          # kota/yetki engeli → AI atlanır, kameralar yine döner
    elif cameras and GEMINI_KEY:
        try:
            from google import genai as gai
            client = gai.Client(api_key=GEMINI_KEY)

            total = len(cameras)
            high  = [c for c in cameras if (c.get("risk") or 0) >= 70]
            ports = {}
            for c in cameras:
                p = str(c.get("port", "?"))
                ports[p] = ports.get(p, 0) + 1
            sources = list(set(c.get("source", "?") for c in cameras))
            loc_str = (f"lat={lat:.4f}, lon={lon:.4f}" if lat and lon
                       else f"country={country}" if country else "unspecified")

            summary = (
                f"{total} cameras found.\n"
                f"High risk (>=70): {len(high)}\n"
                f"Port dist: {ports}\n"
                f"Sources: {sources}\n"
                f"Location: {loc_str}"
            )
            if high:
                summary += "\nCritical:\n"
                for c in high[:3]:
                    summary += (f"  - {c.get('ip','?')} port:{c.get('port','?')}"
                                f" risk:{c.get('risk',0)}\n")

            res = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=(
                    "You are SignalOps SIGINT AI. Analyze these camera scan results:\n\n"
                    + summary +
                    "\n\n1. OVERALL ASSESSMENT\n2. CRITICAL FINDINGS (top 3)\n"
                    "3. RECOMMENDATIONS\n4. End with exactly one line: 'RISK LEVEL: <one of CRITICAL, HIGH, MEDIUM, LOW>'"
                ),
                config={"system_instruction":
                    "You are SignalOps SIGINT AI, expert in wireless security and IoT threats."}
            )
            analysis = res.text
            fallback = "HIGH" if len(high) > 3 else "MEDIUM" if high else "LOW"
            risk_level = parse_risk_level(analysis, fallback)

        except Exception as e:
            print(f"[api/cctv gemini] {type(e).__name__}: {str(e)[:160]}")
            analysis = _ai_unavailable(e)

    return jsonify({
        "cameras":    cameras,
        "total":      len(cameras),
        "analysis":   analysis,
        "risk_level": risk_level,
        "sources_queried": camera_sources_for(lat, lon, country if lat is None else None),
    })

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){2,5}$")

@app.route("/api/search")
@rate_limit("20 per minute")
def api_search():
    stype = (request.args.get("type", "ssid") or "ssid").lower()
    query = request.args.get("query", "").strip()[:200]
    if not query: return jsonify({"devices": []})
    devices = []
    error = None
    try:
        if stype in ("ssid", "bssid"):
            if not (WIGLE_USER and WIGLE_TOKEN):
                return jsonify({"devices": [], "error": "WiGLE credentials not configured"})
            if stype == "bssid":
                if not _MAC_RE.match(query):
                    return jsonify({"devices": [], "error": "Invalid BSSID (expected AA:BB:CC:DD:EE:FF)"}), 400
                q = re.sub(r"[^0-9A-Fa-f]", "", query).upper()
                params = {"netid": ":".join(q[i:i+2] for i in range(0, len(q), 2)), "resultsPerPage": 50}
            else:
                params = {"ssid": query, "resultsPerPage": 50}
            r = requests.get("https://api.wigle.net/api/v2/network/search",
                params=params, auth=(WIGLE_USER, WIGLE_TOKEN), timeout=T)
            if r.status_code == 200:
                for net in r.json().get("results", []):
                    enc = norm_enc(net.get("encryption")); bssid = net.get("netid","")
                    d = {"lat": net.get("trilat"), "lon": net.get("trilong"),
                         "ssid": net.get("ssid"), "bssid": bssid,
                         "vendor": net.get("vendor"), "encryption": enc,
                         "leaked": enc in ("OPEN","WEP"),
                         "signal": net.get("level"), "timestamp": net.get("lastupdt"),
                         "type": classify(net.get("ssid",""), "router"), "source": "wigle"}
                    devices.append(d)
            else:
                error = f"WiGLE HTTP {r.status_code}"
        elif stype == "ip" and SHODAN_KEY:
            try:
                query = str(ipaddress.ip_address(query))
            except ValueError:
                return jsonify({"devices": [], "error": "Invalid IP address"}), 400
            r = requests.get(f"https://api.shodan.io/shodan/host/{query}",
                params={"key": SHODAN_KEY}, timeout=T)
            if r.status_code == 200:
                d = r.json(); loc = d.get("location", {})
                devices.append({"lat": loc.get("latitude"), "lon": loc.get("longitude"),
                    "ip": query, "org": d.get("org"), "os": d.get("os"),
                    "ports": d.get("ports", []),
                    "vulns": list((d.get("vulns") or {}).keys()),
                    "country": loc.get("country_name", ""),
                    "type": "iot_device", "source": "shodan"})
        elif stype in ("location", "country"):
            # Location search: accept either "lat,lon" coordinates or a city/country name.
            # Country name → geocode to center + run full /nearby scan there.
            lat = lon = None
            place_name = None

            # Try parsing as coordinates first ("41.01, 28.97" or "41.01 28.97")
            coord_match = re.match(r"^\s*(-?\d+\.?\d*)\s*[,\s]\s*(-?\d+\.?\d*)\s*$", query)
            if coord_match:
                try:
                    lat = float(coord_match.group(1))
                    lon = float(coord_match.group(2))
                    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                        lat = lon = None
                except ValueError:
                    pass

            # Not coordinates → geocode via Nominatim (free, no API key)
            if lat is None:
                try:
                    gr = requests.get(
                        "https://nominatim.openstreetmap.org/search",
                        params={"q": query, "format": "json", "limit": 1},
                        headers={"User-Agent": "SignalOPS/2.0"},
                        timeout=10,
                    )
                    if gr.status_code == 200:
                        results = gr.json()
                        if results:
                            lat = float(results[0].get("lat"))
                            lon = float(results[0].get("lon"))
                            place_name = results[0].get("display_name", query)
                except Exception as e:
                    print(f"[api_search geocode] {e}")

            if lat is None or lon is None:
                return jsonify({
                    "devices": [],
                    "error": f"Could not resolve location '{query}'. "
                             f"Try a city name (e.g. 'Istanbul'), country ('Turkey'), or coordinates ('41.01, 28.97')."
                })

            print(f"[api_search location] '{query}' → lat={lat}, lon={lon} ({place_name or 'coords'})")
            # Run full parallel fetchers just like /nearby does
            devices = run_parallel(lat, lon)
            # Tag center for frontend
            for d in devices:
                if "search_center" not in d:
                    d["search_center"] = {"lat": lat, "lon": lon, "place": place_name or query}
    except Exception as e:
        print(f"[api_search] {e}")
        error = "Search failed"
    apply_risk(devices)
    resp = {"devices": devices}
    if error: resp["error"] = error
    return jsonify(resp)

@app.route("/api/analyze", methods=["POST"])
@rate_limit("15 per minute")
def api_analyze():
    try: data = request.get_json(force=True, silent=True) or {}
    except: data = {}
    devices = data.get("devices", [])
    if not isinstance(devices, list): devices = []
    devices = [d for d in devices if isinstance(d, dict)][:5000]
    lat = sf(data.get("lat")); lon = sf(data.get("lon"))
    if not devices: return jsonify({"analysis": None})
    if not GEMINI_KEY: return jsonify({"analysis": "⚠ Gemini API key missing."})
    if _hblocked("Gemini"): return jsonify({"analysis": _ai_unavailable(), "risk_level": "UNKNOWN"})
    try:
        from google import genai as gai
        client = gai.Client(api_key=GEMINI_KEY)
        total = len(devices); by_type = {}
        for d in devices:
            t = d.get("type","unknown"); by_type[t] = by_type.get(t, 0)+1
        high_risk = [d for d in devices if (d.get("risk") or 0) >= 70]
        open_nets = [d for d in devices if d.get("leaked")]
        cameras   = [d for d in devices if d.get("type") == "camera"]
        drones    = [d for d in devices if d.get("type") in ("drone","aircraft")]
        summary = f"""Device summary ({total} total):
By type: {by_type}
High risk (>=70): {len(high_risk)}
Open/weak networks: {len(open_nets)}
Cameras: {len(cameras)}
Drones/Aircraft: {len(drones)}
Location: {f"lat={lat:.4f}, lon={lon:.4f}" if lat is not None and lon is not None else "unspecified"}
"""
        if high_risk:
            summary += "\nTop critical:\n"
            for d in high_risk[:5]:
                summary += f"  - {d.get('ssid') or d.get('ip') or d.get('cell_id','?')} ({d.get('type','?')}) risk={d.get('risk',0)} src={d.get('source','?')}\n"
        cracked = [d for d in devices if d.get("leaked")]
        if cracked:
            summary += "\nCracked:\n"
            for d in cracked[:3]:
                summary += f"  - BSSID:{d.get('bssid','?')} SSID:{d.get('ssid','?')}\n"
        ctx_note = str(data.get("context") or "").strip()[:500]
        if ctx_note:
            summary += f"\nAnalyst context: {ctx_note}\n"
        prompt = f"You are SignalOps SIGINT AI. Analyze these scan results.\n\n{summary}\n\nGenerate:\n1. OVERALL ASSESSMENT\n2. CRITICAL THREATS (top 3)\n3. RECOMMENDATIONS\n4. End with exactly one line: 'RISK LEVEL: <one of CRITICAL, HIGH, MEDIUM, LOW>'"
        res = client.models.generate_content(
            model=GEMINI_MODEL, contents=prompt,
            config={"system_instruction": "You are SignalOps SIGINT AI, expert in RF, wireless, and IoT threat intelligence."})
        text = res.text
        fallback = "HIGH" if len(high_risk) > 3 else "MEDIUM" if high_risk else "LOW"
        risk_level = parse_risk_level(text, fallback)
        return jsonify({"analysis": text, "risk_level": risk_level})
    except Exception as e:
        print(f"[api/analyze] {e}")
        return jsonify({"analysis": _ai_unavailable(e), "risk_level": "UNKNOWN"})

@app.route("/api/chat", methods=["POST"])
@app.route("/chatgpt", methods=["POST"])
@rate_limit("20 per minute")
def api_chat():
    # force=True kaldırıldı: text/plain cross-site POST ile kota yakılmasını engeller
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict): data = {}
    msg = (data.get("message") or "").strip()[:4000]
    if not msg: return jsonify({"reply": "Message empty."}), 400
    if not GEMINI_KEY: return jsonify({"reply": "⚠ GEMINI_API_KEY missing."})
    if _hblocked("Gemini"): return jsonify({"reply": _ai_unavailable()})
    try:
        from google import genai as gai
        client = gai.Client(api_key=GEMINI_KEY)
        ctx = data.get("map_context") or {}
        ctx_parts = []
        if ctx.get("total"): ctx_parts.append(f"[Map scan: {ctx.get('total',0)} devices]")
        if ctx.get("location"): ctx_parts.append(f"[Location: {ctx['location']}]")
        for k in ["wifi","bt","camera","cell","drone","iot","high_risk","cracked"]:
            if ctx.get(k):
                labels = {"wifi":"WiFi","bt":"Bluetooth","camera":"Camera","cell":"Cell Tower",
                          "drone":"Drone","iot":"IoT","high_risk":"High Risk","cracked":"Cracked"}
                ctx_parts.append(f"{labels.get(k,k)}: {ctx[k]}")
        ctx_str = " | ".join(ctx_parts)
        system_text = (
            "You are SignalOps — advanced SIGINT and OSINT AI analyst. "
            "Expert in wireless signal intelligence, RF security, drone detection, "
            "IoT threats, and cybersecurity. Respond in English or Turkish based on user language. "
            "Be short, technical, and actionable."
            + (f"\n\nActive Map Context: {ctx_str}" if ctx_str else "")
        )
        history = data.get("history") or []
        if not isinstance(history, list): history = []
        conv_messages = []
        for h in history[-14:]:
            if not isinstance(h, dict): continue
            role = h.get("role", "")
            if role == "bot": role = "model"
            content = str(h.get("content", ""))[:4000]
            if role in ("user", "model") and content:
                conv_messages.append({"role": role, "parts": [{"text": content}]})
        all_msgs = conv_messages + [{"role": "user", "parts": [{"text": msg}]}]
        res = client.models.generate_content(
            model=GEMINI_MODEL, contents=all_msgs,
            config={"system_instruction": system_text})
        return jsonify({"reply": res.text})
    except Exception as e:
        print(f"[api/chat] {e}")
        return jsonify({"reply": _ai_unavailable(e)})

@app.route("/api/status")
def api_status():
    keys = {
        # İki parçalı kimlikler: ikisi de girilmeden "aktif" sayılmaz
        "WiGLE": WIGLE_USER and WIGLE_TOKEN, "OpenCellID": OPENCELLID_KEY,
        "Shodan": SHODAN_KEY, "Censys": CENSYS_ID and CENSYS_SECRET,
        "ZoomEye": ZOOMEYE_KEY, "FOFA": FOFA_EMAIL and FOFA_KEY,
        "Hunter.how": HUNTERHOW_KEY, "Netlas": NETLAS_KEY,
        "LeakIX": LEAKIX_KEY, "CriminalIP": CRIMINALIP_KEY,
        "BinaryEdge": BINARYEDGE_KEY, "Windy": WINDY_KEY,
        "AbuseIPDB": ABUSEIPDB_KEY, "APRS.fi": APRS_FI_KEY,
        "Gemini": GEMINI_KEY,
        "Insecam": True, "EarthCam": True,
    }
    resp = {
        "active":  [k for k,v in keys.items() if v],
        "missing": [k for k,v in keys.items() if not v],
        "version": "2.0-patched",
    }
    # Ek alanlar (mevcut alanlar değişmedi): kota/yetki sorunlu sağlayıcılar + ağ modu
    try:
        resp["degraded"] = {k: v for k, v in _health.degraded().items() if keys.get(k)} if _health else {}
    except Exception:
        resp["degraded"] = {}
    nm = getattr(_MODULE_CTX, "net_mode", None)
    resp["net_mode"] = nm() if callable(nm) else "off"
    return jsonify(resp)

@app.route("/api/debug")
def api_debug():
    keys = {
        "WIGLE_USER": bool(WIGLE_USER), "WIGLE_TOKEN": bool(WIGLE_TOKEN),
        "OPENCELLID_KEY": bool(OPENCELLID_KEY), "SHODAN_KEY": bool(SHODAN_KEY),
        "CENSYS_ID": bool(CENSYS_ID), "CENSYS_SECRET": bool(CENSYS_SECRET),
        "ZOOMEYE_KEY": bool(ZOOMEYE_KEY), "FOFA_EMAIL": bool(FOFA_EMAIL),
        "FOFA_KEY": bool(FOFA_KEY), "HUNTERHOW_KEY": bool(HUNTERHOW_KEY),
        "NETLAS_KEY": bool(NETLAS_KEY), "LEAKIX_KEY": bool(LEAKIX_KEY),
        "CRIMINALIP_KEY": bool(CRIMINALIP_KEY), "BINARYEDGE_KEY": bool(BINARYEDGE_KEY),
        "WINDY_KEY": bool(WINDY_KEY),
        "ABUSEIPDB_KEY": bool(ABUSEIPDB_KEY), "ADSB_KEY": bool(ADSB_KEY),
        "GEMINI_KEY": bool(GEMINI_KEY),
    }
    wigle_ok = False
    if WIGLE_USER and WIGLE_TOKEN:
        try:
            r = requests.get("https://api.wigle.net/api/v2/profile/user",
                auth=(WIGLE_USER, WIGLE_TOKEN), timeout=5)
            wigle_ok = r.status_code == 200
        except: pass
    return jsonify({
        "keys_loaded": keys,
        "active_count": sum(1 for v in keys.values() if v),
        "wigle_auth_ok": wigle_ok,
        "version": "2.0-patched"
    })



@app.route("/api/mac-lookup")
def mac_lookup():
    mac = request.args.get("mac", "").strip()
    if not mac: return jsonify({"vendor": None}), 400
    if not _MAC_RE.match(mac):
        return jsonify({"vendor": None, "error": "Invalid MAC"}), 400
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=4)
        if r.status_code == 200:
            return jsonify({"vendor": r.text.strip()})
        return jsonify({"vendor": None})
    except Exception as e:
        print(f"[mac-lookup] {e}")
        return jsonify({"vendor": None, "error": "lookup failed"})

@app.route("/api/ip-lookup")
def ip_lookup():
    ip = request.args.get("ip", "").strip()
    if not ip: return jsonify({}), 400
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return jsonify({"error": "Invalid IP"}), 400
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get("ip") and not d.get("error"):
                return jsonify(d)
    except Exception: pass
    try:
        r2 = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,org,city,country,countryCode,lat,lon,isp,as,hosting,proxy,mobile"},
            timeout=5)
        if r2.status_code == 200:
            d2 = r2.json()
            if d2.get("status") == "success":
                return jsonify(d2)
    except Exception as e:
        print(f"[ip-lookup] {e}")
        return jsonify({"error": "lookup failed"})
    return jsonify({})

# ══════════════════════════════════════════════
#  IP THREAT INTELLIGENCE (multi-source aggregator)
# ══════════════════════════════════════════════
from ipaddress import ip_address as _ipaddr

# Port analizi için: (port, finding_message)
_IPINTEL_PORTS = [21, 22, 23, 80, 443, 554, 8080, 7547]
_PORT_FINDINGS = {
    23:   "Telnet exposed",
    554:  "RTSP camera detected",
    7547: "Router exploit risk (CWMP)",
    21:   "FTP exposed",
}

def _is_valid_public_ip(ip: str) -> bool:
    """SSRF koruması: private/loopback/reserved IP'leri reddet."""
    try:
        ipo = _ipaddr(ip)
        return not (ipo.is_private or ipo.is_loopback or ipo.is_reserved
                    or ipo.is_link_local or ipo.is_multicast or ipo.is_unspecified)
    except ValueError:
        return False

def _ipintel_geo(ip: str) -> dict:
    """ipinfo.io -> country, city, org, loc."""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            d = r.json()
            loc = d.get("loc", "")
            lat, lon = (None, None)
            if "," in loc:
                try: lat, lon = [float(x) for x in loc.split(",", 1)]
                except Exception: pass
            return {
                "country":  d.get("country", ""),
                "city":     d.get("city", ""),
                "region":   d.get("region", ""),
                "org":      d.get("org", ""),
                "hostname": d.get("hostname", ""),
                "lat": lat, "lon": lon,
            }
    except Exception as e:
        print(f"[ip-intel/geo] {e}")
    return {"country":"", "city":"", "region":"", "org":"", "hostname":"", "lat":None, "lon":None}

def _ipintel_abuse(ip: str) -> dict:
    """AbuseIPDB -> abuseConfidenceScore, totalReports."""
    if not ABUSEIPDB_KEY:
        return {"abuseConfidenceScore": 0, "totalReports": 0, "available": False}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=6,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "abuseConfidenceScore": int(d.get("abuseConfidenceScore", 0) or 0),
                "totalReports":         int(d.get("totalReports", 0) or 0),
                "lastReportedAt":       d.get("lastReportedAt"),
                "usageType":            d.get("usageType", ""),
                "isp":                  d.get("isp", ""),
                "domain":               d.get("domain", ""),
                "available": True,
            }
    except Exception as e:
        print(f"[ip-intel/abuse] {e}")
    return {"abuseConfidenceScore": 0, "totalReports": 0, "available": False}

# Module-level session with retry + TLS 1.2 pinning for CriminalIP
# (aralıklı SSL handshake hatalarına karşı)
import ssl
from requests.adapters import HTTPAdapter
try:
    from urllib3.util.retry import Retry
    from urllib3.util.ssl_ import create_urllib3_context
    _urllib3_ok = True
except ImportError:
    _urllib3_ok = False

class _TLS12Adapter(HTTPAdapter):
    """TLS 1.2 sabitlenmiş HTTPAdapter — bazı CDN'ler TLS 1.3'te flaky."""
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)

def _make_cip_session():
    s = requests.Session()
    if _urllib3_ok:
        retry = Retry(
            total=3, backoff_factor=0.6,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        adapter = _TLS12Adapter(max_retries=retry)
    else:
        adapter = _TLS12Adapter()
    s.mount("https://", adapter)
    s.mount("http://",  adapter)
    return s

_cip_session = _make_cip_session()

def _ipintel_criminalip(ip: str) -> dict:
    """CriminalIP — TLS 1.2 pinned session + retry + dual endpoint fallback."""
    if not CRIMINALIP_KEY:
        return {"score": 0, "classification": "", "tags": [], "available": False}

    headers = {
        "x-api-key":  CRIMINALIP_KEY,
        "User-Agent": "SignalOPS/2.0 (+https://signalops.local)",
        "Accept":     "application/json",
        "Connection": "close",          # keep-alive'ı kapat → her istek yeni handshake
    }
    mapping = {"critical": 95, "dangerous": 80, "moderate": 55, "low": 25, "safe": 5}

    def _parse(d: dict) -> dict:
        score_obj = d.get("score", {}) or {}
        inbound   = (score_obj.get("inbound") or "").strip()
        issues    = d.get("issues", {}) or {}
        tags = []
        for k in ("is_vpn","is_proxy","is_tor","is_hosting","is_scanner",
                  "is_cloud","is_darkweb","is_anonymous_vpn","is_snort"):
            if issues.get(k):
                tags.append(k.replace("is_","").replace("_"," "))
        return {
            "score": mapping.get(inbound.lower(), 0),
            "classification": inbound or "",
            "tags": tags,
            "available": True,
        }

    last_err = None
    endpoints = [
        ("https://api.criminalip.io/v1/asset/ip/report",         {"ip": ip, "full": "true"}),
        ("https://api.criminalip.io/v1/asset/ip/report/summary", {"ip": ip}),
    ]

    for url, params in endpoints:
        for attempt in range(3):  # 3 deneme
            try:
                r = _cip_session.get(url, params=params, headers=headers, timeout=15)
                if r.status_code == 200:
                    return _parse(r.json())
                elif r.status_code in (401, 403):
                    return {"score": 0, "classification": "", "tags": [],
                            "available": False, "error": "auth"}
                elif r.status_code == 429:
                    last_err = "rate-limited"
                    time.sleep(1.0 * (attempt + 1))
                    continue
                else:
                    last_err = f"HTTP {r.status_code}"
                    break  # non-SSL error → next endpoint
            except requests.exceptions.SSLError as e:
                last_err = f"SSL: {str(e)[:80]}"
                time.sleep(0.5 * (attempt + 1))  # backoff
                continue
            except Exception as e:
                last_err = str(e)[:80]
                time.sleep(0.3)
                continue

    print(f"[ip-intel/criminalip] giving up — last error: {last_err}")
    return {"score": 0, "classification": "", "tags": [], "available": False}


def _ipintel_leakix(ip: str) -> dict:
    """LeakIX -> expose olmuş servis var mı?"""
    if not LEAKIX_KEY:
        return {"exposed": False, "services": [], "available": False}
    try:
        r = requests.get(
            f"https://leakix.net/host/{ip}",
            headers={"api-key": LEAKIX_KEY, "Accept": "application/json"},
            timeout=7,
        )
        if r.status_code == 200:
            d = r.json()
            services = d.get("Services", []) or []
            leaks    = d.get("Leaks", []) or []
            svc_names = []
            for s in services[:10]:
                svc_names.append(f"{s.get('protocol','?')}:{s.get('port','?')}")
            return {
                "exposed": bool(services) or bool(leaks),
                "services": svc_names,
                "leak_count": len(leaks),
                "available": True,
            }
    except Exception as e:
        print(f"[ip-intel/leakix] {e}")
    return {"exposed": False, "services": [], "available": False}

def _ipintel_zoomeye(ip: str) -> dict:
    """ZoomEye v2 API -> host/port/service info.
    v2 endpoint: POST https://api.zoomeye.ai/v2/search with base64-encoded qbase64.
    """
    if not ZOOMEYE_KEY:
        return {"ports": [], "services": [], "available": False}

    headers = {
        "API-KEY":      ZOOMEYE_KEY,
        "User-Agent":   "SignalOPS/2.0",
        "Content-Type": "application/json",
        "Accept":       "application/json",
    }
    qbase64 = base64.b64encode(f'ip="{ip}"'.encode()).decode()
    payload = {"qbase64": qbase64, "page": 1, "pagesize": 20}

    try:
        r = requests.post(
            "https://api.zoomeye.ai/v2/search",
            headers=headers, json=payload, timeout=10,
        )
        if r.status_code == 200:
            d = r.json()
            matches = d.get("data") or d.get("matches") or []
            ports, services = set(), []
            for m in matches[:20]:
                # v2 flat structure: port, service, protocol at top level
                port = m.get("port") or (m.get("portinfo") or {}).get("port")
                if port:
                    try: ports.add(int(port))
                    except Exception: pass
                svc = m.get("service") or (m.get("portinfo") or {}).get("service")
                if svc and port:
                    services.append(f"{svc}:{port}")
            return {
                "ports":     sorted(ports),
                "services":  services[:10],
                "total":     d.get("total", len(matches)),
                "available": True,
            }
        elif r.status_code in (401, 403):
            print(f"[ip-intel/zoomeye] auth failed (HTTP {r.status_code})")
            return {"ports": [], "services": [], "available": False, "error": "auth"}
        else:
            print(f"[ip-intel/zoomeye] HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[ip-intel/zoomeye] {e}")

    return {"ports": [], "services": [], "available": False}

def _ipintel_portscan(ip: str) -> dict:
    """Lightweight TCP connect() scan — 2s timeout per port, parallel."""
    open_ports = []
    def _probe(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            return None
        return None
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        futs = {pool.submit(_probe, p): p for p in _IPINTEL_PORTS}
        for res in gather_futures(futs, 12, "portscan").values():
            if res: open_ports.append(res)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    open_ports.sort()
    findings = [_PORT_FINDINGS[p] for p in open_ports if p in _PORT_FINDINGS]
    return {"open_ports": open_ports, "findings": findings}

def _ipintel_risk(abuse: dict, criminal: dict, leakix: dict, ports: dict) -> dict:
    """Risk scoring (0-100)."""
    score = 0
    reasons = []
    if abuse.get("abuseConfidenceScore", 0) > 70:
        score += 40; reasons.append(f"High abuse score ({abuse['abuseConfidenceScore']})")
    elif abuse.get("abuseConfidenceScore", 0) > 40:
        score += 20; reasons.append(f"Moderate abuse score ({abuse['abuseConfidenceScore']})")
    if criminal.get("score", 0) > 70:
        score += 30; reasons.append(f"CriminalIP: {criminal.get('classification','high')}")
    elif criminal.get("score", 0) > 40:
        score += 15; reasons.append(f"CriminalIP: {criminal.get('classification','moderate')}")
    if leakix.get("exposed"):
        score += 30; reasons.append("LeakIX: exposed services detected")
    if 23 in ports.get("open_ports", []):
        score += 20; reasons.append("Telnet (23) exposed")
    if 7547 in ports.get("open_ports", []):
        score += 10; reasons.append("CWMP (7547) exposed")
    score = min(score, 100)
    if score <= 30:   level = "LOW"
    elif score <= 70: level = "MEDIUM"
    else:             level = "HIGH"
    return {"risk_score": score, "risk_level": level, "reasons": reasons}

@app.route("/api/ip-intel")
@rate_limit("10 per minute")
def api_ip_intel():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400
    if not _is_valid_public_ip(ip):
        return jsonify({"error": "Invalid or non-public IP"}), 400

    geo      = {"country":"", "city":"", "region":"", "org":"", "hostname":"", "lat":None, "lon":None}
    abuse    = {"abuseConfidenceScore":0, "totalReports":0, "available":False}
    criminal = {"score":0, "classification":"", "tags":[], "available":False}
    leakix   = {"exposed":False, "services":[], "available":False}
    zoomeye  = {"ports":[], "services":[], "available":False}
    portscan = {"open_ports":[], "findings":[]}

    # STB-02: CriminalIP retry'ları 15 sn'yi aşabilir → zaman aşımında kısmi sonuç dön
    pool = ThreadPoolExecutor(max_workers=6)
    try:
        futs = {
            pool.submit(_ipintel_geo, ip):         "geo",
            pool.submit(_ipintel_abuse, ip):       "abuse",
            pool.submit(_ipintel_criminalip, ip):  "criminal",
            pool.submit(_ipintel_leakix, ip):      "leakix",
            pool.submit(_ipintel_zoomeye, ip):     "zoomeye",
            pool.submit(_ipintel_portscan, ip):    "portscan",
        }
        got = gather_futures(futs, 18, "ip-intel")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    geo      = got.get("geo")      or geo
    abuse    = got.get("abuse")    or abuse
    criminal = got.get("criminal") or criminal
    leakix   = got.get("leakix")   or leakix
    zoomeye  = got.get("zoomeye")  or zoomeye
    portscan = got.get("portscan") or portscan

    # Merge ZoomEye ports into final port list
    merged_ports = sorted(set(portscan["open_ports"]) | set(zoomeye.get("ports", [])))
    findings = list(portscan["findings"])
    for p in zoomeye.get("ports", []):
        if p in _PORT_FINDINGS and _PORT_FINDINGS[p] not in findings:
            findings.append(_PORT_FINDINGS[p])

    merged_ports_block = {"open_ports": merged_ports, "findings": findings}
    risk = _ipintel_risk(abuse, criminal, leakix, merged_ports_block)

    return jsonify({
        "ip":       ip,
        "geo":      geo,
        "abuse":    abuse,
        "criminal": criminal,
        "leakix":   leakix,
        "zoomeye":  zoomeye,
        "ports":    merged_ports,
        "findings": findings,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_reasons": risk["reasons"],
        "sources": {
            "ipinfo":     True,
            "abuseipdb":  abuse.get("available", False),
            "criminalip": criminal.get("available", False),
            "leakix":     leakix.get("available", False),
            "zoomeye":    zoomeye.get("available", False),
        }
    })

@app.route("/api/mccmnc-lookup")
def mccmnc_lookup():
    mcc = request.args.get("mcc", "").strip()
    mnc = request.args.get("mnc", "").strip()
    if not mcc or not mnc: return jsonify({}), 400
    if not (mcc.isdigit() and mnc.isdigit() and len(mcc) == 3 and 1 <= len(mnc) <= 3):
        return jsonify({"error": "MCC must be 3 digits, MNC 1-3 digits"}), 400
    # Önce offline DB (resolve_op'un belgelenmiş önceliği)
    for mv in (mnc, mnc.zfill(2), mnc.zfill(3), mnc.lstrip("0") or "0"):
        hit = _MCC_MNC_DB.get(f"{mcc}:{mv}")
        if hit:
            return jsonify({"operator": hit[0], "mcc": mcc, "mnc": mnc,
                            "country": hit[2], "country_code": hit[1], "type": "", "source": "offline"})
    try:
        r = requests.get(f"https://mcc-mnc.net/api/v1/mccmnc/{mcc}/{mnc}", timeout=3)
        if r.status_code == 200:
            d = r.json()
            return jsonify({
                "operator": d.get("operator") or d.get("network"),
                "mcc": mcc, "mnc": mnc,
                "country": d.get("country_name", ""),
                "country_code": d.get("iso2", ""),
                "type": d.get("type", "")
            })
    except Exception: pass
    op = resolve_op(mcc, mnc)
    iso, cname = resolve_country(mcc, mnc)
    return jsonify({"operator": op, "mcc": mcc, "mnc": mnc, "country": cname or "",
                    "country_code": iso or "", "type": ""})


# ══════════════════════════════════════════════
#  DATA LAYER ENDPOINTS
# ══════════════════════════════════════════════
@app.route("/api/osm-cameras")
def api_osm_cameras():
    bb = parse_bbox()
    if not bb:
        return jsonify({"error": "Invalid bbox parameters (lat1, lon1, lat2, lon2 required)"}), 400
    lat1, lon1, lat2, lon2 = bb
    limit = arg_int("limit", 500, 1, 1000)

    features = []
    sources_used = []
    seen_coords = set()   # dedup key: rounded (lat, lon)

    # ── Source 1: Local static dataset (CAMERAS_WITH_NETWORK_DATA.geojson) ──
    # Instant grid-indexed lookup, ~178k cameras worldwide.
    if _STATIC["cameras"]:
        try:
            local = _cameras_in_bbox(lat1, lon1, lat2, lon2, limit=limit)
            for feat in local:
                coords = feat["geometry"]["coordinates"]
                key = (round(coords[1], 5), round(coords[0], 5))
                if key in seen_coords:
                    continue
                seen_coords.add(key)
                # Normalize properties — same schema as OSM output
                props = feat.get("properties", {}) or {}
                features.append({
                    "type": "Feature",
                    "geometry": feat["geometry"],
                    "properties": {
                        "id":                 props.get("id") or props.get("@id") or f"local_{len(features)}",
                        "name":               props.get("name", ""),
                        "operator":           props.get("operator", props.get("owner", "")),
                        "camera:type":        props.get("camera:type", ""),
                        "surveillance:type":  props.get("surveillance:type", props.get("surveillance", "")),
                        "surveillance:zone":  props.get("surveillance:zone", ""),
                        "camera:mount":       props.get("camera:mount", ""),
                        "direction":          props.get("camera:direction", props.get("direction", "")),
                        "website":            props.get("website", props.get("contact:website", "")),
                        "source":             props.get("source", "static"),
                        "_src":               "static",
                    }
                })
            sources_used.append(f"static:{len(local)}")
        except Exception as e:
            print(f"[osm-cameras] static lookup error: {e}")

    # ── Source 2: OSM Overpass live query (complements static with fresh data) ──
    # Skip if we already have a lot of local results (saves a slow Overpass round-trip).
    clipped = False
    if len(features) < limit:
        # Görünen alan (bbox) — eskiden merkezin 5 km çevresi sorgulanıyordu
        bb_q, clipped = overpass_bbox(lat1, lon1, lat2, lon2)
        remaining = limit - len(features)
        query = f"""
[out:json][timeout:25][bbox:{bb_q}];
(
  node["man_made"="surveillance"];
  node["surveillance:type"="camera"];
  node["surveillance"];
);
out body {remaining};
"""
        try:
            elements, err = overpass_query(query)
            if elements is not None:
                added = 0
                for el in elements:
                    lat = sf(el.get("lat")); lon = sf(el.get("lon"))
                    if not lat or not lon: continue
                    key = (round(lat, 5), round(lon, 5))
                    if key in seen_coords:
                        continue
                    seen_coords.add(key)
                    tags = el.get("tags", {})
                    features.append({
                        "type": "Feature",
                        "geometry": {"type": "Point", "coordinates": [lon, lat]},
                        "properties": {
                            "id": el.get("id"), "name": tags.get("name", ""),
                            "operator": tags.get("operator", tags.get("owner", "")),
                            "camera:type": tags.get("camera:type", ""),
                            "surveillance:type": tags.get("surveillance:type", tags.get("surveillance", "")),
                            "surveillance:zone": tags.get("surveillance:zone", ""),
                            "camera:mount": tags.get("camera:mount", ""),
                            "direction": tags.get("camera:direction", tags.get("direction", "")),
                            "website": tags.get("website", tags.get("contact:website", "")),
                            "source": "osm",
                            "_src": "osm",
                        }
                    })
                    added += 1
                    if len(features) >= limit:
                        break
                sources_used.append(f"osm:{added}")
            else:
                sources_used.append(f"osm_err:{err}")
        except Exception as e:
            sources_used.append(f"osm_err:{str(e)[:40]}")

    return jsonify({
        "type": "FeatureCollection",
        "features": features,
        "total": len(features),
        "sources": sources_used,
        "clipped": clipped,     # True → canlı OSM verisi sadece görünen alanın merkezinden
        "limited": len(features) >= limit,
    })

@app.route("/api/alpr-cameras")
@rate_limit("10 per minute")
def api_alpr_cameras():
    bb = parse_bbox()
    if not bb:
        return jsonify({"features": [], "error": "Invalid bbox"}), 400
    lat1, lon1, lat2, lon2 = bb

    clat = (lat1+lat2)/2; clon = (lon1+lon2)/2
    features = []
    bb_q, clipped = overpass_bbox(lat1, lon1, lat2, lon2)

    osm_query = f"""
[out:json][timeout:25][bbox:{bb_q}];
(
  node["camera:type"="ALPR"];
  node["camera:type"="alpr"];
  node["surveillance:zone"="traffic"];
  node["highway"="speed_camera"];
  node["enforcement"="speed"];
  node["enforcement"="access_control"];
  node["surveillance"="ALPR"];
);
out body 300;
"""
    try:
        elements, _err = overpass_query(osm_query)
        if elements is not None:
            for el in elements:
                lat = sf(el.get("lat")); lon = sf(el.get("lon"))
                if not lat or not lon: continue
                tags = el.get("tags", {})
                features.append({
                    "type": "Feature",
                    "geometry": {"type": "Point", "coordinates": [lon, lat]},
                    "properties": {
                        "id": f"osm:{el.get('id')}", "source": "osm",
                        "camera_type": tags.get("camera:type", "ALPR").upper(),
                        "zone": tags.get("surveillance:zone", tags.get("enforcement", "traffic")),
                        "operator": tags.get("operator", tags.get("owner", "")),
                        "ref": tags.get("ref", tags.get("name", "")),
                        "direction": tags.get("camera:direction", tags.get("direction", "")),
                        "maxspeed": tags.get("maxspeed", ""), "highway": tags.get("highway", ""),
                    }
                })
    except Exception as e: print(f"[ALPR OSM] {e}")

    if SHODAN_KEY and not _hblocked("Shodan"):
        country = get_country_iso(clat, clon); cf = f" country:{country}" if country else ""
        for q in [f'product:"Genetec"{cf}', f'product:"Milestone"{cf}', f'product:"Axis"{cf} port:80',
                  f'http.title:"ALPR"{cf}', f'http.title:"License Plate"{cf}',
                  f'product:"Verkada"{cf}', f'product:"Avigilon"{cf}']:
            if _hblocked("Shodan"): break      # kota/yetki hatası → kalan sorgular atlanır
            try:
                r = requests.get("https://api.shodan.io/shodan/host/search",
                    params={"key": SHODAN_KEY, "query": q, "limit": 10}, timeout=T)
                if r.status_code == 200:
                    for h in r.json().get("matches", []):
                        loc = h.get("location", {})
                        rlat = sf(loc.get("latitude")); rlon = sf(loc.get("longitude"))
                        if not rlat or not rlon: continue
                        features.append({
                            "type": "Feature",
                            "geometry": {"type": "Point", "coordinates": [rlon, rlat]},
                            "properties": {
                                "id": f"shodan:{h.get('ip_str')}:{h.get('port')}",
                                "source": "shodan", "camera_type": "ALPR",
                                "ip": h.get("ip_str"), "port": h.get("port"),
                                "product": h.get("product", ""), "org": h.get("org", ""),
                                "isp": h.get("isp", ""), "country": loc.get("country_name", ""),
                                "city": loc.get("city", ""), "banner": (h.get("data") or "")[:80],
                            }
                        })
                elif r.status_code == 429: break
            except Exception as e: print(f"[ALPR Shodan] {e}")

    seen, deduped = set(), []
    for f in features:
        fid = f["properties"]["id"]
        if fid not in seen:
            seen.add(fid); deduped.append(f)

    return jsonify({
        "type": "FeatureCollection", "features": deduped, "total": len(deduped),
        "sources": list(set(f["properties"]["source"] for f in deduped)),
        "clipped": clipped,
    })

@app.route("/api/precincts")
def api_precincts():
    bb = parse_bbox()
    if not bb:
        return jsonify({"features": [], "error": "Invalid bbox"}), 400
    lat1, lon1, lat2, lon2 = bb

    features = []
    sources_used = []

    # ── Source 1: Local precinct polygons (police_precincts_usa.geojson) ──
    # Real polygon boundaries — much richer than OSM point data.
    if _STATIC["precincts"]:
        try:
            local_polys = _precincts_in_bbox(lat1, lon1, lat2, lon2, limit=200)
            for feat in local_polys:
                props = feat.get("properties", {}) or {}
                features.append({
                    "type": "Feature",
                    "geometry": feat.get("geometry"),
                    "properties": {
                        "ID":          props.get("ID") or props.get("OBJECTID"),
                        "DISTRICT":    props.get("DISTRICT") or props.get("ID") or props.get("name", "?"),
                        "city":        props.get("city", ""),
                        "name":        props.get("name", props.get("DISTRICT", "Police Precinct")),
                        "operator":    props.get("operator", ""),
                        "phone":       props.get("phone", ""),
                        "source_file": props.get("source_file", "static_polygon"),
                        "_src":        "static",
                    }
                })
            sources_used.append(f"static_polygons:{len(local_polys)}")
        except Exception as e:
            print(f"[precincts] static lookup error: {e}")

    # ── Source 2: OSM Overpass live query — adds point-based police stations ──
    # Useful outside the US where we don't have polygon data.
    bb_q, clipped = overpass_bbox(lat1, lon1, lat2, lon2)
    query = f"""
[out:json][timeout:20][bbox:{bb_q}];
(
  node["amenity"="police"];
  way["amenity"="police"];
);
out body center 100;
"""
    try:
        elements, err = overpass_query(query, timeout=25)
        if elements is not None:
            added = 0
            for el in elements:
                tags = el.get("tags", {})
                if el.get("type") == "node":
                    lat = sf(el.get("lat")); lon = sf(el.get("lon"))
                else:
                    center = el.get("center", {})
                    lat = sf(center.get("lat")); lon = sf(center.get("lon"))
                if not lat or not lon: continue
                features.append({
                    "type": "Feature",
                    "geometry": {"type": "Point", "coordinates": [lon, lat]},
                    "properties": {
                        "ID": el.get("id"),
                        "DISTRICT": tags.get("ref", tags.get("name", "?")),
                        "city": tags.get("addr:city", tags.get("addr:town", "")),
                        "name": tags.get("name", "Police Station"),
                        "operator": tags.get("operator", ""),
                        "phone": tags.get("phone", tags.get("contact:phone", "")),
                        "source_file": "osm",
                        "_src": "osm",
                    }
                })
                added += 1
            sources_used.append(f"osm:{added}")
        else:
            sources_used.append(f"osm_err:{err}")
    except Exception as e:
        sources_used.append(f"osm_err:{str(e)[:40]}")

    return jsonify({
        "type": "FeatureCollection",
        "features": features,
        "total": len(features),
        "sources": sources_used,
        "clipped": clipped,
    })

@app.route("/api/flock-networks")
def api_flock_networks():
    """
    ALPR / Flock Safety camera network detection.

    Returns Automated License Plate Reader (ALPR) cameras — including Flock Safety,
    Motorola Vigilant, Rekor, Genetec deployments — based on OSM surveillance tagging
    (DeFlock convention: surveillance:type=ALPR, camera:type=alpr) plus
    manufacturer/operator hints.

    Data sources (merged, deduped):
      1. Local static datasets (CAMERAS_WITH_NETWORK_DATA + tile cache) — ~46k ALPR nodes globally
      2. OSM Overpass API live query — fresh community-contributed data
    """
    bb = parse_bbox()
    if not bb:
        return jsonify({"features": [], "error": "Invalid bbox"}), 400
    lat1, lon1, lat2, lon2 = bb
    limit = arg_int("limit", 500, 1, 1000)

    features = []
    sources_used = []
    seen_coords = set()

    def _alpr_props_from_tags(tags):
        """Normalize OSM/static tags into a consistent ALPR properties dict."""
        return {
            "name":              tags.get("name", ""),
            "manufacturer":      tags.get("manufacturer", tags.get("brand", "")),
            "operator":          tags.get("operator", tags.get("owner", "")),
            "surveillance:type": tags.get("surveillance:type", tags.get("surveillance", "")),
            "camera:type":       tags.get("camera:type", ""),
            "surveillance:zone": tags.get("surveillance:zone", ""),
            "direction":         tags.get("camera:direction", tags.get("direction", "")),
            "camera:mount":      tags.get("camera:mount", ""),
            "highway":           tags.get("highway", ""),
            "is_flock":          "flock" in str(tags.get("manufacturer", "")).lower()
                               or "flock" in str(tags.get("operator", "")).lower(),
        }

    # ── Source 1: Local static dataset (ALPR-filtered) ──
    if _STATIC["cameras"]:
        try:
            local = _alpr_cameras_in_bbox(lat1, lon1, lat2, lon2, limit=limit)
            for feat in local:
                coords = feat["geometry"]["coordinates"]
                key = (round(coords[1], 5), round(coords[0], 5))
                if key in seen_coords:
                    continue
                seen_coords.add(key)
                props = feat.get("properties", {}) or {}
                out_props = _alpr_props_from_tags(props)
                out_props["id"]   = props.get("id") or props.get("@id") or f"local_{len(features)}"
                out_props["_src"] = "static"
                features.append({
                    "type": "Feature",
                    "geometry": feat["geometry"],
                    "properties": out_props,
                })
            sources_used.append(f"static:{len(local)}")
        except Exception as e:
            print(f"[flock-networks] static lookup error: {e}")

    # ── Source 2: OSM Overpass live query (ALPR-specific tags) ──
    clipped = False
    if len(features) < limit:
        bb_q, clipped = overpass_bbox(lat1, lon1, lat2, lon2)
        remaining = limit - len(features)
        query = f"""
[out:json][timeout:25][bbox:{bb_q}];
(
  node["surveillance:type"="ALPR"];
  node["camera:type"="ALPR"];
  node["camera:type"="alpr"];
  node["manufacturer"="Flock Safety"];
  node["operator"~"[Ff]lock"];
);
out body {remaining};
"""
        try:
            elements, err = overpass_query(query, ua="SignalOps/2.1 (surveillance-research)")
            if elements is not None:
                added = 0
                for el in elements:
                    elat = sf(el.get("lat")); elon = sf(el.get("lon"))
                    if not elat or not elon: continue
                    key = (round(elat, 5), round(elon, 5))
                    if key in seen_coords:
                        continue
                    seen_coords.add(key)
                    tags = el.get("tags", {})
                    out_props = _alpr_props_from_tags(tags)
                    out_props["id"]   = el.get("id")
                    out_props["_src"] = "osm"
                    features.append({
                        "type": "Feature",
                        "geometry": {"type": "Point", "coordinates": [elon, elat]},
                        "properties": out_props,
                    })
                    added += 1
                    if len(features) >= limit:
                        break
                sources_used.append(f"osm:{added}")
            else:
                sources_used.append(f"osm_err:{err}")
        except Exception as e:
            sources_used.append(f"osm_err:{str(e)[:40]}")

    return jsonify({
        "type": "FeatureCollection",
        "features": features,
        "total": len(features),
        "sources": sources_used,
        "clipped": clipped,
        "limited": len(features) >= limit,
    })

# ══════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════
# ══════════════════════════════════════════════
#  WATCHLIST — app_v2.py'nin EN ALTINA ekle
#  (ENTRY POINT'tan önce)
# ══════════════════════════════════════════════
import uuid

# STB-04: çalışma dizininden bağımsız mutlak yol (WATCHLIST_DIR ile değiştirilebilir)
_WL_DIR          = _paths.watchlist_dir()
_watchlist_file  = os.path.join(_WL_DIR, "watchlist.json")
_alerts_file     = os.path.join(_WL_DIR, "watchlist_alerts.json")
_watchlist_lock  = threading.Lock()
_alerts_lock     = threading.Lock()
_MAX_ALERTS      = 5000

class _CorruptJSON(Exception):
    pass

# ── JSON Helpers ──────────────────────────────

def _load_json(path, strict=False):
    """Dosya yoksa []. Bozuksa: strict=False → [] (okuma), strict=True → hata
    (yazmadan önce okuma — bozuk dosyanın üzerine [] yazıp veriyi silmemek için)."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("root is not a list")
        return [d for d in data if isinstance(d, dict)]
    except Exception as e:
        print(f"[Watchlist] Corrupt JSON {path}: {e}")
        if strict:
            raise _CorruptJSON(path)
        return []

def _save_json(path, data):
    """Atomik yazım: geçici dosya + os.replace — yarıda kalan yazım dosyayı bozmaz."""
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".wl-", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception as e:
        print(f"[Watchlist] Save error {path}: {e}")
        try: os.unlink(tmp)
        except OSError: pass
        raise

def _corrupt_response(path):
    return jsonify({"ok": False, "error": f"{os.path.basename(path)} is corrupt — fix or remove it; nothing was overwritten"}), 500

# ── Watchlist CRUD ────────────────────────────

@app.route("/api/watchlist", methods=["GET"])
def wl_get():
    with _watchlist_lock:
        entries = _load_json(_watchlist_file)
    return jsonify({"entries": entries, "count": len(entries)})

@app.route("/api/watchlist", methods=["POST"])
def wl_add():
    body = request.get_json(silent=True) or {}
    value = (body.get("value") or "").strip()
    typ   = (body.get("type")  or "").strip().lower()
    if not value or typ not in ("bssid","ssid","ip","mac","icao"):
        return jsonify({"ok": False, "error": "Invalid type or empty value"}), 400

    value = value[:128]
    if typ == "ip":
        try: value = str(ipaddress.ip_address(value))
        except ValueError: return jsonify({"ok": False, "error": "Invalid IP"}), 400
    if typ in ("bssid", "mac") and not _MAC_RE.match(value):
        return jsonify({"ok": False, "error": "Invalid MAC/BSSID"}), 400
    if typ == "icao" and not re.match(r"^~?[0-9A-Fa-f]{6}$", value):
        return jsonify({"ok": False, "error": "ICAO hex must be 6 hex chars"}), 400
    priority = str(body.get("priority") or "medium").lower()
    if priority not in ("low", "medium", "high", "critical"):
        priority = "medium"
    notify = str(body.get("notify") or "browser").lower()
    if notify not in ("browser", "badge"):
        notify = "browser"

    entry = {
        "id":        str(uuid.uuid4())[:8],
        "type":      typ,
        "value":     value.upper() if typ in ("bssid","mac","icao") else value,
        "note":      str(body.get("note") or "").strip()[:120],
        "priority":  priority,
        "notify":    notify,
        "hit_count": 0,
        "created_at": int(time.time())
    }

    with _watchlist_lock:
        try:
            entries = _load_json(_watchlist_file, strict=True)
        except _CorruptJSON:
            return _corrupt_response(_watchlist_file)
        # Duplicate check
        for e in entries:
            if e.get("type") == entry["type"] and e.get("value") == entry["value"]:
                return jsonify({"ok": False, "error": "Already in watchlist"}), 409
        entries.append(entry)
        try: _save_json(_watchlist_file, entries)
        except Exception: return jsonify({"ok": False, "error": "Save failed"}), 500

    return jsonify({"ok": True, "entry": entry})

@app.route("/api/watchlist/<entry_id>", methods=["DELETE"])
def wl_delete(entry_id):
    with _watchlist_lock:
        try:
            entries = _load_json(_watchlist_file, strict=True)
        except _CorruptJSON:
            return _corrupt_response(_watchlist_file)
        entries = [e for e in entries if e.get("id") != entry_id]
        try: _save_json(_watchlist_file, entries)
        except Exception: return jsonify({"ok": False, "error": "Save failed"}), 500
    return jsonify({"ok": True})

# ── Alerts ────────────────────────────────────

@app.route("/api/watchlist/alerts", methods=["GET"])
def wl_alerts_get():
    with _alerts_lock:
        alerts = _load_json(_alerts_file)
    unread = [a for a in alerts if not a.get("read")]
    last_hit = max((a.get("ts") or 0 for a in alerts), default=None) or None
    return jsonify({
        "alerts":   alerts[-100:][::-1],  # son 100, yeniden eskiye
        "total":    len(alerts),
        "unread":   len(unread),
        "last_hit": last_hit
    })

@app.route("/api/watchlist/alerts", methods=["DELETE"])
def wl_alerts_clear():
    with _alerts_lock:
        try: _save_json(_alerts_file, [])
        except Exception: return jsonify({"ok": False, "error": "Save failed"}), 500
    return jsonify({"ok": True})

@app.route("/api/watchlist/alerts/read", methods=["POST"])
def wl_alerts_mark_read():
    """Tüm alarmları okundu işaretle (unread sayacı sıfırlanır)."""
    with _alerts_lock:
        try:
            alerts = _load_json(_alerts_file, strict=True)
        except _CorruptJSON:
            return _corrupt_response(_alerts_file)
        changed = 0
        for a in alerts:
            if not a.get("read"):
                a["read"] = True; changed += 1
        if changed:
            try: _save_json(_alerts_file, alerts)
            except Exception: return jsonify({"ok": False, "error": "Save failed"}), 500
    return jsonify({"ok": True, "marked": changed})

# ── Check endpoint (Surveillance doScan çağırır) ──

@app.route("/api/watchlist/check", methods=["POST"])
def wl_check():
    """
    Surveillance'dan gelen device listesini watchlist ile karşılaştırır.
    Body: { "devices": [...], "scan_source": "surveillance" }
    Return: { "hits": [...] }
    """
    body    = request.get_json(silent=True) or {}
    if not isinstance(body, dict): body = {}
    devices = body.get("devices", [])
    if not isinstance(devices, list): devices = []
    source  = str(body.get("scan_source", "scan"))[:40]
    hits = watchlist_match(devices, source)
    return jsonify({"hits": hits, "count": len(hits)})

def watchlist_match(devices, source="scan"):
    """Cihaz listesini watchlist ile eşleştirir, alarmları kaydeder. Döner: hits listesi.
    (/api/watchlist/check ve alan izleme modülü kullanır)"""
    devices = [d for d in (devices or []) if isinstance(d, dict)][:10000]
    if not devices:
        return []

    with _watchlist_lock:
        watchlist = _load_json(_watchlist_file)

    if not watchlist:
        return []

    hits = []
    now  = int(time.time())

    for entry in watchlist:
        etype = entry.get("type")
        eval_ = str(entry.get("value") or "").upper()
        if not etype or not eval_:
            continue

        for dev in devices:
            matched = False

            if etype == "bssid" and (dev.get("bssid") or "").upper() == eval_:
                matched = True
            elif etype == "ssid"  and (dev.get("ssid")  or "").upper() == eval_.upper():
                matched = True
            elif etype == "ip"    and (dev.get("ip")    or "") == entry.get("value"):
                matched = True
            elif etype == "mac"   and (dev.get("bssid") or dev.get("mac") or "").upper() == eval_:
                matched = True
            elif etype == "icao"  and (dev.get("icao")  or dev.get("hex") or "").upper() == eval_:
                matched = True

            if matched:
                hits.append({
                    "entry_id":    entry.get("id"),
                    "type":        etype,
                    "value":       entry.get("value"),
                    "note":        entry.get("note",""),
                    "priority":    entry.get("priority","medium"),
                    "notify":      entry.get("notify","browser"),
                    "device":      dev,
                    "scan_source": source,
                    "ts":          now,
                    "read":        False
                })
                break  # aynı entry için tek alert yeterli

    if hits:
        # Alert kaydet
        try:
            with _alerts_lock:
                alerts = _load_json(_alerts_file, strict=True)
                alerts.extend(hits)
                _save_json(_alerts_file, alerts[-_MAX_ALERTS:])

            # Watchlist hit_count güncelle
            hit_ids = {h["entry_id"] for h in hits}
            with _watchlist_lock:
                watchlist = _load_json(_watchlist_file, strict=True)
                for e in watchlist:
                    if e.get("id") in hit_ids:
                        e["hit_count"] = e.get("hit_count", 0) + 1
                _save_json(_watchlist_file, watchlist)
        except Exception as e:
            print(f"[Watchlist] could not persist hits: {e}")

    return hits

# ══════════════════════════════════════════════
#  SETTINGS — arayüzden API anahtarı yönetimi
# ══════════════════════════════════════════════
def _mask(v):
    v = str(v or "")
    if not v: return ""
    if len(v) <= 6: return "•" * len(v)
    return "•" * min(12, len(v) - 4) + v[-4:]

@app.route("/api/settings/keys", methods=["GET"])
def settings_keys_get():
    eff = _effective_keys()
    groups, order = {}, []
    try:
        hsnap = _health.snapshot() if _health else {}
    except Exception:
        hsnap = {}
    for env_name, _g, label, group, provider, secret, url in KEY_SCHEMA:
        val, src = eff[env_name]
        if group not in groups:
            groups[group] = []; order.append(group)
        hlabel = _health.ID_TO_LABEL.get(provider) if _health else None
        h = hsnap.get(hlabel) if hlabel else None
        groups[group].append({
            "id": env_name, "label": label, "provider": provider, "secret": secret,
            "configured": bool(val) and src != "default",
            "source": src,                                   # ui | env | default | None
            "display": (_mask(val) if secret else val) if val else "",
            "help_url": url,
            "testable": provider in _KEY_TESTS,
            # sağlayıcı sağlığı (kota/yetki/cooldown) — sorun yoksa None
            "health": ({"provider": hlabel, "state": h["state"], "reason": h["reason"], "until": h["until"]}
                       if h and h["state"] != "ok" else None),
        })
    return jsonify({
        "groups": [{"name": g, "keys": groups[g]} for g in order],
        "config_path": KEYS_FILE,
        "env_file": _paths.ENV_FILE,
    })

@app.route("/api/settings/keys", methods=["POST"])
@rate_limit("30 per minute")
def settings_keys_set():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("values"), dict):
        return jsonify({"ok": False, "error": "JSON body {values:{KEY: value|null}} required"}), 400
    with _keys_lock:
        ui = _load_ui_keys()
        changed = []
        for k, v in body["values"].items():
            if k not in _KEY_IDS:
                return jsonify({"ok": False, "error": f"Unknown key: {k}"}), 400
            if v is None or (isinstance(v, str) and not v.strip()):
                if k in ui:
                    ui.pop(k); changed.append(k)
                continue
            if not isinstance(v, str):
                return jsonify({"ok": False, "error": f"{k}: value must be a string"}), 400
            v = v.strip()
            if len(v) > 512 or any(c in v for c in "\r\n\x00"):
                return jsonify({"ok": False, "error": f"{k}: invalid value"}), 400
            if k == "GEMINI_MODEL" and not re.match(r"^[A-Za-z0-9._\-]{2,80}$", v):
                return jsonify({"ok": False, "error": "Invalid model name"}), 400
            if ui.get(k) != v:
                ui[k] = v; changed.append(k)
        try:
            _save_ui_keys(ui)
        except Exception as e:
            print(f"[settings] save failed: {e}")
            return jsonify({"ok": False, "error": "Could not write config file"}), 500
    _apply_keys()
    if _health is not None and changed:      # anahtar değişti → o sağlayıcının engeli kalkar
        _health.reset_provider_ids(p for e, _g, _l, _gr, p, *_ in KEY_SCHEMA if e in changed)
    print(f"[settings] updated: {', '.join(changed) or '(no change)'}")
    return jsonify({"ok": True, "changed": changed})

# ── Bağlantı testleri (hafif, kota dostu uç noktalar) ──
def _t_wigle():
    r = requests.get("https://api.wigle.net/api/v2/profile/user", auth=(WIGLE_USER, WIGLE_TOKEN), timeout=8)
    if r.status_code == 200:
        return True, f"OK — user {r.json().get('userid') or WIGLE_USER}"
    return False, f"HTTP {r.status_code}"

def _t_shodan():
    r = requests.get("https://api.shodan.io/api-info", params={"key": SHODAN_KEY}, timeout=8)
    if r.status_code == 200:
        j = r.json()
        return True, f"OK — plan {j.get('plan','?')}, query credits {j.get('query_credits','?')}"
    return False, f"HTTP {r.status_code}"

def _t_gemini():
    r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                     params={"key": GEMINI_KEY, "pageSize": 50}, timeout=8)
    if r.status_code == 200:
        names = [m.get("name", "").split("/")[-1] for m in r.json().get("models", [])]
        note = "" if not names or GEMINI_MODEL in names else f" (uyarı: '{GEMINI_MODEL}' listede yok)"
        return True, f"OK — {len(names)} model{note}"
    return False, f"HTTP {r.status_code}"

def _t_censys():
    r = requests.get("https://search.censys.io/api/v1/account", auth=(CENSYS_ID, CENSYS_SECRET), timeout=8)
    if r.status_code == 200:
        q = (r.json().get("quota") or {})
        return True, f"OK — quota {q.get('used','?')}/{q.get('allowance','?')}"
    return False, f"HTTP {r.status_code}"

def _t_fofa():
    r = requests.get("https://fofa.info/api/v1/info/my", params={"email": FOFA_EMAIL, "key": FOFA_KEY}, timeout=8)
    j = r.json() if r.status_code == 200 else {}
    if r.status_code == 200 and not j.get("error"):
        return True, f"OK — {j.get('username') or FOFA_EMAIL}"
    return False, str(j.get("errmsg") or f"HTTP {r.status_code}")[:120]

def _t_abuseipdb():
    r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": "127.0.0.1"},
                     headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}, timeout=8)
    return (True, "OK") if r.status_code == 200 else (False, f"HTTP {r.status_code}")

def _t_windy():
    r = requests.get("https://api.windy.com/webcams/api/v3/webcams", params={"limit": 1},
                     headers={"x-windy-api-key": WINDY_KEY}, timeout=8)
    return (True, "OK") if r.status_code == 200 else (False, f"HTTP {r.status_code}")

def _t_aprs():
    r = requests.get("https://api.aprs.fi/api/get",
                     params={"name": "OH7RDA", "what": "loc", "apikey": APRS_FI_KEY, "format": "json"},
                     headers={"User-Agent": "SignalOps/2.1"}, timeout=8)
    j = r.json() if r.status_code == 200 else {}
    if j.get("result") == "ok":
        return True, "OK"
    return False, str(j.get("description") or f"HTTP {r.status_code}")[:120]

def _t_opencellid():
    r = requests.get("https://opencellid.org/cell/getInArea",
                     params={"key": OPENCELLID_KEY, "BBOX": "41.000,28.970,41.005,28.975", "format": "json", "limit": 1},
                     timeout=8)
    j = {}
    try: j = r.json()
    except Exception: pass
    if r.status_code == 200 and not j.get("error"):
        return True, "OK"
    return False, str(j.get("error") or f"HTTP {r.status_code}")[:120]

# provider → (gerekli global'ler, test fonksiyonu)
_KEY_TESTS = {
    "wigle":      (("WIGLE_USER", "WIGLE_TOKEN"), _t_wigle),
    "shodan":     (("SHODAN_KEY",), _t_shodan),
    "gemini":     (("GEMINI_KEY",), _t_gemini),
    "censys":     (("CENSYS_ID", "CENSYS_SECRET"), _t_censys),
    "fofa":       (("FOFA_EMAIL", "FOFA_KEY"), _t_fofa),
    "abuseipdb":  (("ABUSEIPDB_KEY",), _t_abuseipdb),
    "windy":      (("WINDY_KEY",), _t_windy),
    "aprs":       (("APRS_FI_KEY",), _t_aprs),
    "opencellid": (("OPENCELLID_KEY",), _t_opencellid),
}

@app.route("/api/settings/test", methods=["POST"])
@rate_limit("20 per minute")
def settings_test():
    body = request.get_json(silent=True) or {}
    prov = str(body.get("provider") or "")
    if prov not in _KEY_TESTS:
        return jsonify({"ok": False, "message": "Bu sağlayıcı için test yok — kaydedildi, ilk taramada denenecek"}), 400
    needed, fn = _KEY_TESTS[prov]
    if not all(globals().get(n) for n in needed):
        return jsonify({"ok": False, "message": "Anahtar eksik — önce kaydet"})
    try:
        if _health is not None:
            with _health.probe():              # test, sağlayıcı engelliyken de gerçekten denenir
                ok, msg = fn()
        else:
            ok, msg = fn()
    except requests.RequestException as e:
        ok, msg = False, f"Bağlantı hatası: {type(e).__name__}"
    except Exception as e:
        print(f"[settings/test/{prov}] {e}")
        ok, msg = False, "Beklenmeyen yanıt"
    return jsonify({"ok": ok, "message": msg})

# ── Watchlist page route ──────────────────────

@app.route("/watchlist")
def page_watchlist():
    return render_template("watchlist.html", active="Watchlist")

# ══════════════════════════════════════════════
#  ADS-B DEDICATED ENDPOINT + PAGE
# ══════════════════════════════════════════════
def _fetch_aircraft(lat, lon, radius):
    """adsb.fi + OpenSky paralel; zaman aşımında biten kaynakla devam (STB-02)."""
    aircraft = []
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        futs = {pool.submit(fetch_adsb, lat, lon, radius): "adsb_fi",
                pool.submit(fetch_opensky, lat, lon, radius): "opensky"}
        for res in gather_futures(futs, 18, "aircraft").values():
            if res: aircraft.extend(res)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return dedup_aircraft(aircraft)

@app.route("/api/adsb")
@rate_limit("60 per minute")
def api_adsb():
    lat, lon = validate_coords(request.args.get("lat"), request.args.get("lon"))
    if lat is None:
        return jsonify({"error": "Valid lat/lon required"}), 400
    radius = arg_int("radius", 100, 25, 460)  # km (adsb.fi max 250 NM ≈ 463 km)

    aircraft = _fetch_aircraft(lat, lon, radius)
    for ac in aircraft:
        ac["risk"] = score_aircraft(ac)

    drones      = [a for a in aircraft if a.get("type") == "drone"]
    emergencies = [a for a in aircraft if a.get("emergency")]
    by_country  = {}
    for a in aircraft:
        c = a.get("country") or "Unknown"
        by_country[c] = by_country.get(c, 0) + 1

    analysis = None
    risk_level = "CRITICAL" if emergencies else "HIGH" if len(drones) > 3 else "MEDIUM" if drones else "LOW"
    if GEMINI_KEY and (emergencies or len(drones) > 2) and _hblocked("Gemini"):
        analysis = _ai_unavailable()
    elif GEMINI_KEY and (emergencies or len(drones) > 2):
        try:
            from google import genai as gai
            client = gai.Client(api_key=GEMINI_KEY)
            summary = (f"ADS-B scan lat={lat:.4f} lon={lon:.4f}\n"
                f"Total: {len(aircraft)}, Drones: {len(drones)}, Emergencies: {len(emergencies)}\n")
            if emergencies:
                summary += "EMERGENCY:\n"
                for a in emergencies:
                    summary += f"  {a.get('callsign') or a.get('icao','?')} SQUAWK:{a.get('squawk')} {a.get('squawk_meaning','')}\n"
            if drones:
                summary += "DRONES:\n"
                for d in drones[:5]:
                    summary += f"  {d.get('callsign') or d.get('icao','?')} alt:{d.get('altitude','?')}ft\n"
            res = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=(
                    "You are SignalOps SIGINT AI. Analyze this ADS-B scan:\n\n" + summary +
                    "\n\n1. AIRSPACE ASSESSMENT\n2. THREATS\n3. RECOMMENDATIONS\n4. End with exactly one line: 'RISK LEVEL: <one of CRITICAL, HIGH, MEDIUM, LOW>'"),
                config={"system_instruction": "You are SignalOps SIGINT AI, expert in airspace intelligence and drone detection."})
            analysis = res.text
            fallback = "HIGH" if len(drones) > 3 else "MEDIUM" if drones else "LOW"
            risk_level = "CRITICAL" if emergencies else parse_risk_level(analysis, fallback)
        except Exception as e:
            print(f"[api/adsb gemini] {e}")
            analysis = _ai_unavailable(e)

    return jsonify({
        "aircraft": aircraft, "total": len(aircraft),
        "drones": len(drones), "emergencies": len(emergencies),
        "by_country": by_country, "risk_level": risk_level,
        "analysis": analysis,
        "sources": list(set(a.get("source", "") for a in aircraft)),
    })

@app.route("/adsb")
def page_adsb():
    return render_template("adsb.html", active="ADS-B")

# ══════════════════════════════════════════════
#  ORBITAL — CelesTrak TLE + SGP4 + SatNOGS + GPS Jamming
# ══════════════════════════════════════════════

# CelesTrak category URLs (active, no key needed)
CELESTRAK_SOURCES = {
    "gps":         "https://celestrak.org/NORAD/elements/gp.php?GROUP=gps-ops&FORMAT=tle",
    "glonass":     "https://celestrak.org/NORAD/elements/gp.php?GROUP=glo-ops&FORMAT=tle",
    "galileo":     "https://celestrak.org/NORAD/elements/gp.php?GROUP=galileo&FORMAT=tle",
    "beidou":      "https://celestrak.org/NORAD/elements/gp.php?GROUP=beidou&FORMAT=tle",
    "military":    "https://celestrak.org/NORAD/elements/gp.php?GROUP=military&FORMAT=tle",
    "intelsat":    "https://celestrak.org/NORAD/elements/gp.php?GROUP=intelsat&FORMAT=tle",
    "weather":     "https://celestrak.org/NORAD/elements/gp.php?GROUP=weather&FORMAT=tle",
    "noaa":        "https://celestrak.org/NORAD/elements/gp.php?GROUP=noaa&FORMAT=tle",
    "resource":    "https://celestrak.org/NORAD/elements/gp.php?GROUP=resource&FORMAT=tle",
    "sarsat":      "https://celestrak.org/NORAD/elements/gp.php?GROUP=sarsat&FORMAT=tle",
    "spacestation":"https://celestrak.org/NORAD/elements/gp.php?GROUP=stations&FORMAT=tle",
    "starlink":    "https://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle",
    "active":      "https://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=tle",
}

# Mission classification keywords (matched against satellite name)
MISSION_KEYWORDS = {
    "sigint":      ["NOSS", "INTRUDER", "TRUMPET", "MENTOR", "ORION", "MAGNUM", "VORTEX", "JUMPSEAT"],
    "isr":         ["LACROSSE", "ONYX", "TOPAZ", "KH-", "CRYSTAL", "FIA", "USA-"],
    "early_warning":["DSP", "SBIRS", "OPS "],
    "navigation":  ["GPS", "GLONASS", "GALILEO", "BEIDOU", "NAVSTAR", "IRNSS", "QZSS"],
    "weather":     ["NOAA", "METOP", "GOES", "HIMAWARI", "METEOR", "FENGYUN", "JPSS"],
    "comms":       ["INTELSAT", "IRIDIUM", "INMARSAT", "STARLINK", "ONEWEB", "GLOBALSTAR"],
    "imaging":     ["LANDSAT", "SENTINEL", "TERRA", "AQUA", "WORLDVIEW", "PLANET", "SPOT"],
    "sar":         ["RADARSAT", "TERRASAR", "COSMO", "ICEYE", "CAPELLA"],
    "station":     ["ISS", "TIANGONG", "CSS"],
    "sarsat":      ["SARSAT", "COSPAS"],
}

# Per-category mission hint (when name matching fails)
CATEGORY_MISSION = {
    "gps": "navigation", "glonass": "navigation", "galileo": "navigation", "beidou": "navigation",
    "military": "military", "intelsat": "comms", "weather": "weather", "noaa": "weather",
    "resource": "imaging", "sarsat": "sarsat", "spacestation": "station", "starlink": "comms",
}

_tle_cache = {"data": {}, "ts": 0}
_tle_lock = threading.Lock()
_TLE_TTL = 3600  # 1 hour
_TLE_RETRY = 120  # bir grup boş geldiyse 2 dk sonra tekrar dene

def classify_mission(name, category):
    """Classify satellite mission type by name, fallback to category hint."""
    nm = (name or "").upper()
    for mission, kws in MISSION_KEYWORDS.items():
        for k in kws:
            if k in nm:
                return mission
    return CATEGORY_MISSION.get(category, "other")

def fetch_tle_group(category, url):
    """Download and parse TLE group from CelesTrak."""
    try:
        r = requests.get(url, timeout=12)
        if r.status_code != 200:
            return []
        lines = [l.strip() for l in r.text.splitlines() if l.strip()]
        sats = []
        for i in range(0, len(lines) - 2, 3):
            name = lines[i]
            l1 = lines[i + 1]
            l2 = lines[i + 2]
            if l1.startswith("1 ") and l2.startswith("2 "):
                sats.append({"name": name, "line1": l1, "line2": l2, "category": category})
        return sats
    except Exception as e:
        print(f"[tle] {category}: {e}")
        return []

def get_all_tle(force_refresh=False):
    """Fetch all TLE groups with caching (STB-11: lock + boş grup cache'lenmez + kısmi sonuç)."""
    with _tle_lock:
        now = time.time()
        data = _tle_cache["data"]
        complete = data and all(data.get(c) for c in CELESTRAK_SOURCES)
        ttl = _TLE_TTL if complete else _TLE_RETRY
        if not force_refresh and data and (now - _tle_cache["ts"]) < ttl:
            return data
        result = dict(data) if data else {}
        pool = ThreadPoolExecutor(max_workers=6)
        try:
            futs = {pool.submit(fetch_tle_group, cat, url): cat for cat, url in CELESTRAK_SOURCES.items()}
            got = gather_futures(futs, 30, "tle")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        for cat, sats in got.items():
            if sats:  # başarısız grup eski veriyi silmesin
                result[cat] = sats
        if result:
            _tle_cache["data"] = result
            _tle_cache["ts"] = now
        return result

class SGP4Missing(Exception):
    pass

def propagate_sgp4(tle_list, epoch_dt=None):
    """Propagate TLE list to current (or specified) time using SGP4."""
    try:
        from sgp4.api import Satrec, jday
    except ImportError:
        raise SGP4Missing("sgp4 package not installed — run: pip install sgp4")
    if epoch_dt is None:
        epoch_dt = datetime.now(timezone.utc)
    jd, fr = jday(epoch_dt.year, epoch_dt.month, epoch_dt.day,
                  epoch_dt.hour, epoch_dt.minute, epoch_dt.second + epoch_dt.microsecond / 1e6)
    import math
    out = []
    for s in tle_list:
        try:
            sat = Satrec.twoline2rv(s["line1"], s["line2"])
            e, r, v = sat.sgp4(jd, fr)
            if e != 0:
                continue
            # ECI -> geodetic (simplified, ignores nutation/precession — good enough for display)
            x, y, z = r  # km
            # GMST (approximation)
            T = (jd + fr - 2451545.0) / 36525.0
            gmst = (280.46061837 + 360.98564736629 * (jd + fr - 2451545.0)
                    + 0.000387933 * T * T - T * T * T / 38710000.0) % 360
            gmst_rad = math.radians(gmst)
            # Rotate ECI to ECEF
            cos_g = math.cos(gmst_rad); sin_g = math.sin(gmst_rad)
            xe = x * cos_g + y * sin_g
            ye = -x * sin_g + y * cos_g
            ze = z
            r_earth = math.sqrt(xe * xe + ye * ye + ze * ze)
            lat = math.degrees(math.asin(ze / r_earth))
            lon = math.degrees(math.atan2(ye, xe))
            if lon > 180: lon -= 360
            if lon < -180: lon += 360
            alt = r_earth - 6371.0  # km above Earth surface
            # velocity magnitude km/s
            vel = math.sqrt(v[0] ** 2 + v[1] ** 2 + v[2] ** 2)
            out.append({
                "name": s["name"],
                "category": s["category"],
                "mission": classify_mission(s["name"], s["category"]),
                "lat": round(lat, 4),
                "lon": round(lon, 4),
                "alt_km": round(alt, 1),
                "velocity_kms": round(vel, 3),
                "norad_id": s["line1"][2:7].strip() if len(s["line1"]) > 7 else "",
            })
        except Exception:
            continue
    return out

@app.route("/api/satellites")
def api_satellites():
    """Return current satellite positions via TLE + SGP4."""
    categories = request.args.get("categories", "")
    try:
        tle_data = get_all_tle()
    except Exception as e:
        return jsonify({"error": str(e), "satellites": []}), 500
    if not tle_data:
        return jsonify({"error": "TLE fetch failed", "satellites": []}), 502
    # STB-11: 'active' grubu diğer tüm grupları kapsar → varsayılan isteğe dahil edilmez
    if categories:
        wanted = {c.strip() for c in categories.split(",") if c.strip()}
    else:
        wanted = set(tle_data.keys()) - {"active"}
    combined, seen_ids = [], set()
    # Önce özel kategoriler (mission etiketi daha doğru), sonra 'active'
    for cat in sorted(tle_data.keys(), key=lambda c: c == "active"):
        if cat not in wanted:
            continue
        for s in tle_data[cat]:
            nid = s["line1"][2:7].strip()
            if nid in seen_ids:
                continue
            seen_ids.add(nid)
            combined.append(s)
    # Limit to avoid overload — cap at 2000 per response
    truncated = len(combined) > 2000
    if truncated:
        combined = combined[:2000]
    try:
        positions = propagate_sgp4(combined)
    except SGP4Missing as e:
        return jsonify({"error": str(e), "satellites": []}), 500
    # Summary stats
    by_mission = {}
    for p in positions:
        m = p.get("mission", "other")
        by_mission[m] = by_mission.get(m, 0) + 1
    return jsonify({
        "satellites": positions,
        "total": len(positions),
        "by_mission": by_mission,
        "cached": _tle_cache["ts"],
        "truncated": truncated,
    })

@app.route("/api/satnogs/stations")
def api_satnogs_stations():
    """Fetch active SatNOGS ground stations."""
    try:
        r = requests.get("https://network.satnogs.org/api/stations/?format=json", timeout=12)
        if r.status_code != 200:
            return jsonify({"stations": [], "error": f"HTTP {r.status_code}"}), 502
        data = r.json()
        # SatNOGS API paginates; take first page
        stations = data.get("results", data) if isinstance(data, dict) else data
        out = []
        for s in stations[:500]:
            if s.get("lat") is None or s.get("lng") is None:
                continue
            out.append({
                "id": s.get("id"),
                "name": s.get("name", "Unknown"),
                "lat": s.get("lat"),
                "lon": s.get("lng"),
                "altitude": s.get("altitude"),
                "status": s.get("status", "Unknown"),
                "antenna_count": len(s.get("antenna", [])) if isinstance(s.get("antenna"), list) else 0,
                "qthlocator": s.get("qthlocator", ""),
                "observations": s.get("observations", 0),
                "url": f"https://network.satnogs.org/stations/{s.get('id')}/" if s.get("id") else None,
            })
        return jsonify({"stations": out, "total": len(out)})
    except Exception as e:
        return jsonify({"stations": [], "error": str(e)}), 500

@app.route("/api/gps-jamming")
@rate_limit("15 per minute")
def api_gps_jamming():
    """
    Derive GPS jamming heatmap from ADS-B NAC-P (Navigation Accuracy Category, Position).
    Low NAC-P values in a region indicate aircraft GPS accuracy is degraded — a jamming signature.
    Aggregates aircraft positions into a grid.
    """
    lat, lon = validate_coords(request.args.get("lat"), request.args.get("lon"))
    if lat is None:
        # Default: use a couple of active jamming hotspots globally. Caller should provide coords.
        return jsonify({
            "error": "lat/lon required",
            "hint": "Provide center coordinates; radius parameter optional (default 250nm)"
        }), 400
    radius = arg_int("radius", 250, 50, 250)       # deniz mili (adsb.fi max 250 NM)
    grid_size = arg_float("grid", 0.5, 0.1, 5.0)    # degrees per cell

    # NAC-P sadece adsb.fi verisinde var (OpenSky sağlamıyor) → yalnız adsb.fi
    try:
        aircraft = fetch_adsb(lat, lon, radius * 1.852)
    except Exception as e:
        print(f"[gps-jamming] {e}")
        return jsonify({"error": "aircraft fetch failed", "grid": []}), 502

    # Grid-based NAC-P aggregation
    grid = {}
    for ac in aircraft:
        aclat = ac.get("lat"); aclon = ac.get("lon")
        if aclat is None or aclon is None:
            continue
        # NAC-P field names vary across feeds: nac_p, nic, navp, gva
        nacp = ac.get("nac_p")
        if nacp is None: nacp = ac.get("nic")
        if nacp is None: nacp = ac.get("navp")
        # Skip aircraft with no NAC-P report
        if nacp is None:
            continue
        try:
            nacp = int(nacp)
        except (ValueError, TypeError):
            continue
        # Grid bucket
        gy = round(aclat / grid_size) * grid_size
        gx = round(aclon / grid_size) * grid_size
        key = f"{gy:.3f},{gx:.3f}"
        if key not in grid:
            grid[key] = {"lat": gy, "lon": gx, "nacp_values": [], "aircraft": 0}
        grid[key]["nacp_values"].append(nacp)
        grid[key]["aircraft"] += 1

    # Build cells — flag low-NAC-P clusters as jamming
    cells = []
    for key, c in grid.items():
        if c["aircraft"] < 2:
            continue  # need minimum sample size
        vals = c["nacp_values"]
        avg = sum(vals) / len(vals)
        # Typical modern aircraft NAC-P is 9–11. Values ≤7 sustained across multiple aircraft = jamming signal.
        # Severity: 0 (none) to 100 (severe).
        if avg >= 8:
            severity = 0
        else:
            severity = int(round((8 - avg) / 8 * 100))
        if severity < 20:
            continue  # don't surface weak signals
        cells.append({
            "lat": c["lat"],
            "lon": c["lon"],
            "severity": severity,
            "avg_nacp": round(avg, 1),
            "aircraft_count": c["aircraft"],
            "size_deg": grid_size,
        })
    cells.sort(key=lambda x: -x["severity"])
    return jsonify({
        "grid": cells,
        "total_cells": len(cells),
        "aircraft_sampled": len(aircraft),
        "center": {"lat": lat, "lon": lon},
        "radius_nm": radius,
    })

@app.route("/orbital")
def page_orbital():
    return render_template("orbital.html", active="Orbital")

# ══════════════════════════════════════════════
#  SDR — KiwiSDR Network + APRS-IS
# ══════════════════════════════════════════════

_sdr_cache = {"kiwisdr": {"data": None, "ts": 0}, "aprs": {"data": None, "ts": 0}}
_SDR_TTL = 600  # 10 minutes

# ── KiwiSDR public node scraper ──────────────────────────────────
# KiwiSDR has no official JSON API; the public list at kiwisdr.com/public/
# is rendered from HTML. We scrape the <div class="cl-box"> entries.

def _parse_kiwisdr_html(html):
    """
    Extract KiwiSDR nodes from kiwisdr.com/public/ HTML.
    Each receiver is in <div class='cl-entry ...'> with metadata in HTML comments:
      <!-- name=... -->
      <!-- gps=(lat, lon) -->
      <!-- users=N --> / <!-- users_max=M -->
      <!-- loc=... -->
      <!-- antenna=... -->
      <!-- snr=hf_db,all_db -->
      <!-- sw_version=... -->
      <!-- offline=yes/no -->
    """
    nodes = []
    # Split the HTML into per-receiver blocks
    entry_re = re.compile(
        r"<div\s+class='cl-entry[^']*'[^>]*>(.*?)</div>\s*</div>",
        re.DOTALL | re.IGNORECASE
    )
    # Helper: extract a metadata value from HTML comments inside a block
    def meta(block, key):
        m = re.search(rf"<!--\s*{re.escape(key)}=(.*?)\s*-->", block, re.DOTALL)
        return m.group(1).strip() if m else ""

    # Helper: extract the first valid href
    href_re = re.compile(r"href='(http[^']+)'", re.IGNORECASE)

    for m in entry_re.finditer(html):
        block = m.group(1)

        # Skip offline/erroneous entries
        offline = meta(block, "offline").lower()
        if offline == "yes":
            continue

        gps_str = meta(block, "gps")
        gps_m = re.search(r"\(\s*(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)\s*\)", gps_str)
        if not gps_m:
            continue
        try:
            lat = float(gps_m.group(1))
            lon = float(gps_m.group(2))
        except ValueError:
            continue

        # URL — first http link in block
        url_m = href_re.search(block)
        if not url_m:
            continue
        url = url_m.group(1).strip()

        # User counts
        try:    users     = int(meta(block, "users") or "0")
        except: users     = 0
        try:    users_max = int(meta(block, "users_max") or "4")
        except: users_max = 4

        # SNR (format: "47,47" = all,hf or hf,all — we just show as-is)
        snr_raw = meta(block, "snr")
        snr_disp = ""
        if snr_raw:
            parts = snr_raw.split(",")
            if len(parts) == 2:
                snr_disp = f"{parts[0].strip()}/{parts[1].strip()} dB"
            else:
                snr_disp = snr_raw

        # Bands — convert "0-30000000" to "0-30 MHz"
        bands_raw = meta(block, "bands")
        bands_disp = ""
        if bands_raw and "-" in bands_raw:
            try:
                lo, hi = bands_raw.split("-", 1)
                lo_mhz = int(lo) / 1_000_000
                hi_mhz = int(hi) / 1_000_000
                bands_disp = f"{lo_mhz:g}–{hi_mhz:g} MHz"
            except ValueError:
                bands_disp = bands_raw

        # Extract country from loc — usually "City, Country" format, take last comma-separated part
        loc_raw = meta(block, "loc")
        country = ""
        if loc_raw and "," in loc_raw:
            country = loc_raw.rsplit(",", 1)[-1].strip()
        elif loc_raw:
            country = loc_raw.strip()

        nodes.append({
            "url":       url,
            "name":      meta(block, "name")[:160] or url,
            "lat":       lat,
            "lon":       lon,
            "users":     users,
            "users_max": users_max,
            "snr":       snr_disp,
            "bands":     bands_disp,
            "antenna":   meta(block, "antenna")[:200],
            "grid":      meta(block, "grid"),
            "loc":       loc_raw,
            "country":   country,
            "sw":        meta(block, "sw_version"),
            "asl":       meta(block, "asl"),
            "status":    "online",
        })
    return nodes

def _parse_kiwisdr_fallback(html):
    """Fallback: loose anchor+GPS pairing when the cl-box regex doesn't match."""
    nodes = []
    combo_re = re.compile(
        r'<a[^>]+href=["\'](http[^"\']+?:\d+[^"\']*?)["\'][^>]*>([^<]{3,120})</a>[^(]{0,200}?\(\s*(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)\s*\)',
        re.DOTALL | re.IGNORECASE
    )
    for m in combo_re.finditer(html):
        url, name, lat_s, lon_s = m.groups()
        try:
            lat = float(lat_s); lon = float(lon_s)
        except ValueError:
            continue
        name_clean = re.sub(r"<[^>]+>", "", name).strip()
        if not name_clean:
            continue
        nodes.append({
            "url":       url.strip(),
            "name":      name_clean[:120],
            "lat":       lat,
            "lon":       lon,
            "users":     0,
            "users_max": 4,
            "snr":       "",
            "bands":     "",
            "antenna":   "",
            "country":   "",
            "loc":       "",
            "status":    "online",
        })
    return nodes

@app.route("/api/sdr/kiwisdr")
def api_sdr_kiwisdr():
    """Fetch public KiwiSDR receivers by scraping kiwisdr.com/public/."""
    cache = _sdr_cache["kiwisdr"]
    now = time.time()
    if cache["data"] and (now - cache["ts"]) < _SDR_TTL:
        return jsonify(cache["data"])

    urls = [
        "http://kiwisdr.com/public/",
        "http://kiwisdr.com/.public/",
        "http://rx.linkfanel.net/",
    ]
    html = None
    last_err = None
    for u in urls:
        try:
            r = requests.get(u, timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (SignalOPS KiwiSDR client)"})
            print(f"[KiwiSDR] GET {u} → HTTP {r.status_code}, {len(r.text)} bytes")
            if r.status_code == 200 and len(r.text) > 1000:
                html = r.text
                break
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
            print(f"[KiwiSDR] {u}: {e}")
    if html is None:
        return jsonify({"nodes": [], "error": f"All sources failed: {last_err}"}), 502

    nodes = _parse_kiwisdr_html(html)
    if len(nodes) < 5:
        extra = _parse_kiwisdr_fallback(html)
        seen = {n["url"] for n in nodes}
        for n in extra:
            if n["url"] not in seen:
                nodes.append(n); seen.add(n["url"])

    print(f"[KiwiSDR]   → parsed {len(nodes)} nodes")
    result = {"nodes": nodes, "total": len(nodes)}
    cache["data"] = result
    cache["ts"] = now
    return jsonify(result)

# ══════════════════════════════════════════════
#  APRS-IS seed callsign list
# ══════════════════════════════════════════════
# APRS.fi API doesn't support area search — we query a curated list of known
# active digipeaters/igates/weather stations globally, then filter to user's bbox.
APRS_SEED_CALLSIGNS = [
    # ── Turkey — confirmed active ─────────────────
    "TA1OS", "TA1OS-1", "TA1OS-10",
    "TA2ANL", "TA2ILZ", "TA3X-10", "TA3AX-10",
    "TA4AGW", "TA7AMS", "TA7OM",
    "TB1BLK", "TB3IST", "TB4SNS",
    "YM3KB", "YM7KI",

    # ── Israel (very active APRS region) ──────────
    "4X1BF", "4X1FC", "4X1MK",
    "4X4HF", "4X4JU", "4X4DK",
    "4X6TT", "4X6ZM",
    "4Z5CP", "4Z5LA",
    "4Z7HMI", "4Z7ZQ",

    # ── Middle East / Gulf ────────────────────────
    # UAE
    "A61BK", "A61DD", "A61Q",
    # Saudi Arabia
    "HZ1TT", "HZ1DG", "HZ1SK",
    # Qatar
    "A71AE", "A71AM",
    # Kuwait
    "9K2HN", "9K2YM",
    # Oman
    "A41KT", "A41OO",

    # ── Iran (limited but موجود APRS activity) ───
    "EP2LS", "EP3SMH", "EP4HR",

    # ── Cyprus / Eastern Med ─────────────────────
    "5B4AQN", "5B4VL", "5B4AIF",

    # ── Greece (yakın bölge + aktif) ─────────────
    "SV1IYO-13", "SV2EVS", "SV3AQN-10", "SV9KN",

    # ── Western Europe ────────────────────────────
    "OE1XUR", "OE3XEC", "OE9XVV",
    "OK0NE", "OK0NA", "OK1KIM",
    "DB0UAL", "DB0RES", "DB0SIF",
    "DL0IGS", "DL3EL", "DL9SAU",
    "F5ZEE", "F5KMY", "F1ZOO",
    "EA1URA", "EA3URC", "EA5URR",
    "I0JX-10", "IK2XDE", "IR1UCZ",
    "ON0ULG", "PA0R", "PI1APU",
    "G0TRT", "GB7WB", "M0SYM",
    "SM5GLC", "SM6LZQ",
    "OZ7IGY", "LA5KR", "LA9CW",

    # ── Eastern Europe ────────────────────────────
    "UA3DXW", "UR5EAZ",
    "SR1AAA", "SR9PKB", "SP2KMH",
    "LZ0AIX", "YO2BAW", "YO6KGK", "UW5EKR",

    # ── North America ─────────────────────────────
    "W1AW", "W2GSB", "W4ATL", "W5FC", "W6AMT",
    "K0XP", "KD5LPB", "N1EF", "N3FJP-10", "N4WC",
    "WB4GQK",
    "VE2RYL", "VE3JLD", "VE6TL", "VE7RVF", "VE9AA",

    # ── Asia / Oceania ────────────────────────────
    "JA1YCA", "JH6RTO", "JA7DA", "JA0CAW",
    "BM2KLP", "BV2DQ",
    "HL5BMX",
    "VK2RHR", "VK3RWN", "VK6AS",
    "ZL1VFO", "ZL2KE",

    # ── Africa ────────────────────────────────────
    "ZS1REC", "ZS6RP", "V51WW",

    # ── South America ─────────────────────────────
    "PP5BKO", "PY2KCT", "LU1HKE", "CX1SM",
]

_aprs_cache = {}
_APRS_TTL = 300

@app.route("/api/aprs/stations")
@rate_limit("10 per minute")
def api_aprs_stations():
    """
    Fetch APRS stations near given lat/lon using APRS.fi API.
    Since APRS.fi doesn't support area-search, we query a curated list of
    well-known digipeaters/igates globally, then filter to user's bounding box.

    Required: APRS_FI_KEY env var. Free tier at https://aprs.fi/page/api_key
    """
    lat, lon = validate_coords(request.args.get("lat"), request.args.get("lon"))
    if lat is None:
        return jsonify({"error": "lat/lon required", "stations": []}), 400
    aprs_key = APRS_FI_KEY
    if not aprs_key:
        return jsonify({
            "error": "APRS_FI_KEY not set. Get a free key at https://aprs.fi/page/api_key",
            "stations": []
        }), 401

    # 7 ardışık API çağrısı — aynı bölge 5 dk cache'lenir (aprs.fi kullanım koşulları)
    ck = (round(lat, 1), round(lon, 1))
    cached = _aprs_cache.get(ck)
    if cached and time.time() - cached[0] < _APRS_TTL:
        return jsonify(cached[1])

    # Bounding box: ~2.5° on each side (~275 km at equator, less near poles)
    bbox_deg = 2.5
    lat_min, lat_max = lat - bbox_deg, lat + bbox_deg
    lon_min, lon_max = lon - bbox_deg, lon + bbox_deg

    stations = []
    queried_total = 0
    errors = []
    # Query in batches of 20 callsigns (APRS.fi API max per request)
    for i in range(0, len(APRS_SEED_CALLSIGNS), 20):
        batch = APRS_SEED_CALLSIGNS[i:i+20]
        names_param = ",".join(batch)
        queried_total += len(batch)
        try:
            r = requests.get(
                "https://api.aprs.fi/api/get",
                params={
                    "name":   names_param,
                    "what":   "loc",
                    "apikey": aprs_key,
                    "format": "json",
                },
                headers={"User-Agent": "SignalOPS/1.0 (+https://signalops.local)"},
                timeout=10,
            )
            if r.status_code != 200:
                errors.append(f"batch {i//20+1}: HTTP {r.status_code}")
                continue
            data = r.json()
            if data.get("result") != "ok":
                errors.append(f"batch {i//20+1}: {data.get('description', 'unknown error')}")
                continue
            for entry in data.get("entries", []):
                try:
                    slat = float(entry.get("lat"))
                    slon = float(entry.get("lng"))
                except (TypeError, ValueError):
                    continue
                # Filter by bounding box
                if not (lat_min <= slat <= lat_max and lon_min <= slon <= lon_max):
                    continue
                # Parse optional numeric fields
                try:    speed = float(entry.get("speed")) if entry.get("speed") else None
                except: speed = None
                try:    course = int(float(entry.get("course"))) if entry.get("course") else None
                except: course = None
                try:    altitude = float(entry.get("altitude")) if entry.get("altitude") else None
                except: altitude = None
                stations.append({
                    "callsign":  entry.get("name", "?"),
                    "lat":       slat,
                    "lon":       slon,
                    "comment":   entry.get("comment", ""),
                    "symbol":    entry.get("symbol", ""),
                    "speed":     speed,
                    "course":    course,
                    "altitude":  altitude,
                    "time":      entry.get("time"),
                    "lasttime":  entry.get("lasttime"),
                    "path":      entry.get("path", ""),
                    "srccall":   entry.get("srccall", ""),
                    "type":      entry.get("type", "l"),
                })
        except Exception as e:
            errors.append(f"batch {i//20+1}: {str(e)[:80]}")

    print(f"[APRS] queried {queried_total} callsigns, "
          f"{len(stations)} within bbox ({lat:.2f}±{bbox_deg}°, {lon:.2f}±{bbox_deg}°), "
          f"errors: {len(errors)}")

    result = {
        "stations":       stations,
        "total":          len(stations),
        "queried":        queried_total,
        "center":         {"lat": lat, "lon": lon},
        "bbox_degrees":   bbox_deg,
        "authenticated":  True,
        "errors":         errors if errors else None,
    }
    if not errors or stations:
        _aprs_cache[ck] = (time.time(), result)
        if len(_aprs_cache) > 500:
            _aprs_cache.pop(next(iter(_aprs_cache)))
    return jsonify(result)

@app.route("/api/aprs/callsign")
def api_aprs_callsign():
    """
    Direct APRS.fi lookup for one or more specific callsigns.
    Use: /api/aprs/callsign?name=TA1OS  or  ?name=TA1OS,JA1YCA,W1AW
    No bounding-box filter — returns station wherever it is.
    Free tier: up to 20 callsigns per request (APRS.fi limit).
    """
    name = (request.args.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name parameter required (e.g. ?name=TA1OS)", "stations": []}), 400

    aprs_key = APRS_FI_KEY
    if not aprs_key:
        return jsonify({
            "error": "APRS_FI_KEY not set. Get a free key at https://aprs.fi/page/api_key",
            "stations": []
        }), 401

    # Sanitize — allow letters, digits, dash, comma
    name = re.sub(r"[^A-Za-z0-9,\-]", "", name).upper()
    # Cap at 20 (API limit)
    callsigns = [c for c in name.split(",") if c][:20]
    if not callsigns:
        return jsonify({"error": "No valid callsigns", "stations": []}), 400

    try:
        r = requests.get(
            "https://api.aprs.fi/api/get",
            params={
                "name":   ",".join(callsigns),
                "what":   "loc",
                "apikey": aprs_key,
                "format": "json",
            },
            headers={"User-Agent": "SignalOPS/1.0"},
            timeout=10,
        )
        if r.status_code != 200:
            return jsonify({"stations": [], "error": f"HTTP {r.status_code}"}), 502
        data = r.json()
        if data.get("result") != "ok":
            return jsonify({
                "stations": [],
                "error": data.get("description", "API error"),
                "queried": callsigns,
            }), 400

        stations = []
        for entry in data.get("entries", []):
            try:
                slat = float(entry.get("lat"))
                slon = float(entry.get("lng"))
            except (TypeError, ValueError):
                continue
            try:    speed = float(entry.get("speed")) if entry.get("speed") else None
            except: speed = None
            try:    course = int(float(entry.get("course"))) if entry.get("course") else None
            except: course = None
            try:    altitude = float(entry.get("altitude")) if entry.get("altitude") else None
            except: altitude = None
            stations.append({
                "callsign":  entry.get("name", "?"),
                "lat":       slat,
                "lon":       slon,
                "comment":   entry.get("comment", ""),
                "symbol":    entry.get("symbol", ""),
                "speed":     speed,
                "course":    course,
                "altitude":  altitude,
                "time":      entry.get("time"),
                "lasttime":  entry.get("lasttime"),
                "path":      entry.get("path", ""),
                "srccall":   entry.get("srccall", ""),
                "type":      entry.get("type", "l"),
            })

        found_names = {s["callsign"].upper() for s in stations}
        not_found = [c for c in callsigns if c not in found_names]

        print(f"[APRS callsign] queried={callsigns} found={len(stations)} not_found={not_found}")
        return jsonify({
            "stations":  stations,
            "total":     len(stations),
            "queried":   callsigns,
            "not_found": not_found,
        })
    except Exception as e:
        print(f"[APRS callsign] {e}")
        return jsonify({"stations": [], "error": "APRS lookup failed"}), 500

@app.route("/sdr")
def page_sdr():
    return render_template("sdr.html", active="SDR")

@app.route("/api/dashboard-stats")
def api_dashboard_stats():
    """
    Lightweight aggregate stats for the dashboard.
    Pulls from cached TLE + KiwiSDR + SatNOGS data without forcing fresh fetches.
    Safe to call frequently — never blocks on external APIs.
    """
    stats = {
        "satellites_tracked": 0,
        "sdr_nodes":          0,
        "satnogs_stations":   0,
        "tle_cached_at":      _tle_cache.get("ts", 0),
        "kiwi_cached_at":     _sdr_cache.get("kiwisdr", {}).get("ts", 0),
    }

    # Satellites: sum of all cached TLE groups
    tle_data = _tle_cache.get("data") or {}
    total_sats = 0
    by_mission = {}
    if tle_data:
        seen_ids = set()
        for cat in sorted(tle_data.keys(), key=lambda c: c == "active"):
            for s in tle_data[cat]:
                nid = (s.get("line1") or "")[2:7].strip()
                if nid in seen_ids:
                    continue
                seen_ids.add(nid)
                total_sats += 1
                m = classify_mission(s.get("name", ""), cat)
                by_mission[m] = by_mission.get(m, 0) + 1
    stats["satellites_tracked"] = total_sats
    stats["satellites_by_mission"] = by_mission

    # KiwiSDR nodes (from cache)
    kiwi = _sdr_cache.get("kiwisdr", {}).get("data") or {}
    stats["sdr_nodes"]    = kiwi.get("total", 0)
    kiwi_nodes = kiwi.get("nodes", []) or []
    stats["sdr_active_users"] = sum(int(n.get("users", 0) or 0) for n in kiwi_nodes)

    # Yerel veri setleri ve tarama yapılandırması (dashboard'daki sabit sayıların yerine)
    stats["datasets"] = {
        "cameras":         len(_STATIC.get("cameras") or []),
        "camera_networks": len(_STATIC.get("camera_networks") or []),
        "precincts":       len(_STATIC.get("precincts") or []),
    }
    stats["scan_workers"] = 14
    stats["data_sources"] = len(ALL_FETCHERS) + len(CAMERA_FETCHERS)
    stats["ai_model"]  = GEMINI_MODEL
    stats["ai_active"] = bool(GEMINI_KEY)

    return jsonify(stats)

# ══════════════════════════════════════════════
#  EK MODÜLLER (modules/) — vaka, dışa aktarma, alan izleme, AIS
# ══════════════════════════════════════════════
def _register_key_test(provider, needed_globals, fn):
    _KEY_TESTS[provider] = (tuple(needed_globals), fn)

_MODULE_CTX = None

def register_modules():
    import importlib
    global _MODULE_CTX
    from types import SimpleNamespace
    ctx = _MODULE_CTX = SimpleNamespace(
        app=app, get_key=get_key, register_key_test=_register_key_test, rate_limit=rate_limit,
        run_parallel=run_parallel, run_cell_scan=run_cell_scan, run_camera_scan=run_camera_scan,
        fetch_adsb=fetch_adsb, fetch_aircraft=_fetch_aircraft, apply_risk=apply_risk,
        track_devices=track_devices, detect_imsi_catchers=detect_imsi_catchers, detect_rogue_aps=detect_rogue_aps,
        watchlist_match=watchlist_match, validate_coords=validate_coords, sf=sf, base_dir=BASE_DIR,
        gather_futures=gather_futures, config_dir=CONFIG_DIR,
        public_webcam_sources=PUBLIC_WEBCAM_SOURCES, public_source_keys=PUBLIC_SOURCE_KEYS,
    )
    for name in ("health", "net", "cases", "export", "monitor", "ais", "graph", "timeline", "rf", "pubcams"):
        try:
            mod = importlib.import_module(f"{__package__}.modules.{name}")
            mod.init(app, ctx)
            print(f"[modules] {name}: loaded")
        except ModuleNotFoundError as e:
            if e.name == f"{__package__}.modules.{name}":
                continue      # modül henüz yok
            print(f"[modules] {name}: FAILED — {e}")
        except Exception as e:
            print(f"[modules] {name}: FAILED — {e}")

register_modules()

def main():
    print("\n=== SignalOps ===")
    keys_map = {
        "WiGLE": WIGLE_USER, "OpenCellID": OPENCELLID_KEY,
        "Shodan": SHODAN_KEY, "Censys": CENSYS_ID,
        "ZoomEye": ZOOMEYE_KEY, "FOFA": FOFA_KEY,
        "Hunter.how": HUNTERHOW_KEY, "Netlas": NETLAS_KEY,
        "LeakIX": LEAKIX_KEY, "CriminalIP": CRIMINALIP_KEY,
        "BinaryEdge": BINARYEDGE_KEY, "Windy": WINDY_KEY,
        "Gemini": GEMINI_KEY,
        "AbuseIPDB": ABUSEIPDB_KEY,
    }
    active  = [k for k,v in keys_map.items() if v]
    missing = [k for k,v in keys_map.items() if not v]
    print(f"Active  ({len(active)}):  {', '.join(active)}")
    if missing: print(f"Missing ({len(missing)}): {', '.join(missing)}")
    print("OSM Overpass:  FREE (no key)")
    print("Insecam:       FREE (no key, HTTP scrape)")
    print("EarthCam:      FREE (no key, HTML parse)")
    print("ipinfo.io:     FREE HTTPS (primary IP lookup)")
    print("cachetools TTLCache:", "ACTIVE ✓" if _ttlcache_available else "FALLBACK (pip install cachetools)")
    print("flask-limiter:", "ACTIVE ✓" if _limiter_available else "INACTIVE (pip install flask-limiter)")
    try:
        import importlib.util as _ilu
        if not _ilu.find_spec("sgp4"): raise ImportError
        print("sgp4:          ACTIVE ✓")
    except ImportError:
        print("sgp4:          MISSING — Orbital page disabled (pip install sgp4)")
    print("===========================================\n")
    host = os.getenv("SIGNALOPS_HOST", "127.0.0.1")
    port = int(os.getenv("SIGNALOPS_PORT", "8080"))
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"⚠  {host} adresinde dinleniyor — giriş ekranı yok, ağdaki herkes erişebilir.")
        print("   Erişim için tarayıcıda kullanılacak adresi SIGNALOPS_ALLOWED_HOSTS'a ekle.")
    print(f"→ http://{'localhost' if host in ('127.0.0.1','::1') else host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
