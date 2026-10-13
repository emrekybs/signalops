"""RF Layers — signal-domain data sources on one map page (/rf).

Every source here is free; most need no key. Each endpoint caches upstream data and never raises
to the UI: on failure it returns an empty list plus an "error" string so the page keeps working.

  LoRaWAN gateways  Packet Broker Mapper     mapper.packetbroker.net (no key)
  Meshtastic nodes  meshmap.net nodes.json   (no key)
  Radiosondes       SondeHub v2              api.v2.sondehub.org (no key) + landing predictions
  HF propagation    WSPR (wspr.live) and PSKReporter (no key; PSKReporter asks for a contact e-mail)
  Space weather     NOAA SWPC JSON           (no key)
  Satellite RF      SatNOGS DB transmitters  (no key)
  Aircraft info     hexdb.io                 (no key)
  Repeaters         RepeaterBook             (approved app token, optional)
  Wi-Fi geolocate   BeaconDB                 (no key; needs 2+ BSSIDs)
"""
import json
import math
import re
import threading
import time
import xml.etree.ElementTree as ET

import requests

UA = {"User-Agent": "SignalOps/2.2 (+https://github.com/emrekybs/signalops)"}
T = 15

_cache = {}
_lock = threading.Lock()


def _cached(key, ttl, fn):
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    val = fn()
    with _lock:
        _cache[key] = (time.time(), val)
        if len(_cache) > 400:                       # keep memory bounded
            for k, _ in sorted(_cache.items(), key=lambda kv: kv[1][0])[:100]:
                _cache.pop(k, None)
    return val


def haversine_km(a_lat, a_lon, b_lat, b_lon):
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp, dl = p2 - p1, math.radians(b_lon - a_lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def _f(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def maidenhead_to_latlon(loc):
    """Grid square centre (2, 4 or 6 chars). Returns (lat, lon) or (None, None)."""
    m = re.match(r"^([A-Ra-r]{2})(\d\d)?([A-Xa-x]{2})?", (loc or "").strip())
    if not m:
        return None, None
    U = m.group(1).upper()
    lon = (ord(U[0]) - 65) * 20 - 180
    lat = (ord(U[1]) - 65) * 10 - 90
    w, h = 20.0, 10.0
    if m.group(2):
        lon += int(m.group(2)[0]) * 2; lat += int(m.group(2)[1]); w, h = 2.0, 1.0
        if m.group(3):
            sub = m.group(3).upper()
            lon += (ord(sub[0]) - 65) * (5 / 60); lat += (ord(sub[1]) - 65) * (2.5 / 60); w, h = 5 / 60, 2.5 / 60
    return round(lat + h / 2, 4), round(lon + w / 2, 4)


def latlon_to_maidenhead(lat, lon, n=4):
    lon += 180; lat += 90
    s = chr(65 + int(lon // 20)) + chr(65 + int(lat // 10))
    if n >= 4:
        s += str(int((lon % 20) // 2)) + str(int(lat % 10))
    if n >= 6:
        s += chr(97 + int((lon % 2) * 12)) + chr(97 + int((lat % 1) * 24))
    return s


# ── LoRaWAN gateways (Packet Broker Mapper) ───────────────────────────────
def lora_gateways(lat, lon, radius_km):
    def get():
        r = requests.get("https://mapper.packetbroker.net/api/v2/gateways", headers=UA, timeout=T, params={
            "distanceWithin[latitude]": f"{lat:.4f}", "distanceWithin[longitude]": f"{lon:.4f}",
            "distanceWithin[distance]": int(radius_km * 1000), "limit": 1000})
        r.raise_for_status()
        return r.json() or []
    raw = _cached(("lora", round(lat, 2), round(lon, 2), int(radius_km)), 900, get)
    out = []
    for g in raw if isinstance(raw, list) else []:
        loc = g.get("location") or {}
        la, lo = _f(loc.get("latitude")), _f(loc.get("longitude"))
        if la is None or lo is None:
            continue
        out.append({"id": g.get("id") or g.get("eui"), "eui": g.get("eui"), "net": g.get("netID"),
                    "tenant": g.get("tenantID"), "lat": la, "lon": lo, "alt": loc.get("altitude"),
                    "online": g.get("online"), "updated": g.get("updatedAt"),
                    "antennas": g.get("antennaCount"), "placement": g.get("antennaPlacement"),
                    "dist_km": round(haversine_km(lat, lon, la, lo), 2)})
    return out


# ── Meshtastic (meshmap.net) ─────────────────────────────────────────────
def _mesh_coord(v):
    x = _f(v)
    if x is None:
        return None
    return x / 1e7 if abs(x) > 180 else x      # some maps publish integer degrees × 1e7


def meshtastic_nodes(lat, lon, radius_km):
    def get():
        r = requests.get("https://meshmap.net/nodes.json", headers=UA, timeout=25)
        r.raise_for_status()
        return r.json() or {}
    raw = _cached("meshmap", 600, get)
    items = raw.items() if isinstance(raw, dict) else enumerate(raw or [])
    out = []
    for num, n in items:
        if not isinstance(n, dict):
            continue
        la, lo = _mesh_coord(n.get("latitude")), _mesh_coord(n.get("longitude"))
        if la is None or lo is None or (la == 0 and lo == 0):
            continue
        d = haversine_km(lat, lon, la, lo)
        if d > radius_km:
            continue
        seen = n.get("seenBy") or {}
        last = max((v for v in seen.values() if isinstance(v, (int, float))), default=None) if isinstance(seen, dict) else None
        out.append({"id": str(num), "name": n.get("longName") or n.get("shortName") or str(num), "short": n.get("shortName"),
                    "hw": n.get("hwModel"), "role": n.get("role"), "lat": la, "lon": lo, "alt": n.get("altitude"),
                    "region": n.get("region"), "preset": n.get("modemPreset"), "battery": n.get("batteryLevel"),
                    "ch_util": n.get("chUtil"), "neighbours": n.get("onlineLocalNodes"), "last_seen": last,
                    "dist_km": round(d, 2)})
    out.sort(key=lambda x: x["dist_km"])
    return out[:1500]


# ── Radiosondes (SondeHub) ───────────────────────────────────────────────
def radiosondes(lat, lon, radius_km):
    def get():
        r = requests.get("https://api.v2.sondehub.org/sondes", headers=UA, timeout=T, params={
            "lat": f"{lat:.3f}", "lon": f"{lon:.3f}", "distance": int(radius_km * 1000), "last": 3 * 3600})
        r.raise_for_status()
        return r.json() or {}
    raw = _cached(("sondes", round(lat, 1), round(lon, 1), int(radius_km)), 60, get)
    sondes = []
    for serial, s in (raw.items() if isinstance(raw, dict) else []):
        la, lo = _f(s.get("lat")), _f(s.get("lon"))
        if la is None or lo is None:
            continue
        sondes.append({"serial": s.get("serial") or serial, "type": s.get("type"), "subtype": s.get("subtype"),
                       "manufacturer": s.get("manufacturer"), "lat": la, "lon": lo, "alt": _f(s.get("alt")),
                       "freq_mhz": _f(s.get("frequency")) or _f(s.get("tx_frequency")),
                       "time": s.get("datetime"), "vel_v": _f(s.get("vel_v")), "vel_h": _f(s.get("vel_h")),
                       "heading": _f(s.get("heading")), "temp": _f(s.get("temp")), "humidity": _f(s.get("humidity")),
                       "batt": _f(s.get("batt")), "sats": s.get("sats"), "uploader": s.get("uploader_callsign"),
                       "dist_km": round(haversine_km(lat, lon, la, lo), 1)})
    sondes.sort(key=lambda x: x["dist_km"])
    sondes = sondes[:60]
    preds = {}
    serials = [s["serial"] for s in sondes if s.get("serial")][:30]
    if serials:
        def getp():
            r = requests.get("https://api.v2.sondehub.org/predictions", headers=UA, timeout=T,
                             params={"vehicles": ",".join(serials)})
            r.raise_for_status()
            return r.json() or []
        try:
            for p in _cached(("sondepred", tuple(serials)), 120, getp):
                track = p.get("data")
                if isinstance(track, str):
                    try: track = json.loads(track)
                    except ValueError: track = []
                pts = [[_f(t.get("lat")), _f(t.get("lon"))] for t in (track or []) if isinstance(t, dict)]
                pts = [q for q in pts if q[0] is not None and q[1] is not None]
                if p.get("vehicle"):
                    preds[p["vehicle"]] = {"track": pts[::max(1, len(pts) // 120)],
                                           "landing": pts[-1] if pts else None,
                                           "descending": p.get("descending"), "landed": p.get("landed"),
                                           "burst_alt": _f(p.get("burst_altitude"))}
        except Exception as e:
            print(f"[rf/sondes] predictions: {e}")
    for s in sondes:
        s["prediction"] = preds.get(s["serial"])
    return sondes


# ── WSPR (wspr.live ClickHouse) ──────────────────────────────────────────
def wspr_spots(lat, lon, radius_km, minutes=30):
    dlat = radius_km / 111.0
    dlon = radius_km / max(5.0, 111.0 * math.cos(math.radians(lat)))
    box = lambda p: (f"({p}_lat BETWEEN {lat - dlat:.3f} AND {lat + dlat:.3f} AND "
                     f"{p}_lon BETWEEN {lon - dlon:.3f} AND {lon + dlon:.3f})")
    sql = ("SELECT time, band, frequency, tx_sign, tx_loc, tx_lat, tx_lon, rx_sign, rx_loc, rx_lat, rx_lon, "
           "snr, power, distance FROM wspr.rx "
           f"WHERE time > now() - INTERVAL {int(minutes)} MINUTE AND ({box('rx')} OR {box('tx')}) "
           "ORDER BY time DESC LIMIT 1500 FORMAT JSON")

    def get():
        r = requests.get("https://db1.wspr.live/", headers=UA, timeout=25, params={"query": sql})
        r.raise_for_status()
        return (r.json() or {}).get("data") or []
    rows = _cached(("wspr", round(lat, 1), round(lon, 1), int(radius_km), int(minutes)), 300, get)
    out = []
    for s in rows:
        tl, tn, rl, rn = _f(s.get("tx_lat")), _f(s.get("tx_lon")), _f(s.get("rx_lat")), _f(s.get("rx_lon"))
        if None in (tl, tn, rl, rn):
            continue
        out.append({"time": s.get("time"), "band": s.get("band"), "freq": s.get("frequency"),
                    "tx": s.get("tx_sign"), "tx_loc": s.get("tx_loc"), "tx_lat": tl, "tx_lon": tn,
                    "rx": s.get("rx_sign"), "rx_loc": s.get("rx_loc"), "rx_lat": rl, "rx_lon": rn,
                    "snr": s.get("snr"), "power": s.get("power"), "km": s.get("distance")})
    return out


# ── PSKReporter ──────────────────────────────────────────────────────────
def pskreporter_spots(lat, lon, contact=""):
    grid = latlon_to_maidenhead(lat, lon, 4)[:2]      # field (e.g. KN) keeps the query small but useful

    def get():
        params = {"callsign": grid, "modify": "grid", "flowStartSeconds": -900, "rronly": 1}
        if contact:
            params["appcontact"] = contact
        r = requests.get("https://retrieve.pskreporter.info/query", headers=UA, timeout=25, params=params)
        r.raise_for_status()
        return r.content
    xml = _cached(("psk", grid), 300, get)        # PSKReporter asks clients to poll at most every ~5 min
    out = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return out
    for el in root.iter():
        if el.tag.split('}')[-1] != "receptionReport":
            continue
        a = el.attrib
        tl, tn = maidenhead_to_latlon(a.get("senderLocator"))
        rl, rn = maidenhead_to_latlon(a.get("receiverLocator"))
        if None in (tl, tn, rl, rn):
            continue
        out.append({"time": _f(a.get("flowStartSeconds")), "mode": a.get("mode"), "freq": _f(a.get("frequency")),
                    "tx": a.get("senderCallsign"), "tx_loc": a.get("senderLocator"), "tx_lat": tl, "tx_lon": tn,
                    "rx": a.get("receiverCallsign"), "rx_loc": a.get("receiverLocator"), "rx_lat": rl, "rx_lon": rn,
                    "snr": _f(a.get("sNR"))})
        if len(out) >= 1500:
            break
    return out


# ── NOAA SWPC space weather ──────────────────────────────────────────────
def _xray_class(flux):
    if not flux or flux <= 0:
        return None
    for letter, base in (("X", 1e-4), ("M", 1e-5), ("C", 1e-6), ("B", 1e-7), ("A", 1e-8)):
        if flux >= base:
            return f"{letter}{flux / base:.1f}"
    return "A0.0"


def space_weather():
    def j(url):
        r = requests.get(url, headers=UA, timeout=T)
        r.raise_for_status()
        return r.json()

    def get():
        out = {"kp": None, "kp_time": None, "kp_series": [], "f107": None, "xray": None, "xray_class": None,
               "xray_time": None, "alerts": []}
        try:
            kp = j("https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json")
            rows = []
            if kp and isinstance(kp[0], list):                 # older array-of-arrays format
                hdr = kp[0]
                rows = [dict(zip(hdr, r)) for r in kp[1:]]
            elif kp and isinstance(kp[0], dict):
                rows = kp
            ser = [(r.get("time_tag"), _f(r.get("Kp") if "Kp" in r else r.get("kp_index"))) for r in rows]
            ser = [s for s in ser if s[1] is not None]
            if ser:
                out["kp_time"], out["kp"] = ser[-1]
                out["kp_series"] = [s[1] for s in ser[-24:]]
        except Exception as e:
            print(f"[rf/swpc] kp: {e}")
        try:
            f = j("https://services.swpc.noaa.gov/json/f107_cm_flux.json")
            if f:
                last = max(f, key=lambda r: r.get("time_tag") or "")
                out["f107"] = _f(last.get("flux"))
        except Exception as e:
            print(f"[rf/swpc] f107: {e}")
        try:
            x = j("https://services.swpc.noaa.gov/json/goes/primary/xrays-6-hour.json")
            longw = [r for r in x or [] if r.get("energy") == "0.1-0.8nm" and _f(r.get("flux"))]
            if longw:
                out["xray"] = _f(longw[-1]["flux"]); out["xray_time"] = longw[-1].get("time_tag")
                out["xray_class"] = _xray_class(out["xray"])
        except Exception as e:
            print(f"[rf/swpc] xray: {e}")
        try:
            al = j("https://services.swpc.noaa.gov/products/alerts.json") or []
            for a in sorted(al, key=lambda r: r.get("issue_datetime") or "", reverse=True)[:6]:
                msg = str(a.get("message") or "")
                title = next((ln.strip() for ln in msg.splitlines() if ln.strip().upper().startswith(("ALERT", "WARNING", "WATCH", "SUMMARY", "EXTENDED"))), "")
                out["alerts"].append({"id": a.get("product_id"), "time": a.get("issue_datetime"), "title": title[:140]})
        except Exception as e:
            print(f"[rf/swpc] alerts: {e}")
        # Plain-language impact for HF / GNSS users
        kpv = out["kp"] or 0
        if out["kp"] is None and out["xray"] is None and out["f107"] is None and not out["alerts"]:
            raise RuntimeError("all SWPC feeds failed")          # don't cache an empty result
        out["impact"] = ("Severe geomagnetic storm: HF blackouts and GNSS errors likely" if kpv >= 7 else
                         "Geomagnetic storm: degraded HF at high latitudes, GNSS accuracy may drop" if kpv >= 5 else
                         "Unsettled: minor HF fading possible" if kpv >= 4 else "Quiet: normal HF and GNSS conditions")
        return out
    return _cached("swpc", 600, get)


# ── SatNOGS transmitters ─────────────────────────────────────────────────
def satnogs_transmitters(norad):
    def get():
        r = requests.get("https://db.satnogs.org/api/transmitters/", headers=UA, timeout=T,
                         params={"format": "json", "satellite__norad_cat_id": int(norad)})
        r.raise_for_status()
        return r.json() or []
    out = []
    for t in _cached(("satnogs_tx", int(norad)), 3600, get):
        out.append({"uuid": t.get("uuid"), "description": t.get("description"), "alive": t.get("alive"),
                    "status": t.get("status"), "type": t.get("type"), "mode": t.get("mode"),
                    "downlink_mhz": round(t["downlink_low"] / 1e6, 4) if t.get("downlink_low") else None,
                    "downlink_high_mhz": round(t["downlink_high"] / 1e6, 4) if t.get("downlink_high") else None,
                    "uplink_mhz": round(t["uplink_low"] / 1e6, 4) if t.get("uplink_low") else None,
                    "baud": t.get("baud"), "service": t.get("service"), "updated": t.get("updated")})
    out.sort(key=lambda t: (not t["alive"], t["downlink_mhz"] or 0))
    return out


# ── hexdb.io aircraft info ───────────────────────────────────────────────
def aircraft_info(hexcode=None, callsign=None):
    out = {}
    if hexcode:
        def geta():
            r = requests.get(f"https://hexdb.io/api/v1/aircraft/{hexcode}", headers=UA, timeout=10)
            return r.json() if r.status_code == 200 else {}
        a = _cached(("hexdb_ac", hexcode), 86400, geta) or {}
        if a.get("Registration") or a.get("Type"):
            out.update({"registration": a.get("Registration"), "manufacturer": a.get("Manufacturer"),
                        "type_code": a.get("ICAOTypeCode"), "type": a.get("Type"),
                        "owner": a.get("RegisteredOwners"), "operator_code": a.get("OperatorFlagCode")})
    if callsign:
        def getr():
            r = requests.get(f"https://hexdb.io/api/v1/route/icao/{callsign}", headers=UA, timeout=10)
            return r.json() if r.status_code == 200 else {}
        rt = _cached(("hexdb_rt", callsign), 6 * 3600, getr) or {}
        route = str(rt.get("route") or "")
        if route and "-" in route:
            out["route"] = route.split("-")
    return out


# ── RepeaterBook (approved token) ────────────────────────────────────────
def repeaters(lat, lon, radius_km, country, token):
    na = country.strip().lower() in ("united states", "usa", "us", "canada", "mexico")
    url = "https://www.repeaterbook.com/api/" + ("export.php" if na else "exportROW.php")

    def get():
        r = requests.get(url, timeout=25, params={"country": country},
                         headers={**UA, "X-RB-App-Token": token})
        r.raise_for_status()
        return r.json() or {}
    raw = _cached(("rb", country.lower()), 6 * 3600, get)
    rows = raw.get("results") if isinstance(raw, dict) else raw
    out = []
    for x in rows or []:
        la = _f(x.get("Lat") or x.get("lat") or x.get("Latitude"))
        lo = _f(x.get("Long") or x.get("lon") or x.get("Longitude"))
        if la is None or lo is None:
            continue
        d = haversine_km(lat, lon, la, lo)
        if d > radius_km:
            continue
        out.append({"callsign": x.get("Callsign"), "freq": x.get("Frequency"), "input": x.get("Input Freq"),
                    "tone": x.get("PL") or x.get("CTCSS"), "city": x.get("Nearest City"), "mode": x.get("Mode") or
                    ", ".join(k for k in ("FM Analog", "DMR", "D-Star", "System Fusion", "P-25", "NXDN") if str(x.get(k, "")).lower() == "yes"),
                    "status": x.get("Operational Status"), "lat": la, "lon": lo, "dist_km": round(d, 1)})
    out.sort(key=lambda r: r["dist_km"])
    return out[:500]


# ── BeaconDB Wi-Fi geolocation ───────────────────────────────────────────
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def beacondb_locate(bssids):
    body = {"considerIp": False, "wifiAccessPoints": [{"macAddress": b.lower().replace("-", ":")} for b in bssids]}
    r = requests.post("https://api.beacondb.net/v1/geolocate", json=body, headers=UA, timeout=T)
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    j = r.json() or {}
    loc = j.get("location") or {}
    return {"found": loc.get("lat") is not None, "lat": loc.get("lat"), "lon": loc.get("lng"), "accuracy_m": j.get("accuracy")}


# ── Flask wiring ─────────────────────────────────────────────────────────
def init(app, ctx):
    from flask import Blueprint, jsonify, render_template, request
    if "rf" in app.blueprints:
        return
    bp = Blueprint("rf", __name__)
    rl = getattr(ctx, "rate_limit", None) or (lambda spec: (lambda f: f))
    get_key = getattr(ctx, "get_key", lambda k: "")

    def coords(max_radius):
        lat, lon = ctx.validate_coords(request.args.get("lat"), request.args.get("lon"))
        if lat is None:
            return None, None, None
        try:
            radius = float(request.args.get("radius_km", 50))
        except ValueError:
            radius = 50.0
        return lat, lon, max(1.0, min(max_radius, radius))

    def wrap(name, fn):
        try:
            data = fn()
            return jsonify({"items": data, "count": len(data)})
        except requests.RequestException as e:
            code = getattr(getattr(e, "response", None), "status_code", None)
            print(f"[rf/{name}] {type(e).__name__} {code or ''}")
            return jsonify({"items": [], "count": 0, "error": f"{name} unavailable ({code or type(e).__name__})"})
        except Exception as e:
            print(f"[rf/{name}] {e}")
            return jsonify({"items": [], "count": 0, "error": f"{name} failed"})

    def need_coords():
        return jsonify({"items": [], "count": 0, "error": "lat/lon required"}), 400

    @bp.route("/rf")
    def page_rf():
        return render_template("rf.html", active="RF Layers")

    @bp.route("/api/rf/lora")
    @rl("30 per minute")
    def api_lora():
        lat, lon, r = coords(200)
        if lat is None: return need_coords()
        return wrap("Packet Broker", lambda: lora_gateways(lat, lon, r))

    @bp.route("/api/rf/meshtastic")
    @rl("30 per minute")
    def api_mesh():
        lat, lon, r = coords(500)
        if lat is None: return need_coords()
        return wrap("meshmap.net", lambda: meshtastic_nodes(lat, lon, r))

    @bp.route("/api/rf/sondes")
    @rl("30 per minute")
    def api_sondes():
        lat, lon, r = coords(1000)
        if lat is None: return need_coords()
        return wrap("SondeHub", lambda: radiosondes(lat, lon, r))

    @bp.route("/api/rf/wspr")
    @rl("20 per minute")
    def api_wspr():
        lat, lon, r = coords(1500)
        if lat is None: return need_coords()
        try: minutes = max(10, min(120, int(request.args.get("minutes", 30))))
        except ValueError: minutes = 30
        return wrap("wspr.live", lambda: wspr_spots(lat, lon, r, minutes))

    @bp.route("/api/rf/pskreporter")
    @rl("10 per minute")
    def api_psk():
        lat, lon, _r = coords(1)
        if lat is None: return need_coords()
        return wrap("PSKReporter", lambda: pskreporter_spots(lat, lon, get_key("PSKREPORTER_CONTACT")))

    @bp.route("/api/rf/spaceweather")
    @rl("30 per minute")
    def api_swpc():
        try:
            return jsonify(space_weather())
        except Exception as e:
            print(f"[rf/swpc] {e}")
            return jsonify({"error": "NOAA SWPC unavailable"})

    @bp.route("/api/rf/satnogs/transmitters")
    @rl("30 per minute")
    def api_satnogs_tx():
        norad = request.args.get("norad", "")
        if not norad.isdigit() or not (1 <= int(norad) <= 999999):
            return jsonify({"items": [], "count": 0, "error": "norad (NORAD catalog number) required"}), 400
        return wrap("SatNOGS DB", lambda: satnogs_transmitters(int(norad)))

    @bp.route("/api/aircraft/info")
    @rl("60 per minute")
    def api_aircraft_info():
        hx = (request.args.get("hex") or "").strip().upper()
        cs = re.sub(r"[^A-Z0-9]", "", (request.args.get("callsign") or "").upper())[:8]
        if hx and not re.fullmatch(r"[0-9A-F]{6}", hx):
            hx = ""
        if not hx and not cs:
            return jsonify({"error": "hex or callsign required"}), 400
        try:
            return jsonify(aircraft_info(hx or None, cs or None))
        except Exception as e:
            print(f"[rf/hexdb] {e}")
            return jsonify({"error": "hexdb.io unavailable"})

    @bp.route("/api/rf/repeaters")
    @rl("10 per minute")
    def api_repeaters():
        token = get_key("REPEATERBOOK_TOKEN")
        if not token:
            return jsonify({"items": [], "count": 0, "error": "RepeaterBook token not set (Settings → Air & Radio)"})
        lat, lon, r = coords(300)
        if lat is None: return need_coords()
        country = re.sub(r"[^A-Za-z .'-]", "", request.args.get("country") or "")[:40]
        if not country:
            return jsonify({"items": [], "count": 0, "error": "country required"}), 400
        return wrap("RepeaterBook", lambda: repeaters(lat, lon, r, country, token))

    @bp.route("/api/rf/beacondb", methods=["POST"])
    @rl("20 per minute")
    def api_beacondb():
        body = request.get_json(silent=True) or {}
        raw = body.get("bssids") if isinstance(body, dict) else None
        if isinstance(raw, str):
            raw = re.split(r"[\s,;]+", raw)
        bssids = [b.strip() for b in (raw or []) if isinstance(b, str) and MAC_RE.match(b.strip())][:20]
        if len(bssids) < 2:
            return jsonify({"found": False, "error": "BeaconDB needs at least 2 BSSIDs seen together"}), 400
        try:
            return jsonify(beacondb_locate(bssids))
        except requests.RequestException as e:
            return jsonify({"found": False, "error": f"BeaconDB unavailable ({type(e).__name__})"})

    app.register_blueprint(bp)
