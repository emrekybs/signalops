"""More official public webcam networks for the CCTV page.

Each loader returns [{id, name, lat, lon, thumb, stream, online, view}] and is registered into the app's
PUBLIC_WEBCAM_SOURCES table (label, operator, country, bbox, loader), so the existing CCTV search, the
1-hour station cache and the "by country" listing pick them up with no other changes.

Keyless: Iceland (Vegagerðin), Spain (DGT, DATEX II), NSW + Queensland (AU), ALERTCalifornia, USGS AVO.
Free key (Settings → Cameras): NPS webcams (falls back to DEMO_KEY), 511 Ontario / Alberta / Georgia, FL511.
"""
import xml.etree.ElementTree as ET

import requests

UA = {"User-Agent": "SignalOps/2.2 (+https://github.com/emrekybs/signalops)"}
T = 25
_get_key = lambda k: ""          # replaced in init()


def _f(v):
    try:
        x = float(v)
        return x if -180.0 <= x <= 180.0 else None
    except (TypeError, ValueError):
        return None


def _iceland():
    r = requests.get("https://vegasja.vegagerdin.is/arcgis/rest/services/data/info/MapServer/1/query", headers=UA, timeout=T,
                     params={"where": "1=1", "outFields": "*", "outSR": 4326, "f": "json"})
    r.raise_for_status()
    out = []
    for f in r.json().get("features") or []:
        a, g = f.get("attributes") or {}, f.get("geometry") or {}
        la, lo = _f(g.get("y")), _f(g.get("x"))
        if la is None or lo is None:
            continue
        img = a.get("SLOD")
        name = " · ".join(str(x) for x in (a.get("MYNDAVEL"), a.get("SKYRING")) if x) or "Vegagerðin camera"
        out.append({"id": a.get("MAELIST_NR") or a.get("OBJECTID"), "name": name, "lat": la, "lon": lo,
                    "thumb": img, "stream": img, "online": True, "view": a.get("VEGHEITI")})
    return out


def _local(tag):
    return tag.split('}')[-1]


def _spain_dgt():
    r = requests.get("https://nap.dgt.es/datex2/v3/dgt/DevicePublication/camaras_datex2_v37.xml", headers=UA, timeout=40)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    out = []
    for dev in root.iter():
        if _local(dev.tag) != "device":
            continue
        vals = {}
        for el in dev.iter():
            t = _local(el.tag)
            if el.text and el.text.strip() and t not in vals:
                vals[t] = el.text.strip()
        if vals.get("typeOfDevice", "camera").lower() != "camera":
            continue
        la, lo = _f(vals.get("latitude")), _f(vals.get("longitude"))
        if la is None or lo is None:
            continue
        img = vals.get("deviceUrl")
        road = vals.get("roadName") or vals.get("roadNumber") or vals.get("value")
        did = dev.attrib.get("id")
        out.append({"id": did, "name": f"DGT {road or 'camera'} · {did}" if did else "DGT camera", "lat": la, "lon": lo,
                    "thumb": img, "stream": img, "online": True, "view": vals.get("description") or road})
    return out


def _nsw():
    r = requests.get("https://www.livetraffic.com/datajson/all-feeds-web.json", headers=UA, timeout=T)
    r.raise_for_status()
    j = r.json()
    items = j if isinstance(j, list) else (j.get("features") or [])
    out = []
    for it in items:
        if (it.get("eventCategory") or (it.get("properties") or {}).get("eventCategory")) != "liveCams":
            continue
        p = it.get("properties") or {}
        c = (it.get("geometry") or {}).get("coordinates") or []
        if len(c) < 2:
            continue
        lo, la = _f(c[0]), _f(c[1])
        if la is None or lo is None:
            continue
        out.append({"id": it.get("id"), "name": p.get("title") or "NSW Live Traffic camera", "lat": la, "lon": lo,
                    "thumb": p.get("href"), "stream": p.get("href"), "online": True,
                    "view": " · ".join(str(x) for x in (p.get("view"), p.get("direction"), p.get("region")) if x)})
    return out


def _qld():
    # Public key published by QLDTraffic for its open data feed
    r = requests.get("https://api.qldtraffic.qld.gov.au/v1/webcams", headers=UA, timeout=T,
                     params={"apikey": "3e83add325cbb69ac4d8e5bf433d770b"})
    r.raise_for_status()
    out = []
    for f in r.json().get("features") or []:
        p = f.get("properties") or {}
        c = (f.get("geometry") or {}).get("coordinates") or []
        if len(c) < 2:
            continue
        lo, la = _f(c[0]), _f(c[1])
        if la is None or lo is None:
            continue
        out.append({"id": p.get("id"), "name": p.get("description") or "QLDTraffic camera", "lat": la, "lon": lo,
                    "thumb": p.get("image_url"), "stream": p.get("image_url"), "online": True,
                    "view": " · ".join(str(x) for x in (p.get("direction"), p.get("locality"), p.get("district")) if x)})
    return out


def _alertca():
    import time
    r = requests.get("https://cameras.alertcalifornia.org/public-camera-data/all_cameras-v3.json", headers=UA, timeout=T)
    r.raise_for_status()
    now = time.time()
    out = []
    for f in r.json().get("features") or []:
        p = f.get("properties") or {}
        c = (f.get("geometry") or {}).get("coordinates") or []
        if len(c) < 2:
            continue
        lo, la = _f(c[0]), _f(c[1])
        if la is None or lo is None or not p.get("id"):
            continue
        ts = p.get("last_frame_ts")
        try: fresh = now - float(ts) < 3600
        except (TypeError, ValueError): fresh = True
        out.append({"id": p.get("id"), "name": p.get("name") or p.get("id"), "lat": la, "lon": lo,
                    "thumb": None, "stream": None, "online": fresh,
                    "view": " · ".join(str(x) for x in (p.get("county"), p.get("state"),
                                                         f"az {p['az_current']}°" if p.get("az_current") is not None else None) if x)})
    return out


def _usgs_avo():
    r = requests.get("https://avo-volcview.wr.usgs.gov/ashcam-api/webcamApi/webcams", headers=UA, timeout=T)
    r.raise_for_status()
    j = r.json()
    rows = j if isinstance(j, list) else (j.get("webcams") or j.get("data") or [])
    out = []
    for w in rows:
        la, lo = _f(w.get("latitude")), _f(w.get("longitude"))
        if la is None or lo is None:
            continue
        img = w.get("newestImage")
        if isinstance(img, dict):
            img = img.get("url") or img.get("imageUrl")
        img = img if isinstance(img, str) and img.startswith("http") else None
        out.append({"id": w.get("webcamCode"), "name": w.get("webcamName") or w.get("webcamCode") or "USGS volcano cam",
                    "lat": la, "lon": lo, "thumb": img, "stream": img or w.get("externalUrl"),
                    "online": bool(w.get("hasImages", True)), "view": w.get("vName")})
    return out


def _nps():
    key = _get_key("NPS_API_KEY") or "DEMO_KEY"
    out, start = [], 0
    for _ in range(3):                       # ~300 webcams → at most 3 pages of 200
        r = requests.get("https://developer.nps.gov/api/v1/webcams", headers=UA, timeout=T,
                         params={"api_key": key, "limit": 200, "start": start})
        r.raise_for_status()
        j = r.json()
        data = j.get("data") or []
        for w in data:
            la, lo = _f(w.get("latitude")), _f(w.get("longitude"))
            if la is None or lo is None or (la == 0 and lo == 0):
                continue
            imgs = w.get("images") or []
            img = next((i.get("url") for i in imgs if isinstance(i, dict) and i.get("url")), None)
            parks = ", ".join(p.get("fullName", "") for p in (w.get("relatedParks") or []) if isinstance(p, dict))
            out.append({"id": w.get("id"), "name": w.get("title") or "NPS webcam", "lat": la, "lon": lo,
                        "thumb": img, "stream": w.get("url") or img,
                        "online": str(w.get("status", "Active")).lower() == "active",
                        "view": parks or ("streaming" if w.get("isStreaming") else None)})
        start += len(data)
        try: total = int(j.get("total") or 0)
        except ValueError: total = 0
        if not data or start >= total:
            break
    return out


def _ibi511(host, key_name):
    """Shared loader for the IBI '511' developer API (Ontario, Alberta, Georgia, Florida)."""
    def load():
        key = _get_key(key_name)
        if not key:
            return []
        r = requests.get(f"https://{host}/api/v2/get/cameras", headers=UA, timeout=T,
                         params={"key": key, "format": "json"})
        r.raise_for_status()
        out = []
        for c in r.json() or []:
            la, lo = _f(c.get("Latitude")), _f(c.get("Longitude"))
            if la is None or lo is None:
                continue
            views = [v for v in (c.get("Views") or []) if isinstance(v, dict)]
            v0 = next((v for v in views if str(v.get("Status", "")).lower() not in ("disabled", "offline")), views[0] if views else {})
            img = v0.get("Url")
            out.append({"id": c.get("Id"), "name": c.get("Name") or c.get("Location") or c.get("Roadway") or "511 camera",
                        "lat": la, "lon": lo, "thumb": img, "stream": v0.get("VideoUrl") or img,
                        "online": str(v0.get("Status", "Enabled")).lower() not in ("disabled", "offline"),
                        "view": " · ".join(str(x) for x in (c.get("Roadway"), c.get("Direction"), v0.get("Description")) if x)})
        return out
    return load


# key: (label, operator, country, bbox (S, W, N, E), loader, required key or None)
SOURCES = {
    "is_vegagerdin": ("Vegagerðin (Iceland)", "Icelandic Road Administration", "IS", (63.2, -24.6, 66.6, -13.4), _iceland, None),
    "es_dgt":        ("DGT (Spain)", "Dirección General de Tráfico", "ES", (27.6, -18.2, 43.8, 4.4), _spain_dgt, None),
    "au_nsw":        ("NSW Live Traffic", "Transport for NSW", "AU", (-37.6, 140.9, -28.1, 153.7), _nsw, None),
    "au_qld":        ("QLDTraffic", "Queensland TMR", "AU", (-29.2, 137.9, -9.1, 153.6), _qld, None),
    "alertca":       ("ALERTCalifornia", "UC San Diego ALERTCalifornia", "US", (31.0, -125.0, 49.0, -104.0), _alertca, None),
    "usgs_avo":      ("USGS volcano cams", "USGS Alaska Volcano Observatory", "US", (50.0, -180.0, 72.0, -129.0), _usgs_avo, None),
    "nps":           ("NPS webcams", "US National Park Service", "US", (18.5, -170.0, 71.5, -66.0), _nps, None),
    "on511":         ("511 Ontario", "Ontario MTO", "CA", (41.7, -95.2, 56.9, -74.3), _ibi511("511on.ca", "ONTARIO511_KEY"), "ONTARIO511_KEY"),
    "ab511":         ("511 Alberta", "Alberta Transportation", "CA", (49.0, -120.0, 60.0, -110.0), _ibi511("511.alberta.ca", "ALBERTA511_KEY"), "ALBERTA511_KEY"),
    "ga511":         ("511 Georgia", "Georgia DOT", "US", (30.4, -85.6, 35.0, -80.8), _ibi511("511ga.org", "GEORGIA511_KEY"), "GEORGIA511_KEY"),
    "fl511":         ("FL511", "Florida DOT", "US", (24.4, -87.6, 31.0, -80.0), _ibi511("fl511.com", "FL511_KEY"), "FL511_KEY"),
}


def init(app, ctx):
    global _get_key
    _get_key = getattr(ctx, "get_key", _get_key)
    table = getattr(ctx, "public_webcam_sources", None)
    keys = getattr(ctx, "public_source_keys", None)
    if table is None:
        print("[pubcams] app has no public webcam table — skipped")
        return
    for k, (label, op, cc, bbox, fn, key) in SOURCES.items():
        if k in table:
            continue
        table[k] = (label, op, cc, bbox, fn)
        if key and keys is not None:
            keys[k] = key
