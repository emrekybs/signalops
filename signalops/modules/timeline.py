"""
SignalOps — Zaman çizelgesi (Timeline): aynı bölgenin / vakanın taramalarını sırayla yeniden oynatma.

Sayfa
  GET /timeline                        templates/timeline.html (Cases'ten açılır; ?area= | ?case= | ?scan=)

API
  GET /api/timeline/areas[?case_id=]   ≥2 taraması olan bölgeler (area_key grupları), son taramaya göre azalan
  GET /api/timeline?area_key=… | ?case_id=… | ?scan_id=…  [&from=<epoch>&to=<epoch>&limit=<1..500>]
        → {source, scans:[…], devices:{dev_key:{…}}, stats}

Notlar
  * "changed" = önceki taramada (i-1) de vardı ve >50 m yer değiştirdi (yaklaşık konumlar hariç)
    ya da risk / ad / tür değişti. store.diff_scans'tan farkı: o 150 m eşiği ve data JSON alanlarını
    (encryption, operator …) kullanır; burada performans için yalnızca kolonlar okunur.
  * Toplam işlenen cihaz satırı MAX_ROWS ile sınırlı; aşılırsa en eski taramalar düşülür (truncated).
"""
import json, math, re, time
from flask import Blueprint, request, jsonify, render_template

from . import store

bp = Blueprint("timeline", __name__)

MAX_LIMIT = 500
DEFAULT_LIMIT = 200
MAX_ROWS = 200_000
MOVE_M = 50.0
MAX_AREA_KEY = 200
KINDS = {"nearby": "Nearby", "cctv": "CCTV", "cell": "Cell", "adsb": "ADS-B", "ais": "AIS",
         "search": "Search", "other": "Other"}
_AREA_RE = re.compile(r"^[\x20-\x7e -￿]+$")


class BadRequest(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


@bp.errorhandler(BadRequest)
def _bad(e):
    return jsonify({"error": e.msg}), e.code


# ── Girdi doğrulama ──────────────────────────────────────
def _arg_int(name, lo, hi, default=None):
    v = request.args.get(name)
    if v is None or v.strip() == "":
        return default
    v = v.strip()
    if not re.fullmatch(r"-?\d{1,19}", v):
        raise BadRequest(f"'{name}' must be an integer")
    x = int(v)
    if not (lo <= x <= hi):
        raise BadRequest(f"'{name}' out of range ({lo}–{hi})")
    return x


def _arg_area():
    v = request.args.get("area_key")
    if v is None:
        return None
    v = v.strip()
    if not v or len(v) > MAX_AREA_KEY or not _AREA_RE.match(v):
        raise BadRequest("'area_key' invalid")
    return v


def _num(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


# ── Bölge etiketi ────────────────────────────────────────
def _kind_label(k):
    return KINDS.get(k, str(k or "?").upper() if k else "?")


def area_label(area_key, kind=None, monitor_name=None, params=None):
    ak = str(area_key or "")
    if ak.startswith("monitor:"):
        return f"Monitor · {monitor_name or '#' + ak.split(':', 1)[1]}"
    parts = ak.split(":", 2)
    k = kind or parts[0]
    if len(parts) == 3 and parts[1] == "q":
        q = parts[2]
        p = params if isinstance(params, dict) else {}
        if p.get("country"):
            return f"{_kind_label(k)} · country {q.upper()}"
        return f"{_kind_label(k)} · “{q}”"
    if len(parts) == 3 and parts[1] == "none":
        return f"{_kind_label(k)} · single scan"
    if len(parts) == 3:
        la, lo = _num(parts[1]), _num(parts[2])
        if la is not None and lo is not None:
            return f"{_kind_label(k)} · {la:.2f}, {lo:.2f}"
    return f"{_kind_label(k)} · {ak[:80]}"


def _parse_params(v):
    if isinstance(v, dict):
        return v
    try:
        p = json.loads(v or "{}")
        return p if isinstance(p, dict) else {}
    except (TypeError, ValueError):
        return {}


def _hav_m(a_lat, a_lon, b_lat, b_lon):
    r = 6371000.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp = p2 - p1
    dl = math.radians(b_lon - a_lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


# ── Sayfa ────────────────────────────────────────────────
@bp.route("/timeline")
def timeline_page():
    return render_template("timeline.html", active="Cases")


# ── Bölgeler ─────────────────────────────────────────────
_AREAS_SQL = """
SELECT s.area_key, MAX(s.kind) AS kind, COUNT(*) AS scans, MIN(s.created_at) AS first_at, MAX(s.created_at) AS last_at,
       GROUP_CONCAT(DISTINCT s.case_id) AS case_ids, AVG(s.lat) AS lat, AVG(s.lon) AS lon,
       MAX(s.monitor_id) AS monitor_id, MAX(s.id) AS last_id,
       (SELECT s2.params FROM scans s2 WHERE s2.area_key=s.area_key ORDER BY s2.id DESC LIMIT 1) AS params
  FROM scans s
 WHERE s.area_key IS NOT NULL {extra}
 GROUP BY s.area_key HAVING COUNT(*) >= 2
 ORDER BY last_at DESC, last_id DESC
 LIMIT 1000
"""


@bp.route("/api/timeline/areas", methods=["GET"])
def list_areas():
    case_id = _arg_int("case_id", 1, 2**62)
    with store.db() as c:
        if case_id:
            if not c.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise BadRequest("case not found", 404)
            rs = c.execute(_AREAS_SQL.format(
                extra="AND s.area_key IN (SELECT area_key FROM scans WHERE case_id=? AND area_key IS NOT NULL)"),
                (case_id,)).fetchall()
        else:
            rs = c.execute(_AREAS_SQL.format(extra="")).fetchall()
        mids = sorted({r["monitor_id"] for r in rs if r["monitor_id"]})
        mnames = {}
        if mids:
            mnames = {r["id"]: r["name"] for r in c.execute(
                f"SELECT id, name FROM monitors WHERE id IN ({','.join('?' * len(mids))})", mids)}
    out = []
    for r in rs:
        ak = r["area_key"]
        mon = None
        if ak.startswith("monitor:"):
            try: mon = int(ak.split(":", 1)[1])
            except ValueError: mon = None
        cids = sorted({int(x) for x in (r["case_ids"] or "").split(",") if x.strip().isdigit()})
        out.append({
            "area_key": ak, "kind": r["kind"],
            "label": area_label(ak, r["kind"], mnames.get(mon), _parse_params(r["params"])),
            "scans": r["scans"], "first_at": r["first_at"], "last_at": r["last_at"], "case_ids": cids,
            "lat": round(r["lat"], 5) if r["lat"] is not None else None,
            "lon": round(r["lon"], 5) if r["lon"] is not None else None,
            "monitor_id": mon,
        })
    return jsonify({"areas": out})


# ── Zaman çizelgesi ──────────────────────────────────────
@bp.route("/api/timeline", methods=["GET"])
def timeline():
    t0 = time.perf_counter()
    area_key = _arg_area()
    case_id = _arg_int("case_id", 1, 2**62)
    scan_id = _arg_int("scan_id", 1, 2**62)
    if sum(x is not None for x in (area_key, case_id, scan_id)) != 1:
        raise BadRequest("exactly one of 'area_key', 'case_id', 'scan_id' is required")
    t_from = _arg_int("from", 0, 2**40)
    t_to = _arg_int("to", 0, 2**40)
    if t_from is not None and t_to is not None and t_from > t_to:
        raise BadRequest("'from' must be <= 'to'")
    limit = _arg_int("limit", 1, MAX_LIMIT, DEFAULT_LIMIT)

    with store.db() as c:
        source = {"mode": "area" if area_key else "case" if case_id else "scan"}
        if scan_id:
            s = c.execute("SELECT area_key FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not s:
                raise BadRequest("scan not found", 404)
            area_key = s["area_key"]
            source["scan_id"] = scan_id
        if case_id:
            cr = c.execute("SELECT id, name FROM cases WHERE id=?", (case_id,)).fetchone()
            if not cr:
                raise BadRequest("case not found", 404)
            where, vals = "case_id=?", [case_id]
            source.update(case_id=case_id, label=cr["name"])
        else:
            where, vals = "area_key=?", [area_key]
            first = c.execute("SELECT kind, monitor_id, params FROM scans WHERE area_key=? ORDER BY id DESC LIMIT 1",
                              (area_key,)).fetchone()
            if not first:
                raise BadRequest("area not found", 404)
            mname = None
            if first["monitor_id"]:
                m = c.execute("SELECT name FROM monitors WHERE id=?", (first["monitor_id"],)).fetchone()
                mname = m["name"] if m else None
            source.update(area_key=area_key,
                          label=area_label(area_key, first["kind"], mname, _parse_params(first["params"])))
        if t_from is not None:
            where += " AND created_at>=?"; vals.append(t_from)
        if t_to is not None:
            where += " AND created_at<=?"; vals.append(t_to)
        # Sadece kimlik + zaman (ucuz) → pencereyi seç
        ids = c.execute(f"SELECT id, device_count FROM scans WHERE {where} ORDER BY created_at, id", vals).fetchall()
        total_scans = len(ids)
        pos = None
        if scan_id:
            pos = next((i for i, r in enumerate(ids) if r["id"] == scan_id), None)
        if pos is not None and total_scans > limit:
            start = max(0, min(pos - limit // 2, total_scans - limit))
        else:
            start = max(0, total_scans - limit)
        window = ids[start:start + limit]
        # Satır sınırı: en yeni taramalardan geriye doğru, MAX_ROWS'a sığanları al
        truncated, budget, keep_from = False, 0, 0
        for i in range(len(window) - 1, -1, -1):
            budget += int(window[i]["device_count"] or 0)
            if budget > MAX_ROWS:
                keep_from, truncated = i + 1, True
                break
        if pos is not None and truncated and (pos - start) < keep_from:
            # İstenen tarama düşülecekti → pencereyi ondan başlat
            keep_from = pos - start
            budget, end = 0, keep_from
            while end < len(window) and budget + int(window[end]["device_count"] or 0) <= MAX_ROWS:
                budget += int(window[end]["device_count"] or 0); end += 1
            window = window[:max(end, keep_from + 1)]
        dropped = keep_from
        window = window[keep_from:]
        sids = [r["id"] for r in window]
        scans = []
        rows_by_scan = {sid: [] for sid in sids}
        if sids:
            ph = ",".join("?" * len(sids))
            srows = {r["id"]: r for r in c.execute(
                f"SELECT id, created_at, kind, label, device_count, lat, lon, case_id, area_key, monitor_id"
                f"  FROM scans WHERE id IN ({ph})", sids)}
            scans = [srows[sid] for sid in sids]
            cur = c.cursor()
            cur.row_factory = None          # düz tuple → satır başına daha hızlı erişim
            cur.execute(
                f"SELECT scan_id, dev_key, type, source, name, lat, lon, risk,"
                f"       CASE WHEN instr(data, '\"approx\"') THEN json_extract(data, '$.approx') END"
                f"  FROM scan_devices WHERE scan_id IN ({ph}) LIMIT ?", (*sids, MAX_ROWS + 1))
            n_rows = 0
            for r in cur:
                n_rows += 1
                if n_rows > MAX_ROWS:
                    truncated = True
                    break
                rows_by_scan[r[0]].append(r)

    # ── Dizi üzerinde tek geçiş ──
    # st[key] = [kayıt, son_görülme_idx, lat, lon, risk, ad, tür, yaklaşık]  (önceki taramadaki durum)
    devices, st = {}, {}
    out_scans = []
    device_rows = 0
    isfinite, hav = math.isfinite, _hav_m
    prev_n = 0
    for idx, s in enumerate(scans):
        n_new = n_changed = n_kept = 0
        srows = rows_by_scan[s["id"]]
        for (_sid, key, typ, src, name, lat, lon, risk, approx) in srows:
            device_rows += 1
            if lat is not None and lon is not None:
                try:
                    lat, lon = float(lat), float(lon)
                    if not (isfinite(lat) and isfinite(lon)):
                        lat = lon = None
                except (TypeError, ValueError):
                    lat = lon = None
            else:
                lat = lon = None
            risk = int(risk or 0)
            approx = bool(approx) and str(approx).lower() not in ("0", "false")
            e = st.get(key)
            if e is None:
                d = devices[key] = {"name": name, "type": typ or "", "source": src or "",
                                    "first_idx": idx, "last_idx": idx, "present": [idx], "risks": [risk],
                                    "risk_max": risk, "positions": [], "changed": []}
                if lat is not None:
                    d["positions"].append([idx, round(lat, 6), round(lon, 6)])
                if idx > 0:
                    n_new += 1
                st[key] = [d, idx, lat, lon, risk, name, typ, approx]
                continue
            d = e[0]
            if name: d["name"] = name
            if typ: d["type"] = typ
            if src: d["source"] = src
            d["last_idx"] = idx
            if risk > d["risk_max"]: d["risk_max"] = risk
            d["present"].append(idx)
            d["risks"].append(risk)
            if lat is not None:
                ps = d["positions"]
                if not ps:
                    ps.append([idx, round(lat, 6), round(lon, 6)])
                elif not approx:
                    lp = ps[-1]
                    if (lp[1] != round(lat, 6) or lp[2] != round(lon, 6)) and hav(lp[1], lp[2], lat, lon) > MOVE_M:
                        ps.append([idx, round(lat, 6), round(lon, 6)])
            if e[1] == idx - 1:
                n_kept += 1
                moved = (lat is not None and e[2] is not None and not approx and not e[7]
                         and (lat != e[2] or lon != e[3]) and hav(e[2], e[3], lat, lon) > MOVE_M)
                if moved or e[4] != risk or (name and e[5] != name) or (typ and e[6] != typ):
                    n_changed += 1
                    d["changed"].append(idx)
            else:
                n_new += 1
            e[1], e[2], e[3], e[4], e[7] = idx, lat, lon, risk, approx
            if name: e[5] = name
            if typ: e[6] = typ
        counts = {"new": n_new, "gone": prev_n - n_kept, "changed": n_changed} if idx > 0 else \
            {"new": 0, "gone": 0, "changed": 0, "baseline": True}
        prev_n = len(srows)
        out_scans.append({
            "id": s["id"], "created_at": s["created_at"], "kind": s["kind"], "label": s["label"] or "",
            "device_count": len(srows), "lat": s["lat"], "lon": s["lon"], "case_id": s["case_id"],
            "area_key": s["area_key"], "monitor_id": s["monitor_id"], "counts": counts,
        })

    persistent = sum(1 for d in devices.values() if len(d["present"]) >= 2)
    focus_idx = None
    if scan_id:
        focus_idx = next((i for i, s in enumerate(out_scans) if s["id"] == scan_id), None)
    stats = {
        "scans": len(out_scans), "scans_total": total_scans, "scans_dropped": dropped,
        "devices": len(devices), "device_rows": device_rows, "persistent": persistent,
        "transient": len(devices) - persistent, "truncated": truncated,
        "row_cap": MAX_ROWS, "limit": limit, "focus_idx": focus_idx,
        "first_at": out_scans[0]["created_at"] if out_scans else None,
        "last_at": out_scans[-1]["created_at"] if out_scans else None,
        "move_threshold_m": MOVE_M,
        "ms": round((time.perf_counter() - t0) * 1000, 1),
    }
    return jsonify({"source": source, "scans": out_scans, "devices": devices, "stats": stats})


def init(app, ctx):
    app.register_blueprint(bp)
