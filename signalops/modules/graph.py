"""
SignalOps — Korelasyon Grafiği (Correlation Graph).

Sayfa
  GET /graph                         templates/graph.html (Cases'ten açılır; nav'da yok → active="Cases")
     deep link: /graph?case=<id>  ·  /graph?key=<dev_key>

API
  GET /api/graph?case_id=&key=&depth=&min_together=&limit=&kinds=&since=
     case_id       vaka kapsamı (yalnız o vakanın taramaları)
     key           odak cihaz → ego grafı (BFS, depth adım)
     depth         1–3 (key modunda varsayılan 2)
     min_together  seen_with eşiği: iki cihaz en az N ortak taramada (varsayılan 2)
     limit         en fazla cihaz düğümü (varsayılan 300, en çok 1500)
     kinds         virgüllü tarama türleri (nearby,cctv,cell,adsb,ais,search,other)
     since         epoch saniye; yalnız bu andan sonraki taramalar
  Döner (Cytoscape biçimi):
     {nodes:[{data:{id,label,group,type,risk,count,…}}], edges:[{data:{id,source,target,rel,weight,label}}],
      stats:{nodes,edges,devices,truncated,edges_truncated,mode,ms,db_scans}}

Düğüm grupları: device · case · ssid · net24 · operator_lac · org
Kenar ilişkileri: in_case · seen_with · broadcasts · in_net · in_lac · org

Notlar
  * Öznitelik düğümleri (ssid / net24 / operator_lac / org) yalnız seçili cihazlardan en az ikisi
    paylaşıyorsa oluşur (tekil öznitelik = gürültü).
  * Ego BFS cihazdan cihaza ilerler: seen_with + aynı SSID + aynı /24 + aynı operatör/LAC + aynı org.
    Vaka üyeliği BFS'te gezilmez (bir vakadaki tüm cihazlar patlamasın); vaka düğümleri yaprak olarak eklenir.
  * Tüm seçim/öz-birleştirme işlemleri bağlantıya özel TEMP tablolarla yapılır (N+1 sorgu yok,
    self-join yalnız seçili anahtarlarla).
"""
import ipaddress, json, time
from flask import Blueprint, request, jsonify, render_template

from . import store

try:
    from .cases import SCAN_KINDS
except Exception:                              # cases modülü yüklenemese de grafik çalışsın
    SCAN_KINDS = ("nearby", "cctv", "cell", "adsb", "ais", "search", "other")

bp = Blueprint("graph", __name__)

DEF_LIMIT, MAX_LIMIT = 300, 1500
DEF_DEPTH, MAX_DEPTH = 2, 3
DEF_TOGETHER, MAX_TOGETHER = 2, 100000
MAX_KEY = 300
MAX_SEEN_EDGES = 6000          # seen_with kenar tavanı (en güçlüler kalır)
MAX_FRONTIER = 1500
SSID_TYPES = ("router", "bluetooth", "ble")
MAX_ATTR = 120                 # öznitelik etiketi uzunluğu


class BadRequest(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


@bp.errorhandler(BadRequest)
def _bad(e):
    return jsonify({"error": e.msg}), e.code


# ── Girdi doğrulama ──────────────────────────────────────
def _int_arg(name, default, lo, hi):
    v = request.args.get(name)
    if v is None or v.strip() == "":
        return default
    v = v.strip()
    if not (v.isdigit() or (v[0] == "-" and v[1:].isdigit())) or len(v) > 18:
        raise BadRequest(f"'{name}' must be an integer")
    x = int(v)
    if x < lo or x > hi:
        raise BadRequest(f"'{name}' must be between {lo} and {hi}")
    return x


def _params():
    a = request.args
    case_id = _int_arg("case_id", None, 1, 2**62)
    key = a.get("key")
    if key is not None:
        key = key.strip()
        if not key:
            key = None
        elif len(key) > MAX_KEY or any(ord(ch) < 32 for ch in key):
            raise BadRequest("'key' invalid or too long")
    depth = _int_arg("depth", DEF_DEPTH, 1, MAX_DEPTH)
    together = _int_arg("min_together", DEF_TOGETHER, 1, MAX_TOGETHER)
    limit = _int_arg("limit", DEF_LIMIT, 1, MAX_LIMIT)
    since = _int_arg("since", None, 0, 2**40)
    kinds = None
    raw = (a.get("kinds") or "").strip()
    if raw:
        ks = [k.strip() for k in raw.split(",") if k.strip()]
        bad = [k for k in ks if k not in SCAN_KINDS]
        if bad or len(ks) > len(SCAN_KINDS) * 2:
            raise BadRequest(f"'kinds' must be a comma list of: {', '.join(SCAN_KINDS)}")
        kinds = sorted(set(ks))
    return dict(case_id=case_id, key=key, depth=depth, together=together, limit=limit, since=since, kinds=kinds)


# ── Yardımcılar ──────────────────────────────────────────
def _temp_keys(c, table, keys):
    c.execute(f"DROP TABLE IF EXISTS temp.{table}")
    c.execute(f"CREATE TEMP TABLE {table}(dev_key TEXT PRIMARY KEY)")
    c.executemany(f"INSERT OR IGNORE INTO {table}(dev_key) VALUES(?)", [(k,) for k in keys])


def _scope(c, p):
    """Kapsam filtresi varsa temp.g_scans doldurur; scan_devices takma adı 'd' için SQL parçası döner."""
    where, args = [], []
    if p["case_id"] is not None:
        where.append("case_id=?"); args.append(p["case_id"])
    if p["kinds"]:
        where.append(f"kind IN ({','.join('?' * len(p['kinds']))})"); args.extend(p["kinds"])
    if p["since"] is not None:
        where.append("created_at>=?"); args.append(p["since"])
    if not where:
        return ""
    c.execute("CREATE TEMP TABLE g_scans(id INTEGER PRIMARY KEY)")
    c.execute(f"INSERT INTO g_scans(id) SELECT id FROM scans WHERE {' AND '.join(where)}", args)
    return " AND d.scan_id IN (SELECT id FROM temp.g_scans)"


def _ipv4_of_key(k):
    if not k.startswith("ip:"):
        return None
    ip = k[3:].rsplit(":", 1)[0]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return str(a) if a.version == 4 else None


def _net24(k):
    ip = _ipv4_of_key(k)
    return ".".join(ip.split(".")[:3]) + ".0/24" if ip else None


def _lac(k):
    if not k.startswith("cell:"):
        return None
    parts = k.split(":")
    return ":".join(parts[1:4]) if len(parts) >= 5 else None


def _ssid(t, data):
    if (t or "").lower() not in SSID_TYPES:
        return None
    s = data.get("ssid") if isinstance(data, dict) else None
    if isinstance(s, str) and s.strip():
        return s.strip()[:200]
    return None


def _org(k, data):
    if not k.startswith("ip:") or not isinstance(data, dict):
        return None
    o = data.get("org")
    if isinstance(o, str) and o.strip():
        return o.strip()[:200]
    return None


def _jload(s):
    try:
        d = json.loads(s) if isinstance(s, str) else s
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _latest(c, table, sc):
    """Seçili anahtarların kapsam içindeki son (en yüksek scan_id) satırı. bare-column + tek MAX."""
    out = {}
    for r in c.execute(
            f"SELECT d.dev_key AS k, d.type AS type, d.name AS name, d.data AS data, d.lat AS lat, d.lon AS lon,"
            f"       MAX(d.scan_id) AS sid"
            f"  FROM temp.{table} t JOIN scan_devices d ON d.dev_key=t.dev_key WHERE 1{sc} GROUP BY d.dev_key"):
        out[r["k"]] = r
    return out


# ── Ego BFS ──────────────────────────────────────────────
def _neighbors(c, frontier, together, sc):
    """frontier → {komşu_anahtar: skor}. Seviye başına sabit sayıda sorgu (N+1 yok)."""
    _temp_keys(c, "g_front", frontier)
    score = {}
    # 1) birlikte görülme
    sc_a = sc.replace("d.scan_id", "a.scan_id")
    for r in c.execute(
            f"SELECT b.dev_key AS k, COUNT(*) AS w FROM temp.g_front f"
            f"  JOIN scan_devices a ON a.dev_key=f.dev_key"
            f"  JOIN scan_devices b ON b.scan_id=a.scan_id AND b.dev_key<>a.dev_key"
            f" WHERE 1{sc_a} GROUP BY a.dev_key, b.dev_key HAVING w>=?", (together,)):
        score[r["k"]] = max(score.get(r["k"], 0), 1000 + r["w"])
    # 2) öznitelik paylaşımı (aynı SSID / /24 / operatör+LAC / org)
    lat = _latest(c, "g_front", sc)
    ssids, prefs, orgs = set(), set(), set()
    for k, r in lat.items():
        d = _jload(r["data"])
        s = _ssid(r["type"], d)
        if s: ssids.add(s)
        ip = _ipv4_of_key(k)
        if ip:
            prefs.add("ip:" + ".".join(ip.split(".")[:3]) + ".")
            o = _org(k, d)
            if o: orgs.add(o)
        lac = _lac(k)
        if lac:
            prefs.add("cell:" + lac + ":")
    found = set()
    if ssids:
        c.execute("DROP TABLE IF EXISTS temp.g_ssid")
        c.execute("CREATE TEMP TABLE g_ssid(name TEXT PRIMARY KEY)")
        c.executemany("INSERT OR IGNORE INTO g_ssid VALUES(?)", [(s,) for s in ssids])
        found.update(r[0] for r in c.execute(
            f"SELECT DISTINCT d.dev_key FROM scan_devices d"
            f" WHERE d.name IN (SELECT name FROM temp.g_ssid) AND lower(d.type) IN ({','.join('?' * len(SSID_TYPES))}){sc}",
            SSID_TYPES))
    if prefs:
        c.execute("DROP TABLE IF EXISTS temp.g_pref")
        c.execute("CREATE TEMP TABLE g_pref(lo TEXT PRIMARY KEY, hi TEXT)")
        # '.'→'/' ve ':'→';' bir sonraki ASCII karakter: [lo, hi) aralığı indeksle taranır
        c.executemany("INSERT OR IGNORE INTO g_pref VALUES(?,?)", [(x, x[:-1] + chr(ord(x[-1]) + 1)) for x in prefs])
        found.update(r[0] for r in c.execute(
            f"SELECT DISTINCT d.dev_key FROM temp.g_pref p"
            f"  JOIN scan_devices d ON d.dev_key>=p.lo AND d.dev_key<p.hi WHERE 1{sc}"))
    if orgs:
        c.execute("DROP TABLE IF EXISTS temp.g_org")
        c.execute("CREATE TEMP TABLE g_org(org TEXT PRIMARY KEY)")
        c.executemany("INSERT OR IGNORE INTO g_org VALUES(?)", [(o,) for o in orgs])
        found.update(r[0] for r in c.execute(
            f"SELECT DISTINCT d.dev_key FROM scan_devices d"
            f" WHERE d.dev_key>='ip:' AND d.dev_key<'ip;'"
            f"   AND json_valid(d.data) AND trim(json_extract(d.data,'$.org')) IN (SELECT org FROM temp.g_org){sc}"))
    for k in found:
        score.setdefault(k, 1)
    return score


def _ego(c, p, sc):
    key = p["key"]
    if not c.execute(f"SELECT 1 FROM scan_devices d WHERE d.dev_key=?{sc} LIMIT 1", (key,)).fetchone():
        raise BadRequest("device not found" + (" in the selected scope" if sc else ""), 404)
    level = {key: 0}
    order = [key]
    frontier = [key]
    truncated = False
    for lvl in range(1, p["depth"] + 1):
        if not frontier or len(order) >= p["limit"]:
            truncated = truncated or bool(frontier and lvl <= p["depth"] and len(order) >= p["limit"])
            break
        cand = _neighbors(c, frontier[:MAX_FRONTIER], p["together"], sc)
        if len(frontier) > MAX_FRONTIER:
            truncated = True
        new = sorted((k for k in cand if k not in level), key=lambda k: (-cand[k], k))
        room = p["limit"] - len(order)
        if len(new) > room:
            truncated = True
            new = new[:room]
        for k in new:
            level[k] = lvl
        order.extend(new)
        frontier = new
    return order, level, truncated


# ── Grafik inşası ────────────────────────────────────────
def _build(c, keys, p, sc, level=None):
    _temp_keys(c, "g_keys", keys)
    nodes, edges = [], []
    # cihaz özetleri
    agg = {r["k"]: r for r in c.execute(
        f"SELECT d.dev_key AS k, COUNT(*) AS n, MAX(d.risk) AS risk, MIN(s.created_at) AS first_seen,"
        f"       MAX(s.created_at) AS last_seen, GROUP_CONCAT(DISTINCT d.source) AS sources,"
        f"       GROUP_CONCAT(DISTINCT s.kind) AS kinds"
        f"  FROM temp.g_keys t JOIN scan_devices d ON d.dev_key=t.dev_key JOIN scans s ON s.id=d.scan_id"
        f" WHERE 1{sc} GROUP BY d.dev_key")}
    lat = _latest(c, "g_keys", sc)
    prof = {r["dev_key"]: r["name"] for r in c.execute(
        "SELECT p.dev_key, p.name FROM profiles p JOIN temp.g_keys t ON t.dev_key=p.dev_key WHERE p.name<>''")}
    fl_sql = "SELECT f.case_id, f.dev_key, f.label, f.color FROM flags f JOIN temp.g_keys t ON t.dev_key=f.dev_key"
    fl_args = ()
    if p["case_id"] is not None:
        fl_sql += " WHERE f.case_id=?"; fl_args = (p["case_id"],)
    flags = c.execute(fl_sql, fl_args).fetchall()
    dev_flags = {}
    for f in flags:
        dev_flags.setdefault(f["dev_key"], []).append({"case_id": f["case_id"], "label": f["label"] or "", "color": f["color"] or "red"})

    attrs = {"ssid": {}, "net24": {}, "operator_lac": {}, "org": {}}
    present = []
    for k in keys:
        a = agg.get(k); l = lat.get(k)
        if not a or not l:
            continue
        present.append(k)
        data = _jload(l["data"])
        t = (l["type"] or "").lower() or ("vessel" if k.startswith("mmsi:") else "aircraft" if k.startswith("icao:") else "unknown")
        name = prof.get(k) or (l["name"] if l["name"] and l["name"] != "?" else None) or k
        if k.startswith("cell:") and k not in prof and str(name) == str(data.get("cell_id")):
            op = data.get("operator")
            name = f"{op if isinstance(op, str) and op.strip() else 'Cell'} #{name}"   # çıplak hücre kimliği yerine
        nd = {
            "id": k, "key": k, "group": "device", "type": t, "label": str(name)[:80],
            "risk": int(a["risk"] or 0), "count": int(a["n"] or 0),
            "first_seen": a["first_seen"], "last_seen": a["last_seen"],
            "sources": sorted({s for s in (a["sources"] or "").split(",") if s}),
            "kinds": sorted({s for s in (a["kinds"] or "").split(",") if s}),
            "lat": l["lat"], "lon": l["lon"],
        }
        if k in prof: nd["profile"] = prof[k]
        if k in dev_flags:
            fs = dev_flags[k]
            nd["flagged"] = True
            nd["flags"] = fs
            nd["flag_label"] = next((f["label"] for f in fs if f["label"]), "")
            nd["flag_color"] = fs[0]["color"]
        if level is not None:
            nd["level"] = level.get(k)
            if level.get(k) == 0: nd["focus"] = True
        for fld in ("operator", "radio", "org", "encryption", "port", "vendor", "manufacturer"):
            v = data.get(fld)
            if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v).strip():
                nd.setdefault("meta", {})[fld] = str(v)[:120]
        nodes.append({"data": nd})
        s = _ssid(t, data)
        if s: attrs["ssid"].setdefault(s, []).append(k)
        n24 = _net24(k)
        if n24: attrs["net24"].setdefault(n24, []).append(k)
        lac = _lac(k)
        if lac: attrs["operator_lac"].setdefault(lac, []).append((k, data.get("operator")))
        o = _org(k, data)
        if o: attrs["org"].setdefault(o, []).append(k)

    # öznitelik düğümleri (≥2 cihaz paylaşıyorsa)
    rel_of = {"ssid": "broadcasts", "net24": "in_net", "operator_lac": "in_lac", "org": "org"}
    prefix = {"ssid": "ssid:", "net24": "net24:", "operator_lac": "lac:", "org": "org:"}
    for g, groups in attrs.items():
        for val, members in groups.items():
            if len(members) < 2:
                continue
            nid = prefix[g] + val
            label = val
            nd = {"id": nid, "group": g, "type": g, "label": label[:MAX_ATTR], "value": val, "count": len(members)}
            if g == "operator_lac":
                mcc, mnc, lacv = (val.split(":") + ["", "", ""])[:3]
                ops = sorted({str(o) for _, o in members if o})
                nd.update(mcc=mcc, mnc=mnc, lac=lacv, operator=ops[0] if ops else "")
                nd["label"] = f"{ops[0] + ' ' if ops else ''}LAC {lacv} ({mcc}/{mnc})"[:MAX_ATTR]
                members = [m for m, _ in members]
            nodes.append({"data": nd})
            rel = rel_of[g]
            for m in members:
                edges.append({"data": {"id": f"{rel}|{m}|{nid}", "source": m, "target": nid, "rel": rel, "weight": 1, "label": ""}})

    # g_sd: seçili anahtarların kapsam içi görülmeleri → self-join ve vaka kenarları bunun üzerinde
    c.execute("DROP TABLE IF EXISTS temp.g_sd")
    c.execute(f"CREATE TEMP TABLE g_sd AS SELECT d.scan_id AS scan_id, d.dev_key AS dev_key"
              f"  FROM temp.g_keys t JOIN scan_devices d ON d.dev_key=t.dev_key WHERE 1{sc}")
    c.execute("CREATE INDEX temp.g_sd_ix ON g_sd(scan_id, dev_key)")

    # seen_with
    seen = c.execute(
        "SELECT a.dev_key AS s, b.dev_key AS t, COUNT(*) AS w FROM temp.g_sd a"
        "  JOIN temp.g_sd b ON b.scan_id=a.scan_id AND b.dev_key>a.dev_key"
        " GROUP BY a.dev_key, b.dev_key HAVING w>=? ORDER BY w DESC, s, t LIMIT ?",
        (p["together"], MAX_SEEN_EDGES + 1)).fetchall()
    edges_trunc = len(seen) > MAX_SEEN_EDGES
    for r in seen[:MAX_SEEN_EDGES]:
        edges.append({"data": {"id": f"seen_with|{r['s']}|{r['t']}", "source": r["s"], "target": r["t"],
                               "rel": "seen_with", "weight": r["w"], "label": f"{r['w']}×"}})

    # vakalar
    inc = {}
    for r in c.execute("SELECT a.dev_key AS k, s.case_id AS cid, COUNT(*) AS n FROM temp.g_sd a"
                       "  JOIN scans s ON s.id=a.scan_id WHERE s.case_id IS NOT NULL GROUP BY a.dev_key, s.case_id"):
        inc[(r["k"], r["cid"])] = r["n"]
    present_set = set(present)
    flagged_pairs = {(f["dev_key"], f["case_id"]): f for f in flags if f["dev_key"] in present_set}
    for pair in flagged_pairs:
        inc.setdefault(pair, 0)
    if p["case_id"] is not None:
        inc = {pc: n for pc, n in inc.items() if pc[1] == p["case_id"]}
    case_ids = sorted({cid for _, cid in inc})
    if case_ids:
        cases = {}
        c.execute("DROP TABLE IF EXISTS temp.g_cases")
        c.execute("CREATE TEMP TABLE g_cases(id INTEGER PRIMARY KEY)")
        c.executemany("INSERT INTO g_cases VALUES(?)", [(i,) for i in case_ids])
        for r in c.execute("SELECT c.id, c.name, c.status, (SELECT COUNT(*) FROM scans s WHERE s.case_id=c.id) AS scans"
                           "  FROM cases c JOIN temp.g_cases g ON g.id=c.id"):
            cases[r["id"]] = r
        for cid in case_ids:
            r = cases.get(cid)
            if not r:
                continue
            nodes.append({"data": {"id": f"case:{cid}", "group": "case", "type": "case", "case_id": cid,
                                   "label": str(r["name"])[:80], "status": r["status"], "count": r["scans"]}})
        for (k, cid), n in sorted(inc.items()):
            if cid not in cases or k not in present_set:
                continue
            fl = flagged_pairs.get((k, cid))
            ed = {"id": f"in_case|{k}|case:{cid}", "source": k, "target": f"case:{cid}", "rel": "in_case",
                  "weight": n, "label": "flagged" if fl else ""}
            if fl:
                ed["flagged"] = True
                ed["flag_color"] = fl["color"] or "red"
            edges.append({"data": ed})
    return nodes, edges, edges_trunc, len(present)


def build_graph(p):
    t0 = time.perf_counter()
    with store.db() as c:
        db_scans = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        if p["case_id"] is not None and not c.execute("SELECT 1 FROM cases WHERE id=?", (p["case_id"],)).fetchone():
            raise BadRequest("case not found", 404)
        sc = _scope(c, p)
        level = None
        if p["key"]:
            keys, level, truncated = _ego(c, p, sc)
            mode = "ego"
        else:
            mode = "case" if p["case_id"] is not None else "all"
            fl_sql = "SELECT DISTINCT dev_key FROM flags" + (" WHERE case_id=?" if p["case_id"] is not None else "")
            flagged = [r[0] for r in c.execute(fl_sql, (p["case_id"],) if p["case_id"] is not None else ())]
            _temp_keys(c, "g_flag", flagged)
            rs = c.execute(
                f"SELECT d.dev_key AS k, MAX(d.risk) AS risk, COUNT(*) AS n FROM scan_devices d WHERE 1{sc}"
                f" GROUP BY d.dev_key"
                f" ORDER BY (d.dev_key IN (SELECT dev_key FROM temp.g_flag)) DESC, risk DESC, n DESC, d.dev_key"
                f" LIMIT ?", (p["limit"] + 1,)).fetchall()
            truncated = len(rs) > p["limit"]
            keys = [r["k"] for r in rs[:p["limit"]]]
        nodes, edges, edges_trunc, ndev = _build(c, keys, p, sc, level) if keys else ([], [], False, 0)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    return {"nodes": nodes, "edges": edges,
            "stats": {"nodes": len(nodes), "edges": len(edges), "devices": ndev, "truncated": bool(truncated),
                      "edges_truncated": edges_trunc, "mode": mode, "focus": p["key"], "case_id": p["case_id"],
                      "depth": p["depth"] if p["key"] else None, "min_together": p["together"],
                      "limit": p["limit"], "kinds": p["kinds"], "since": p["since"],
                      "db_scans": db_scans, "ms": ms}}


# ── Rotalar ──────────────────────────────────────────────
@bp.route("/graph")
def graph_page():
    return render_template("graph.html", active="Cases")


def api_graph():
    return jsonify(build_graph(_params()))


def init(app, ctx):
    if "graph" in app.blueprints:
        return
    rl = getattr(ctx, "rate_limit", None) or (lambda spec: (lambda f: f))
    bp.add_url_rule("/api/graph", "api_graph", rl("120 per minute")(api_graph), methods=["GET"])
    app.register_blueprint(bp)
