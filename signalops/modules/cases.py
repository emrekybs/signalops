"""
SignalOps — Vakalar (Cases), kayıtlı taramalar, notlar, işaretler, cihaz korelasyonu, sunucu profilleri.

Sayfa
  GET  /cases                                  vaka çalışma alanı (templates/cases.html)

Vakalar
  GET    /api/cases                            liste (+ scan_count, flag_count, note_count, last_scan_at)
  POST   /api/cases                            {name, description?}
  GET    /api/cases/<id>                       vaka + taramalar (cihazsız) + notlar + işaretler
  PATCH  /api/cases/<id>                       {name?, description?, status? open|closed}
  DELETE /api/cases/<id>                       taramalar kalır (case_id → NULL)

Taramalar
  POST   /api/scans                            {kind, devices, lat?, lon?, case_id?, label?, params?} → {scan, diff}
  GET    /api/scans?case_id=&kind=&unassigned=1&limit=&offset=
  GET    /api/scans/<id>                       cihazlarla birlikte (+ prev_id)
  PATCH  /api/scans/<id>                       {case_id? (null = vakadan çıkar), label?}
  DELETE /api/scans/<id>
  GET    /api/scans/<id>/diff?against=<id>&summary=1

Notlar / işaretler
  POST   /api/cases/<id>/notes                 {body, scan_id?, dev_key?}
  DELETE /api/notes/<id>
  POST   /api/cases/<id>/flags                 {dev_key, label?, color?, data?}   (upsert)
  DELETE /api/cases/<id>/flags/<path:dev_key>

Korelasyon / profiller
  GET    /api/devices/history?key=<dev_key>
  GET    /api/profiles
  POST   /api/profiles                         {device:{…}, name?, note?}  (anahtar = store.device_key, upsert)
  PATCH  /api/profiles?key=                    {name?, note?}
  DELETE /api/profiles?key=
"""
import json, math
from flask import Blueprint, request, jsonify, render_template

from . import store

bp = Blueprint("cases", __name__)

SCAN_KINDS = ("nearby", "cctv", "cell", "adsb", "ais", "search", "other")
CASE_STATUS = ("open", "closed")
FLAG_COLORS = ("red", "amber", "green", "blue", "purple", "grey")
MAX_NAME = 200
MAX_TEXT = 5000
MAX_KEY = 300
MAX_JSON_SMALL = 20000          # params / flag data / profile device (serileştirilmiş karakter)
MAX_BODY_BYTES = 64 * 1024 * 1024


class BadRequest(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


@bp.errorhandler(BadRequest)
def _bad(e):
    return jsonify({"error": e.msg}), e.code


def _err(msg, code=400):
    return jsonify({"error": msg}), code


# ── Girdi doğrulama ──────────────────────────────────────
def _body():
    if request.content_length and request.content_length > MAX_BODY_BYTES:
        raise BadRequest("Request body too large", 413)
    b = request.get_json(silent=True)
    if not isinstance(b, dict):
        raise BadRequest("JSON object body required (Content-Type: application/json)")
    return b


def _str(b, key, maxlen, required=False, default=None):
    if key not in b or b[key] is None:
        if required:
            raise BadRequest(f"'{key}' is required")
        return default
    v = b[key]
    if not isinstance(v, str):
        raise BadRequest(f"'{key}' must be a string")
    v = v.strip()
    if required and not v:
        raise BadRequest(f"'{key}' must not be empty")
    if len(v) > maxlen:
        raise BadRequest(f"'{key}' too long (max {maxlen} characters)")
    return v


def _id(v, name):
    """Pozitif tamsayı kimlik (bool reddedilir). None → None."""
    if v is None:
        return None
    if isinstance(v, bool):
        raise BadRequest(f"'{name}' must be an integer")
    if isinstance(v, str) and v.strip().isdigit():
        v = int(v.strip())
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    if not isinstance(v, int) or v <= 0 or v > 2**62:
        raise BadRequest(f"'{name}' must be a positive integer")
    return v


def _coord(v, name, lo, hi):
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        raise BadRequest(f"'{name}' must be a number")
    try:
        x = float(v)
    except (TypeError, ValueError):
        raise BadRequest(f"'{name}' must be a number")
    if not math.isfinite(x) or not (lo <= x <= hi):
        raise BadRequest(f"'{name}' out of range")
    return x


def _small_json(v, name, kind=dict):
    if v is None:
        return None
    if not isinstance(v, kind):
        raise BadRequest(f"'{name}' must be an {'object' if kind is dict else 'array'}")
    try:
        s = json.dumps(v, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        raise BadRequest(f"'{name}' is not serializable")
    if len(s) > MAX_JSON_SMALL:
        raise BadRequest(f"'{name}' too large")
    return v


def _arg_id(name):
    v = request.args.get(name)
    if v in (None, ""):
        return None
    return _id(v, name)


def _arg_key():
    k = (request.args.get("key") or "").strip()
    if not k:
        raise BadRequest("'key' query parameter required")
    if len(k) > MAX_KEY:
        raise BadRequest("'key' too long")
    return k


def _case_exists(c, case_id):
    return c.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone() is not None


def _require_case(case_id):
    with store.db() as c:
        if not _case_exists(c, case_id):
            raise BadRequest("case not found", 404)


# ── Sayfa ────────────────────────────────────────────────
@bp.route("/cases")
def cases_page():
    return render_template("cases.html", active="Cases")


# ── Vakalar ──────────────────────────────────────────────
_CASE_LIST_SQL = """
SELECT c.*,
  (SELECT COUNT(*) FROM scans s WHERE s.case_id=c.id)        AS scan_count,
  (SELECT COUNT(*) FROM flags f WHERE f.case_id=c.id)        AS flag_count,
  (SELECT COUNT(*) FROM notes n WHERE n.case_id=c.id)        AS note_count,
  (SELECT MAX(created_at) FROM scans s WHERE s.case_id=c.id) AS last_scan_at
FROM cases c
"""


@bp.route("/api/cases", methods=["GET"])
def list_cases():
    with store.db() as c:
        cases = store.rows(c.execute(_CASE_LIST_SQL + " ORDER BY (c.status='closed'), c.updated_at DESC, c.id DESC"))
        un = c.execute("SELECT COUNT(*) AS n, MAX(created_at) AS last FROM scans WHERE case_id IS NULL").fetchone()
    return jsonify({"cases": cases, "unassigned": {"scan_count": un["n"], "last_scan_at": un["last"]}})


@bp.route("/api/cases", methods=["POST"])
def create_case():
    b = _body()
    name = _str(b, "name", MAX_NAME, required=True)
    desc = _str(b, "description", MAX_TEXT, default="")
    t = store.now()
    with store.db() as c:
        cid = c.execute("INSERT INTO cases(name, description, status, created_at, updated_at) VALUES(?,?,?,?,?)",
                        (name, desc, "open", t, t)).lastrowid
        case = store.row(c.execute(_CASE_LIST_SQL + " WHERE c.id=?", (cid,)).fetchone())
    return jsonify({"case": case}), 201


@bp.route("/api/cases/<int:case_id>", methods=["GET"])
def get_case(case_id):
    with store.db() as c:
        case = store.row(c.execute(_CASE_LIST_SQL + " WHERE c.id=?", (case_id,)).fetchone())
        if not case:
            return _err("case not found", 404)
        scans = store.rows(c.execute("SELECT * FROM scans WHERE case_id=? ORDER BY created_at DESC, id DESC", (case_id,)))
        notes = store.rows(c.execute("SELECT * FROM notes WHERE case_id=? ORDER BY created_at DESC, id DESC", (case_id,)))
        flags = store.rows(c.execute(
            "SELECT f.*, (SELECT MAX(name) FROM scan_devices d WHERE d.dev_key=f.dev_key) AS name,"
            " (SELECT MAX(type) FROM scan_devices d WHERE d.dev_key=f.dev_key) AS type"
            " FROM flags f WHERE f.case_id=? ORDER BY f.created_at DESC", (case_id,)))
    return jsonify({"case": case, "scans": scans, "notes": notes, "flags": flags})


@bp.route("/api/cases/<int:case_id>", methods=["PATCH"])
def update_case(case_id):
    b = _body()
    sets, vals = [], []
    name = _str(b, "name", MAX_NAME)
    if name is not None:
        if not name:
            raise BadRequest("'name' must not be empty")
        sets.append("name=?"); vals.append(name)
    desc = _str(b, "description", MAX_TEXT)
    if desc is not None:
        sets.append("description=?"); vals.append(desc)
    status = _str(b, "status", 10)
    if status is not None:
        if status not in CASE_STATUS:
            raise BadRequest("'status' must be 'open' or 'closed'")
        sets.append("status=?"); vals.append(status)
    if not sets:
        raise BadRequest("nothing to update (name, description, status)")
    with store.db() as c:
        if not _case_exists(c, case_id):
            return _err("case not found", 404)
        c.execute(f"UPDATE cases SET {', '.join(sets)}, updated_at=? WHERE id=?", (*vals, store.now(), case_id))
        case = store.row(c.execute(_CASE_LIST_SQL + " WHERE c.id=?", (case_id,)).fetchone())
    return jsonify({"case": case})


@bp.route("/api/cases/<int:case_id>", methods=["DELETE"])
def delete_case(case_id):
    with store.db() as c:
        if not _case_exists(c, case_id):
            return _err("case not found", 404)
        n = c.execute("SELECT COUNT(*) FROM scans WHERE case_id=?", (case_id,)).fetchone()[0]
        c.execute("DELETE FROM cases WHERE id=?", (case_id,))
    return jsonify({"ok": True, "deleted": case_id, "scans_unassigned": n})


# ── Taramalar ────────────────────────────────────────────
@bp.route("/api/scans", methods=["POST"])
def create_scan():
    b = _body()
    kind = b.get("kind")
    if kind not in SCAN_KINDS:
        raise BadRequest(f"'kind' must be one of: {', '.join(SCAN_KINDS)}")
    devices = b.get("devices")
    if not isinstance(devices, list):
        raise BadRequest("'devices' must be an array")
    if len(devices) > store.MAX_DEVICES_PER_SCAN:
        raise BadRequest(f"too many devices (max {store.MAX_DEVICES_PER_SCAN})")
    if any(not isinstance(d, dict) for d in devices):
        raise BadRequest("every device must be an object")
    lat = _coord(b.get("lat"), "lat", -90, 90)
    lon = _coord(b.get("lon"), "lon", -180, 180)
    if (lat is None) != (lon is None):
        raise BadRequest("'lat' and 'lon' must be given together")
    case_id = _id(b.get("case_id"), "case_id")
    label = _str(b, "label", MAX_NAME, default="")
    params = _small_json(b.get("params"), "params") or {}
    if case_id:
        _require_case(case_id)
    clean = []
    for d in devices:
        if "_key" in d:                     # sayfa içi geçici anahtar — kalıcı kimlik store.device_key
            d = {k: v for k, v in d.items() if k != "_key"}
        clean.append(d)
    scan = store.save_scan(kind, clean, lat, lon, case_id=case_id, label=label, params=params)
    diff = store.diff_scans(scan["id"])
    return jsonify({"scan": scan, "diff": diff}), 201


@bp.route("/api/scans", methods=["GET"])
def list_scans():
    where, vals = [], []
    case_id = _arg_id("case_id")
    if case_id:
        where.append("s.case_id=?"); vals.append(case_id)
    if request.args.get("unassigned") in ("1", "true"):
        where.append("s.case_id IS NULL")
    kind = request.args.get("kind")
    if kind:
        if kind not in SCAN_KINDS:
            raise BadRequest(f"'kind' must be one of: {', '.join(SCAN_KINDS)}")
        where.append("s.kind=?"); vals.append(kind)
    try:
        limit = max(1, min(1000, int(request.args.get("limit", 200))))
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        raise BadRequest("'limit'/'offset' must be integers")
    sql = ("SELECT s.*, c.name AS case_name FROM scans s LEFT JOIN cases c ON c.id=s.case_id"
           + (" WHERE " + " AND ".join(where) if where else "")
           + " ORDER BY s.created_at DESC, s.id DESC LIMIT ? OFFSET ?")
    with store.db() as c:
        scans = store.rows(c.execute(sql, (*vals, limit, offset)))
    return jsonify({"scans": scans})


@bp.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    s = store.get_scan(scan_id)
    if not s:
        return _err("scan not found", 404)
    s["prev_id"] = store.previous_scan_id(scan_id)
    if s.get("case_id"):
        with store.db() as c:
            r = c.execute("SELECT name FROM cases WHERE id=?", (s["case_id"],)).fetchone()
            s["case_name"] = r["name"] if r else None
    return jsonify({"scan": s})


@bp.route("/api/scans/<int:scan_id>", methods=["PATCH"])
def update_scan(scan_id):
    b = _body()
    sets, vals = [], []
    touched = set()
    if "case_id" in b:
        cid = _id(b.get("case_id"), "case_id")
        if cid:
            _require_case(cid)
        sets.append("case_id=?"); vals.append(cid)
        touched.add(cid)
    label = _str(b, "label", MAX_NAME)
    if label is not None:
        sets.append("label=?"); vals.append(label)
    if not sets:
        raise BadRequest("nothing to update (case_id, label)")
    with store.db() as c:
        old = c.execute("SELECT case_id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not old:
            return _err("scan not found", 404)
        c.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id=?", (*vals, scan_id))
        for cid in touched | {old["case_id"]}:
            if cid:
                c.execute("UPDATE cases SET updated_at=? WHERE id=?", (store.now(), cid))
        s = store.row(c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
    return jsonify({"scan": s})


@bp.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    with store.db() as c:
        if not c.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone():
            return _err("scan not found", 404)
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    return jsonify({"ok": True, "deleted": scan_id})


@bp.route("/api/scans/<int:scan_id>/diff", methods=["GET"])
def scan_diff(scan_id):
    against = _arg_id("against")
    with store.db() as c:
        if not c.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone():
            return _err("scan not found", 404)
        if against and not c.execute("SELECT 1 FROM scans WHERE id=?", (against,)).fetchone():
            return _err("comparison scan not found", 404)
    if against == scan_id:
        raise BadRequest("cannot compare a scan with itself")
    d = store.diff_scans(scan_id, against)
    if request.args.get("summary") in ("1", "true"):
        d = {"new_scan": d["new_scan"], "old_scan": d["old_scan"], "counts": d["counts"]}
    return jsonify(d)


# ── Notlar ───────────────────────────────────────────────
@bp.route("/api/cases/<int:case_id>/notes", methods=["POST"])
def add_note(case_id):
    b = _body()
    body = _str(b, "body", MAX_TEXT, required=True)
    scan_id = _id(b.get("scan_id"), "scan_id")
    dev_key = _str(b, "dev_key", MAX_KEY) or None
    with store.db() as c:
        if not _case_exists(c, case_id):
            return _err("case not found", 404)
        if scan_id and not c.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone():
            return _err("scan not found", 404)
        nid = c.execute("INSERT INTO notes(case_id, scan_id, dev_key, body, created_at) VALUES(?,?,?,?,?)",
                        (case_id, scan_id, dev_key, body, store.now())).lastrowid
        c.execute("UPDATE cases SET updated_at=? WHERE id=?", (store.now(), case_id))
        note = store.row(c.execute("SELECT * FROM notes WHERE id=?", (nid,)).fetchone())
    return jsonify({"note": note}), 201


@bp.route("/api/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    with store.db() as c:
        if not c.execute("SELECT 1 FROM notes WHERE id=?", (note_id,)).fetchone():
            return _err("note not found", 404)
        c.execute("DELETE FROM notes WHERE id=?", (note_id,))
    return jsonify({"ok": True, "deleted": note_id})


# ── İşaretler ────────────────────────────────────────────
@bp.route("/api/cases/<int:case_id>/flags", methods=["POST"])
def add_flag(case_id):
    b = _body()
    dev_key = _str(b, "dev_key", MAX_KEY, required=True)
    label = _str(b, "label", MAX_NAME, default="")
    color = _str(b, "color", 10, default="red") or "red"
    if color not in FLAG_COLORS:
        raise BadRequest(f"'color' must be one of: {', '.join(FLAG_COLORS)}")
    data = _small_json(b.get("data"), "data") or {}
    with store.db() as c:
        if not _case_exists(c, case_id):
            return _err("case not found", 404)
        c.execute("INSERT INTO flags(case_id, dev_key, label, color, data, created_at) VALUES(?,?,?,?,?,?)"
                  " ON CONFLICT(case_id, dev_key) DO UPDATE SET label=excluded.label, color=excluded.color, data=excluded.data",
                  (case_id, dev_key, label, color, json.dumps(data, ensure_ascii=False, default=str), store.now()))
        c.execute("UPDATE cases SET updated_at=? WHERE id=?", (store.now(), case_id))
        flag = store.row(c.execute("SELECT * FROM flags WHERE case_id=? AND dev_key=?", (case_id, dev_key)).fetchone())
    return jsonify({"flag": flag}), 201


@bp.route("/api/cases/<int:case_id>/flags/<path:dev_key>", methods=["DELETE"])
def delete_flag(case_id, dev_key):
    with store.db() as c:
        if not _case_exists(c, case_id):
            return _err("case not found", 404)
        n = c.execute("DELETE FROM flags WHERE case_id=? AND dev_key=?", (case_id, dev_key)).rowcount
    if not n:
        return _err("flag not found", 404)
    return jsonify({"ok": True})


# ── Cihaz korelasyonu ────────────────────────────────────
@bp.route("/api/devices/history", methods=["GET"])
def device_history():
    key = _arg_key()
    h = store.device_history(key)
    if not h["sightings"] and not h["profile"] and not h["flags"]:
        return _err("device not found", 404)
    return jsonify(h)


# ── Profiller ────────────────────────────────────────────
@bp.route("/api/profiles", methods=["GET"])
def list_profiles():
    with store.db() as c:
        ps = store.rows(c.execute("SELECT * FROM profiles ORDER BY updated_at DESC, created_at DESC"))
    return jsonify({"profiles": ps})


@bp.route("/api/profiles", methods=["POST"])
def save_profile():
    b = _body()
    dev = _small_json(b.get("device"), "device")
    if not dev:
        raise BadRequest("'device' object required")
    key = store.device_key(dev)
    if not key:
        raise BadRequest("device has no stable identifier (bssid/mac, ip, cell_id, icao, mmsi or coordinates)")
    name = _str(b, "name", MAX_NAME)
    note = _str(b, "note", MAX_TEXT)
    dev = {k: v for k, v in dev.items() if k != "_key"}
    t = store.now()
    created = t
    sa = dev.get("saved_at")          # eski localStorage profilleri: ms epoch
    if isinstance(sa, (int, float)) and not isinstance(sa, bool) and math.isfinite(sa) and sa > 0:
        sa = int(sa / 1000) if sa > 1e11 else int(sa)
        if 946684800 <= sa <= t + 86400:
            created = sa
    with store.db() as c:
        existed = c.execute("SELECT 1 FROM profiles WHERE dev_key=?", (key,)).fetchone() is not None
        c.execute("INSERT INTO profiles(dev_key, name, note, data, created_at, updated_at) VALUES(?,?,?,?,?,?)"
                  " ON CONFLICT(dev_key) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at"
                  + (", name=excluded.name" if name is not None else "")
                  + (", note=excluded.note" if note is not None else ""),
                  (key, name or "", note or "", json.dumps(dev, ensure_ascii=False, default=str), created, t))
        p = store.row(c.execute("SELECT * FROM profiles WHERE dev_key=?", (key,)).fetchone())
    return jsonify({"profile": p, "created": not existed}), (200 if existed else 201)


@bp.route("/api/profiles", methods=["PATCH"])
def update_profile():
    key = _arg_key()
    b = _body()
    sets, vals = [], []
    name = _str(b, "name", MAX_NAME)
    if name is not None:
        sets.append("name=?"); vals.append(name)
    note = _str(b, "note", MAX_TEXT)
    if note is not None:
        sets.append("note=?"); vals.append(note)
    if not sets:
        raise BadRequest("nothing to update (name, note)")
    with store.db() as c:
        if not c.execute("SELECT 1 FROM profiles WHERE dev_key=?", (key,)).fetchone():
            return _err("profile not found", 404)
        c.execute(f"UPDATE profiles SET {', '.join(sets)}, updated_at=? WHERE dev_key=?", (*vals, store.now(), key))
        p = store.row(c.execute("SELECT * FROM profiles WHERE dev_key=?", (key,)).fetchone())
    return jsonify({"profile": p})


@bp.route("/api/profiles", methods=["DELETE"])
def delete_profile():
    key = _arg_key()
    with store.db() as c:
        n = c.execute("DELETE FROM profiles WHERE dev_key=?", (key,)).rowcount
    if not n:
        return _err("profile not found", 404)
    return jsonify({"ok": True})


def init(app, ctx):
    app.register_blueprint(bp)
