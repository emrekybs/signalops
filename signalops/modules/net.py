"""
SignalOps — Ağ / OPSEC: Tor veya SOCKS/HTTP proxy (isteğe bağlı, kullanıcı kontrolünde).

Modlar: off (varsayılan) | tor | custom
* Bir mod uygulanınca backend'in `requests` ile yaptığı TÜM HTTP(S) çağrıları proxy'den geçer:
  HTTP_PROXY / HTTPS_PROXY / ALL_PROXY (+ küçük harf) ortam değişkenleri ayarlanır, requests
  bunları her çağrıda okur. NO_PROXY=localhost,127.0.0.1,::1. SOCKS için socks5h (DNS de proxy'den).
* "off" → başlangıçtaki ortam değerleri geri yüklenir (kurumsal proxy vb. bozulmasın).
* Seçim config_dir/net.json'da saklanır (atomik yazım, 0600) ve açılışta uygulanır.
* Tor: 127.0.0.1:9050'de sistem tor'u varsa o kullanılır; yoksa `tor` ikilisi bulunursa
  kendi tor'umuz 127.0.0.1:9052'de başlatılır. Sadece bizim başlattığımız durdurulur.
* AIS (aisstream websocket) ws_connect() üzerinden aynı proxy'yi kullanır.
"""
import atexit
import collections
import importlib.util
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from flask import Blueprint, jsonify, request

PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy")
NO_PROXY = "localhost,127.0.0.1,::1"
SYSTEM_TOR_PORT = 9050
OUR_TOR_PORT = 9052
CHECK_URL = "https://check.torproject.org/api/ip"
MODES = ("off", "tor", "custom")
_SCHEMES = ("socks5", "socks5h", "http", "https")

_ORIG_ENV = {k: os.environ.get(k) for k in PROXY_VARS}   # açılıştaki değerler ("off" bunlara döner)
_lock = threading.RLock()
_ctx = None
_cfg_path = None
_state = {"mode": "off", "url": "", "proxy": None, "error": None}
_last_check = {"result": None}
_tor = {"proc": None, "pid": None, "bootstrap": 0, "log": collections.deque(maxlen=60),
        "started_at": None, "error": None}

bp = Blueprint("net", __name__)


# ── yardımcılar ───────────────────────────────
def have_pysocks():
    return importlib.util.find_spec("socks") is not None


def have_python_socks():
    return importlib.util.find_spec("python_socks") is not None


def have_socksio():
    return importlib.util.find_spec("socksio") is not None


def tor_binary():
    return shutil.which("tor")


def install_hint():
    if sys.platform.startswith("linux"):
        return "sudo apt install tor"
    if sys.platform == "darwin":
        return "brew install tor"
    if sys.platform.startswith("win"):
        return "Install the Tor Expert Bundle: https://www.torproject.org/download/tor/"
    return "Install tor from https://www.torproject.org/download/tor/"


def _port_open(port, host="127.0.0.1", timeout=0.3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def mask_url(u):
    """Kimlik bilgilerini gizler: socks5h://user:pass@h:p → socks5h://***@h:p"""
    if not u:
        return u
    try:
        p = urlsplit(u)
        if p.username or p.password:
            host = p.hostname or ""
            if ":" in host:
                host = f"[{host}]"
            return f"{p.scheme}://***@{host}{':' + str(p.port) if p.port else ''}"
    except ValueError:
        return "<invalid>"
    return u


def validate_url(u):
    """→ (normalize edilmiş url, None) | (None, hata)"""
    if not isinstance(u, str):
        return None, "url must be a string"
    u = u.strip()
    if not u:
        return None, "Proxy URL required"
    if len(u) > 200:
        return None, "Proxy URL too long (max 200)"
    if any(c in u for c in "\r\n\t\x00 "):
        return None, "Proxy URL contains invalid characters"
    try:
        p = urlsplit(u)
        port = p.port
    except ValueError:
        return None, "Invalid proxy URL / port"
    scheme = (p.scheme or "").lower()
    if scheme not in _SCHEMES:
        return None, "Scheme must be socks5, socks5h, http or https"
    if not p.hostname or not re.match(r"^[A-Za-z0-9.\-:\[\]_]+$", p.hostname):
        return None, "Proxy host missing or invalid"
    if port is None or not (1 <= port <= 65535):
        return None, "Proxy port (1-65535) required"
    if p.path not in ("", "/") or p.query or p.fragment:
        return None, "Proxy URL must be scheme://[user:pass@]host:port"
    if scheme == "socks5":
        scheme = "socks5h"            # DNS de proxy üzerinden (sızıntı yok)
    auth = ""
    if p.username:
        auth = p.username + (":" + p.password if p.password else "") + "@"
    host = p.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{auth}{host}:{port}", None


def _our_tor_running():
    pr = _tor["proc"]
    return pr is not None and pr.poll() is None


def tor_port():
    """tor modunda kullanılacak SOCKS portu."""
    if _our_tor_running():
        return OUR_TOR_PORT
    return SYSTEM_TOR_PORT


def _proxy_for(mode, url):
    if mode == "tor":
        return f"socks5h://127.0.0.1:{tor_port()}"
    if mode == "custom":
        return url
    return None


def _set_env(proxy):
    if proxy is None:
        for k, v in _ORIG_ENV.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        os.environ[k] = proxy
        os.environ[k.lower()] = proxy
    os.environ["NO_PROXY"] = NO_PROXY
    os.environ["no_proxy"] = NO_PROXY


def apply(mode, url=""):
    """Modu uygular (env). → (ok, hata). PySocks yoksa SOCKS reddedilir, önceki mod kalır."""
    if mode not in MODES:
        return False, "mode must be off, tor or custom"
    proxy = _proxy_for(mode, url)
    if proxy and proxy.startswith("socks") and not have_pysocks():
        return False, "PySocks is not installed — SOCKS/Tor cannot be enabled (pip install PySocks)"
    with _lock:
        _set_env(proxy)
        _state.update(mode=mode, url=url if mode == "custom" else "", proxy=proxy, error=None)
    _restart_streams()
    print(f"[net] mode={mode}" + (f" proxy={mask_url(proxy)}" if proxy else " (direct)"))
    return True, None


def _reapply_tor_port():
    with _lock:
        if _state["mode"] == "tor":
            proxy = _proxy_for("tor", "")
            if proxy != _state["proxy"]:
                _set_env(proxy)
                _state["proxy"] = proxy
                _restart_streams()


def _restart_streams():
    """Açık AIS websocket'i eski rotada kalmasın — bir sonraki /api/ais yeni rotadan bağlanır."""
    m = sys.modules.get("modules.ais")
    col = getattr(m, "COLLECTOR", None) if m else None
    if col is not None:
        try:
            col.stop()
        except Exception:
            pass


def active_proxy():
    with _lock:
        return _state["proxy"]


# ── kalıcılık ─────────────────────────────────
def save():
    if not _cfg_path:
        return
    d = os.path.dirname(_cfg_path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".net-", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"mode": _state["mode"], "url": _state["url"]}, f, indent=2)
        try: os.chmod(tmp, 0o600)
        except OSError: pass
        os.replace(tmp, _cfg_path)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def load_and_apply(autostart=True):
    """net.json'u okur ve uygular (açılışta). Bozuk/eksik → off."""
    mode, url = "off", ""
    try:
        with open(_cfg_path, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and d.get("mode") in MODES:
            mode = d["mode"]
            if mode == "custom":
                url, err = validate_url(d.get("url") or "")
                if err:
                    print(f"[net] net.json custom url invalid ({err}) — direct")
                    mode, url = "off", ""
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[net] net.json okunamadı: {e}")
    ok, err = apply(mode, url)
    if not ok:
        with _lock:
            _state["error"] = err
            _state["mode_wanted"] = mode
        print(f"[net] {mode} could not be applied: {err} — staying direct")
        apply("off")
        with _lock:
            _state["error"] = err
    elif mode == "tor" and autostart and not _port_open(SYSTEM_TOR_PORT) and tor_binary():
        threading.Thread(target=tor_start, name="tor-autostart", daemon=True).start()
    return _state["mode"]


# ── Tor süreci ────────────────────────────────
_BOOT_RE = re.compile(r"Bootstrapped (\d{1,3})%")


def _reader(proc):
    try:
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            _tor["log"].append(line[:300])
            m = _BOOT_RE.search(line)
            if m:
                _tor["bootstrap"] = min(100, int(m.group(1)))
                if _tor["bootstrap"] >= 100:
                    _reapply_tor_port()
            if "[err]" in line.lower() or "could not bind" in line.lower():
                _tor["error"] = line[-200:]
    except Exception:
        pass
    finally:
        _reapply_tor_port()


def tor_start():
    with _lock:
        if _our_tor_running():
            return {"ok": True, "ours": True, "port": OUR_TOR_PORT, "already": True}
        if _port_open(SYSTEM_TOR_PORT):
            _reapply_tor_port()
            return {"ok": True, "ours": False, "port": SYSTEM_TOR_PORT, "system": True}
        binp = tor_binary()
        if not binp:
            return {"ok": False, "error": "tor binary not found", "install_hint": install_hint()}
        if _port_open(OUR_TOR_PORT):
            return {"ok": False, "error": f"Port {OUR_TOR_PORT} is already in use by another process"}
        data_dir = os.path.join(os.path.dirname(_cfg_path) if _cfg_path else tempfile.gettempdir(), "tor-data")
        os.makedirs(data_dir, exist_ok=True)
        try: os.chmod(data_dir, 0o700)
        except OSError: pass
        # __OwningControllerProcess: SignalOps süreci ölürse (SIGKILL dahil) tor da kendini kapatır
        cmd = [binp, "--SocksPort", f"127.0.0.1:{OUR_TOR_PORT}", "--DataDirectory", data_dir,
               "--Log", "notice stdout", "--__OwningControllerProcess", str(os.getpid())]
        kw = {}
        if os.name == "posix":
            kw["start_new_session"] = True          # kendi süreç grubu
        else:
            kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, text=True, bufsize=1, **kw)
        except OSError as e:
            return {"ok": False, "error": f"tor could not be started: {type(e).__name__}"}
        _tor.update(proc=proc, pid=proc.pid, bootstrap=0, started_at=time.time(), error=None)
        _tor["log"].clear()
        threading.Thread(target=_reader, args=(proc,), name="tor-log", daemon=True).start()
    _reapply_tor_port()
    print(f"[net] tor started pid={proc.pid} port={OUR_TOR_PORT}")
    return {"ok": True, "ours": True, "port": OUR_TOR_PORT, "pid": proc.pid}


def tor_stop():
    with _lock:
        pr = _tor["proc"]
        if pr is None or pr.poll() is not None:
            _tor["proc"] = None
            if _port_open(SYSTEM_TOR_PORT):
                return {"ok": False, "error": "System tor is not managed by SignalOps — not stopped"}
            return {"ok": True, "stopped": False, "note": "SignalOps tor is not running"}
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(pr.pid), signal.SIGTERM)
            else:
                pr.terminate()
        except (ProcessLookupError, PermissionError, OSError):
            try: pr.terminate()
            except Exception: pass
        try:
            pr.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(pr.pid), signal.SIGKILL)
                else:
                    pr.kill()
            except Exception:
                pass
            try: pr.wait(timeout=3)
            except Exception: pass
        pid = pr.pid
        _tor.update(proc=None, bootstrap=0)
    _reapply_tor_port()
    print(f"[net] tor stopped pid={pid}")
    return {"ok": True, "stopped": True, "pid": pid}


@atexit.register
def _cleanup():
    try:
        if _our_tor_running():
            tor_stop()
    except Exception:
        pass


# ── WebSocket (AIS) ───────────────────────────
def ws_proxied():
    """AIS websocket'i aktif proxy'den geçebiliyor mu? (None = proxy kapalı)"""
    p = active_proxy()
    if not p:
        return None
    if p.startswith("http"):
        return True
    return have_python_socks() or have_pysocks()


def ws_connect(lib, url, timeout=10):
    """websocket-client create_connection — etkin proxy ile."""
    p = active_proxy()
    if not p:
        return lib.create_connection(url, timeout=timeout)
    pu = urlsplit(p)
    auth = (pu.username or "", pu.password or "") if pu.username else None
    if pu.scheme in ("http", "https"):
        return lib.create_connection(url, timeout=timeout, http_proxy_host=pu.hostname,
                                     http_proxy_port=pu.port, proxy_type="http", http_proxy_auth=auth)
    if have_python_socks():
        return lib.create_connection(url, timeout=timeout, http_proxy_host=pu.hostname,
                                     http_proxy_port=pu.port, proxy_type="socks5h", http_proxy_auth=auth)
    # PySocks ile önceden bağlanmış soket (DNS proxy tarafında çözülür: rdns=True)
    import socks
    tu = urlsplit(url)
    secure = tu.scheme == "wss"
    port = tu.port or (443 if secure else 80)
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, pu.hostname, pu.port, rdns=True,
                username=auth[0] if auth else None, password=auth[1] if auth else None)
    s.settimeout(timeout)
    s.connect((tu.hostname, port))
    if secure:
        s = ssl.create_default_context().wrap_socket(s, server_hostname=tu.hostname)
    return lib.create_connection(url, timeout=timeout, socket=s)


# ── durum ─────────────────────────────────────
def status():
    with _lock:
        mode, proxy, err = _state["mode"], _state["proxy"], _state["error"]
        ours = _our_tor_running()
        pid = _tor["pid"] if ours else None
        boot = _tor["bootstrap"]
        logs = list(_tor["log"])[-5:]
        tor_err = _tor["error"]
    system = (not ours) and _port_open(SYSTEM_TOR_PORT)
    port = OUR_TOR_PORT if ours else (SYSTEM_TOR_PORT if system else None)
    warnings = []
    if mode == "tor" and not ours and not system:
        warnings.append("Tor mode is on but no Tor is listening — outbound API calls will fail until Tor runs.")
    if mode == "tor" and ours and boot < 100:
        warnings.append(f"Tor is bootstrapping ({boot}%) — calls may fail until 100%.")
    ais = ws_proxied()
    if proxy and proxy.startswith("socks") and not have_socksio():
        warnings.append("Gemini (google-genai/httpx) needs 'socksio' for SOCKS — AI calls may fail (pip install socksio).")
    return {
        "mode": mode,
        "proxy_url": mask_url(proxy) if proxy else None,
        "custom_url": mask_url(_state["url"]) if _state["url"] else "",
        "pysocks": have_pysocks(),
        "error": err,
        "tor": {"binary": tor_binary(), "running": bool(ours or system), "ours": ours, "system": system,
                "pid": pid, "port": port, "bootstrap": (boot if ours else (100 if system else 0)),
                "last_log_lines": logs, "error": tor_err if ours or tor_err else None,
                "install_hint": None if tor_binary() else install_hint()},
        "ais": {"proxied": ais, "note": ("not proxied (direct)" if ais is False else
                                         "via proxy" if ais else "direct (proxy off)")},
        "check": {"last_result": _last_check["result"]},
        "warnings": warnings,
        "no_proxy": NO_PROXY,
    }


def check_exit():
    import requests
    t0 = time.time()
    res = {"mode": _state["mode"], "at": int(t0)}
    try:
        r = requests.get(CHECK_URL, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
        j = r.json()
        res.update(ok=True, IsTor=bool(j.get("IsTor")), IP=str(j.get("IP") or "")[:64])
    except Exception as e:
        res.update(ok=False, error=f"{type(e).__name__}: {str(e)[:160]}")
    res["ms"] = int((time.time() - t0) * 1000)
    _last_check["result"] = res
    return res


# ── uç noktalar ───────────────────────────────
def _json_body():
    b = request.get_json(silent=True)
    return b if isinstance(b, dict) else None


def api_status():
    return jsonify(status())


def api_mode():
    b = _json_body()
    if b is None:
        return jsonify({"ok": False, "error": "JSON body {mode, url?} required"}), 400
    mode = b.get("mode")
    if mode not in MODES:
        return jsonify({"ok": False, "error": "mode must be off, tor or custom"}), 400
    url = ""
    if mode == "custom":
        url, err = validate_url(b.get("url"))
        if err:
            return jsonify({"ok": False, "error": err}), 400
    ok, err = apply(mode, url)
    if not ok:
        return jsonify({"ok": False, "error": err, "pysocks": have_pysocks()}), 400
    try:
        save()
    except Exception as e:
        print(f"[net] save failed: {e}")
        return jsonify({"ok": False, "error": "Could not write net.json", "status": status()}), 500
    return jsonify({"ok": True, "status": status()})


def api_tor_start():
    if _json_body() is None:
        return jsonify({"ok": False, "error": "JSON body required"}), 400
    r = tor_start()
    r["status"] = status()
    return jsonify(r), (200 if r.get("ok") else 400)


def api_tor_stop():
    if _json_body() is None:
        return jsonify({"ok": False, "error": "JSON body required"}), 400
    r = tor_stop()
    r["status"] = status()
    return jsonify(r), (200 if r.get("ok") else 400)


def api_check():
    if _json_body() is None:
        return jsonify({"ok": False, "error": "JSON body required"}), 400
    return jsonify(check_exit())


def init(app, ctx):
    global _ctx, _cfg_path
    _ctx = ctx
    _cfg_path = os.path.join(ctx.config_dir, "net.json")
    ctx.ws_connect = ws_connect
    ctx.net_status = status
    ctx.net_mode = lambda: _state["mode"]
    if "net" not in app.blueprints:
        rl = getattr(ctx, "rate_limit", None) or (lambda spec: (lambda f: f))
        bp.add_url_rule("/api/net/status", "api_status", api_status)
        bp.add_url_rule("/api/net/mode", "api_mode", rl("20 per minute")(api_mode), methods=["POST"])
        bp.add_url_rule("/api/net/tor/start", "api_tor_start", rl("10 per minute")(api_tor_start), methods=["POST"])
        bp.add_url_rule("/api/net/tor/stop", "api_tor_stop", rl("10 per minute")(api_tor_stop), methods=["POST"])
        bp.add_url_rule("/api/net/check", "api_check", rl("10 per minute")(api_check), methods=["POST"])
        app.register_blueprint(bp)
    load_and_apply()
