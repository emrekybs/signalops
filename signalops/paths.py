"""Where SignalOps keeps its state.

Git checkout (start.sh / Docker / python app_v2.py): everything stays next to the code, as before
  ./config/keys.json  ./db/signalops.db  ./data/  ./watchlist.json  ./.env
pip install: a per-user home directory, because site-packages is not the place for state
  ~/.signalops/ (override with SIGNALOPS_HOME)

Each path can still be overridden on its own: SIGNALOPS_CONFIG_DIR, SIGNALOPS_DB, DATA_DIR, WATCHLIST_DIR.
"""
import os

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(PKG_DIR)
IN_CHECKOUT = os.path.exists(os.path.join(_REPO, "start.sh")) and os.path.exists(os.path.join(_REPO, "pyproject.toml"))

HOME = os.path.abspath(os.path.expanduser(
    os.getenv("SIGNALOPS_HOME") or (_REPO if IN_CHECKOUT else os.path.join("~", ".signalops"))))

ENV_FILE = os.path.join(HOME, ".env")


# Read at call time so values from .env (loaded by the app after this module) are honoured
def config_dir():    return os.getenv("SIGNALOPS_CONFIG_DIR") or os.path.join(HOME, "config")
def db_path():       return os.getenv("SIGNALOPS_DB") or os.path.join(HOME, "db", "signalops.db")
def data_dir():      return os.getenv("DATA_DIR") or os.path.join(HOME, "data")
def watchlist_dir(): return os.getenv("WATCHLIST_DIR") or HOME
