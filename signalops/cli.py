"""`signalops` command."""
import argparse
import os
import sys


def main(argv=None):
    from . import __version__
    p = argparse.ArgumentParser(prog="signalops", description="SignalOps — local SIGINT / OSINT workbench")
    p.add_argument("--host", help="bind address (default 127.0.0.1; anything else exposes the UI to your network)")
    p.add_argument("--port", type=int, help="port (default 8080)")
    p.add_argument("--home", help="state directory for keys, database and data (default ~/.signalops)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    p.add_argument("--version", action="version", version=f"SignalOps {__version__}")
    a = p.parse_args(argv)
    if a.home:
        os.environ["SIGNALOPS_HOME"] = a.home
    if a.host:
        os.environ["SIGNALOPS_HOST"] = a.host
    if a.port:
        os.environ["SIGNALOPS_PORT"] = str(a.port)

    from . import paths
    os.makedirs(paths.HOME, exist_ok=True)
    print(f"SignalOps {__version__} · state: {paths.HOME}")
    if not os.path.isdir(paths.data_dir()):
        print(f"  optional datasets: put them in {paths.data_dir()} (camera / ALPR / precinct layers); without them OSM is used live")

    from .app_v2 import main as run
    if not a.no_browser and sys.stdout.isatty():
        import threading, webbrowser
        port = os.getenv("SIGNALOPS_PORT", "8080")
        threading.Timer(2.5, lambda: webbrowser.open(f"http://localhost:{port}")).start()
    run()


if __name__ == "__main__":
    main()
