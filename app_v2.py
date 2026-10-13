"""Compatibility entry point for git checkouts: `python app_v2.py`, `gunicorn app_v2:app`, `import app_v2`.
The application lives in the signalops package (signalops/app_v2.py)."""
import sys

if __name__ == "__main__":
    from signalops.cli import main
    main(["--no-browser"] + sys.argv[1:])
else:
    import signalops.app_v2 as _real
    sys.modules[__name__] = _real
