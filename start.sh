#!/usr/bin/env bash
# SignalOps — tek komutla kurulum + başlatma (Linux / macOS)
#   ./start.sh            kur (ilk sefer) ve başlat
#   ./start.sh --port 9090
#   ./start.sh --update   bağımlılıkları yeniden kur
set -euo pipefail
cd "$(dirname "$0")"

PORT="${SIGNALOPS_PORT:-8080}"
UPDATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --update) UPDATE=1; shift ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "Bilinmeyen seçenek: $1"; exit 1 ;;
  esac
done

PY="$(command -v python3 || true)"
[ -z "$PY" ] && { echo "✗ python3 bulunamadı. Kur: sudo apt install python3 python3-venv"; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' \
  || { echo "✗ Python 3.9+ gerekli ($("$PY" --version))"; exit 1; }

if [ ! -d .venv ]; then
  echo "→ Sanal ortam oluşturuluyor (.venv)…"
  "$PY" -m venv .venv || { echo "✗ venv oluşturulamadı. Kur: sudo apt install python3-venv"; exit 1; }
  UPDATE=1
fi
# requirements.txt değiştiyse yeniden kur
STAMP=".venv/.req.sha"
NEW_SHA="$(sha256sum requirements.txt 2>/dev/null | cut -d' ' -f1 || shasum -a 256 requirements.txt | cut -d' ' -f1)"
if [ "$UPDATE" = 1 ] || [ ! -f "$STAMP" ] || [ "$(cat "$STAMP")" != "$NEW_SHA" ]; then
  echo "→ Bağımlılıklar kuruluyor…"
  .venv/bin/python -m pip install -q --upgrade pip
  .venv/bin/python -m pip install -q -r requirements.txt
  echo "$NEW_SHA" > "$STAMP"
fi

[ -d data ] || echo "⚠ data/ klasörü yok — kamera/karakol katmanları OSM canlı verisiyle çalışır (daha yavaş)."
[ -f .env ] || echo "ℹ API anahtarlarını arayüzden gir: http://localhost:${PORT}/settings"

export SIGNALOPS_PORT="$PORT"
echo "→ SignalOps başlatılıyor: http://localhost:${PORT}  (durdurmak için Ctrl+C)"
( sleep 35; command -v xdg-open >/dev/null && xdg-open "http://localhost:${PORT}" >/dev/null 2>&1 || true ) &
exec .venv/bin/python app_v2.py
