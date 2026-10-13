# SignalOps — tek konteyner, yerel kullanım
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SIGNALOPS_HOST=0.0.0.0 \
    SIGNALOPS_PORT=8080 \
    SIGNALOPS_ALLOWED_HOSTS=localhost,127.0.0.1 \
    SIGNALOPS_DB=/app/state/signalops.db \
    SIGNALOPS_CONFIG_DIR=/app/state/config \
    WATCHLIST_DIR=/app/state \
    DATA_DIR=/app/data

# Tor: Ayarlar → Network / OPSEC → "Start Tor" butonu konteynerde de çalışsın
RUN apt-get update \
 && apt-get install -y --no-install-recommends tor \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN useradd --create-home --uid 10001 signalops \
 && mkdir -p /app/state /app/data \
 && if [ -f watchlist.json ] && [ ! -f /app/state/watchlist.json ]; then cp watchlist.json /app/state/; fi \
 && chown -R signalops:signalops /app/state
USER signalops

VOLUME ["/app/state"]
EXPOSE 8080

# Tek worker: önbellekler ve alan izleme zamanlayıcısı tek süreçte kalsın; uzun taramalar için 180 sn timeout
CMD ["gunicorn", "--workers", "1", "--threads", "16", "--timeout", "180", "--bind", "0.0.0.0:8080", "app_v2:app"]
