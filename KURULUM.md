# SignalOps — Kurulum

SignalOps **yerel** çalışacak şekilde tasarlandı: varsayılan olarak sadece bu bilgisayardan
(`http://localhost:8080`) erişilir, giriş ekranı yoktur.

## 0. pip ile (en kolayı)

```bash
pip install signalops-sigint      # PyPI'da "signalops" adı başka bir projede, paket adı bu
signalops                         # → http://localhost:8080
signalops --port 9090 --home ~/sigops   # farklı port / veri klasörü
```

pip kurulumunda anahtarlar, veritabanı ve watchlist `~/.signalops/` altında tutulur.
İsteğe bağlı veri setlerini `~/.signalops/data/` içine koyabilirsin.
GitHub'dan direkt: `pip install git+https://github.com/emrekybs/signalops`

## 1. Tek komutla (Linux / macOS)

```bash
./start.sh                 # ilk seferde sanal ortamı kurar, sonra başlatır
./start.sh --port 9090     # farklı port
./start.sh --update        # bağımlılıkları yeniden kur
```

Windows: `start.bat` dosyasına çift tıkla.

Gereksinim: Python 3.9+ (Linux'ta `python3-venv` paketi).

## 2. Docker ile

```bash
docker compose up -d       # derler ve arka planda başlatır → http://localhost:8080
docker compose logs -f     # loglar
docker compose down        # durdur
```

- Port sadece `127.0.0.1`'e açılır (ağdaki diğer cihazlar erişemez).
- Veritabanı, API anahtarları ve watchlist `signalops-state` volume'unda kalıcıdır.
- `data/` klasörü salt okunur bağlanır.

## 3. Elle

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 app_v2.py
```

## data/ klasörü

Kamera / ALPR / karakol katmanları için yerel veri setleri (`CAMERAS_WITH_NETWORK_DATA.geojson`,
`police_precincts_usa.geojson`, `camera_networks.json`, `tiles/`). Kaynak koddan çalıştırırken proje
klasörünün içinde `data/`, pip kurulumunda `~/.signalops/data/` olarak durmalı. Yoksa uygulama yine çalışır, katmanlar canlı OSM verisiyle (daha yavaş) gelir.

## API anahtarları

**Settings** sayfasından tek tek girilir, kaydedildiği an devreye girer (yeniden başlatma yok).
`config/keys.json` içinde saklanır — paylaşma, git'e ekleme. İstersen `.env` de kullanılabilir;
arayüzden girilen değer `.env`'in önüne geçer.

Harita altlığı: CARTO artık anahtar istiyor. Anahtar yoksa haritalar otomatik olarak
OpenStreetMap'e geçer. Orijinal koyu görünüm için Settings → Maps'e ücretsiz CARTO anahtarı gir.

## Ortam değişkenleri (opsiyonel)

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `SIGNALOPS_HOST` | `127.0.0.1` | Dinlenecek adres. `0.0.0.0` = ağa açık (giriş ekranı yok!) |
| `SIGNALOPS_PORT` | `8080` | Port |
| `SIGNALOPS_ALLOWED_HOSTS` | — | LAN'dan erişim için izin verilen adresler (ör. `192.168.1.20`) |
| `SIGNALOPS_DB` | `db/signalops.db` | Vaka / tarama veritabanı |
| `SIGNALOPS_CONFIG_DIR` | `config/` | API anahtarları, secret key |
| `WATCHLIST_DIR` | proje klasörü | `watchlist.json` konumu |
| `DATA_DIR` | `data/` | Yerel veri setleri |
| `SIGNALOPS_DISABLE_SCHEDULER` | — | `1` = alan izleme zamanlayıcısını kapat |
| `OVERPASS_MAX_SPAN` | `0.5` | Canlı OSM sorgusunun en geniş alanı (derece) |

## Sayfalar

| Sayfa | Ne yapar |
|---|---|
| Dashboard | Durum, API'ler, hızlı tarama |
| SIGINT Map | WiFi / BT / hücre / IoT / kamera birleşik harita |
| Surveillance | Cihaz akışı, şüphe puanı |
| CCTV | Kamera keşfi (tarayıcı motorları + resmî trafik/hava kameraları) |
| Geo Track / Mobile | Baz istasyonları, IMSI-catcher sezgileri |
| ADS-B / Orbital / SDR / Maritime | Uçak, uydu, KiwiSDR/APRS, AIS gemi takibi |
| Cases | Kayıtlı taramalar, değişim tespiti, cihaz geçmişi, PDF/KML/GeoJSON/CSV |
| Graph | Cihaz / SSID / IP bloğu / vaka korelasyon grafiği (Cases → Graph) |
| Timeline | Bir bölgenin taramalarını haritada zaman kaydırıcısıyla oynatma (Cases → Timeline) |
| Monitor | Alan çiz, periyodik tara, webhook bildirimi |
| Watchlist | Hedef BSSID / IP / ICAO takibi |
| Settings | API anahtarları ve bağlantı testleri |
