"""
Maritime / AIS modülü — gemi takibi (SignalOps).

Kaynaklar
─────────
• aisstream.io  — ücretsiz API anahtarı, WebSocket akışı (wss://stream.aisstream.io/v0/stream).
                  REST anlık görüntü yok → arka planda tek bir abonelik açık tutulur, her MMSI'nin
                  son durumu bellekte biriktirilir, /api/ais bellekten cevap verir.
                  Docs: https://aisstream.io/documentation
                  Modeller: https://github.com/aisstream/ais-message-models
• Digitraffic Marine (Fintraffic) — anahtarsız REST, Finlandiya / kuzey Baltık kapsamı.
                  https://meri.digitraffic.fi/api/ais/v1/locations  (GeoJSON)
                  https://meri.digitraffic.fi/api/ais/v1/vessels    (statik veri)
                  Docs: https://www.digitraffic.fi/en/marine-traffic/
                  Zorunlu: Accept-Encoding: gzip, önerilen: Digitraffic-User başlığı.

Bayraklar (flags) sezgiseldir (heuristic) — kesin kanıt değildir.
"""
import json
import math
import socket
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone

import requests
from flask import Blueprint, jsonify, request, render_template

bp = Blueprint("ais", __name__)
_ctx = None

AISSTREAM_URL = "wss://stream.aisstream.io/v0/stream"
DIGITRAFFIC_LOC = "https://meri.digitraffic.fi/api/ais/v1/locations"
DIGITRAFFIC_VES = "https://meri.digitraffic.fi/api/ais/v1/vessels"
DIGITRAFFIC_HEADERS = {"Digitraffic-User": "SignalOps", "Accept-Encoding": "gzip",
                       "Accept": "application/json"}
# Fintraffic alıcılarının kapsadığı yaklaşık alan (Finlandiya + kuzey/orta Baltık)
DIGITRAFFIC_COVER = (53.0, 9.0, 67.5, 32.5)      # (min_lat, min_lon, max_lat, max_lon)

TTL_S = 90 * 60            # bellekte tutma süresi
DARK_AFTER_S = 30 * 60     # hareket ederken bu kadar süre sessiz kalırsa "dark"
STALE_UI_S = 10 * 60       # UI'da soluk gösterim eşiği (bilgi amaçlı)
MAX_VESSELS = 20000
IDLE_CLOSE_S = 10 * 60     # istek gelmezse akışı kapat
WARMUP_S = 60              # yeni abonelikten sonra "ısınma" süresi
MAX_BOXES = 3              # tek abonelikte en fazla kutu (son kullanılan alanlar)
REQUEST_BUDGET_S = 9.0     # /api/ais en fazla bu kadar bekler

AIS_MSG_TYPES = ["PositionReport", "StandardClassBPositionReport", "ExtendedClassBPositionReport",
                 "ShipStaticData", "StaticDataReport"]

# ══════════════════════════════════════════════
#  Referans tablolar
# ══════════════════════════════════════════════
NAV_STATUS = {
    0: "Under way using engine", 1: "At anchor", 2: "Not under command",
    3: "Restricted manoeuvrability", 4: "Constrained by draught", 5: "Moored", 6: "Aground",
    7: "Engaged in fishing", 8: "Under way sailing", 9: "Reserved (HSC)", 10: "Reserved (WIG)",
    11: "Towing astern", 12: "Pushing ahead / towing alongside", 13: "Reserved",
    14: "AIS-SART / MOB / EPIRB active", 15: "Not defined",
}

_TYPE_FIXED = {
    0: "Not available", 20: "Wing in ground (WIG)", 30: "Fishing", 31: "Towing",
    32: "Towing (large)", 33: "Dredging / underwater ops", 34: "Diving ops", 35: "Military ops",
    36: "Sailing", 37: "Pleasure craft", 50: "Pilot vessel", 51: "Search and rescue",
    52: "Tug", 53: "Port tender", 54: "Anti-pollution", 55: "Law enforcement",
    56: "Spare (local)", 57: "Spare (local)", 58: "Medical transport",
    59: "Non-combatant (RR Res. 18)",
}
_TYPE_FAMILY = {2: "Wing in ground (WIG)", 4: "High speed craft (HSC)", 6: "Passenger",
                7: "Cargo", 8: "Tanker", 9: "Other type"}
_TYPE_SUFFIX = {1: "hazardous cat. A", 2: "hazardous cat. B", 3: "hazardous cat. C",
                4: "hazardous cat. D", 9: "no additional info"}


def ship_type_name(code):
    try:
        c = int(code)
    except (TypeError, ValueError):
        return "Unknown"
    if c in _TYPE_FIXED:
        return _TYPE_FIXED[c]
    fam, sub = divmod(c, 10)
    if fam in _TYPE_FAMILY and 0 <= c <= 99:
        base = _TYPE_FAMILY[fam]
        if fam == 2 and sub >= 5:
            return base + " (reserved)"
        return base + (f" — {_TYPE_SUFFIX[sub]}" if sub in _TYPE_SUFFIX else "")
    if 1 <= c <= 19 or c in (38, 39):
        return "Reserved"
    return "Unknown"


def ship_category(code):
    try:
        c = int(code)
    except (TypeError, ValueError):
        return "other"
    if 70 <= c <= 79: return "cargo"
    if 80 <= c <= 89: return "tanker"
    if 60 <= c <= 69 or 40 <= c <= 49: return "passenger"
    if c == 30: return "fishing"
    if c == 35: return "military"
    if c == 55: return "law"
    if c == 51: return "sar"
    if c in (31, 32, 52, 53): return "tug"
    if c in (36, 37): return "pleasure"
    return "other"


# ITU MID (Maritime Identification Digits) → ISO 3166-1 alpha-2
MID = {
    # Europe
    201: "AL", 202: "AD", 203: "AT", 204: "PT", 205: "BE", 206: "BY", 207: "BG", 208: "VA",
    209: "CY", 210: "CY", 211: "DE", 212: "CY", 213: "GE", 214: "MD", 215: "MT", 216: "AM",
    218: "DE", 219: "DK", 220: "DK", 224: "ES", 225: "ES", 226: "FR", 227: "FR", 228: "FR",
    229: "MT", 230: "FI", 231: "FO", 232: "GB", 233: "GB", 234: "GB", 235: "GB", 236: "GI",
    237: "GR", 238: "HR", 239: "GR", 240: "GR", 241: "GR", 242: "MA", 243: "HU", 244: "NL",
    245: "NL", 246: "NL", 247: "IT", 248: "MT", 249: "MT", 250: "IE", 251: "IS", 252: "LI",
    253: "LU", 254: "MC", 255: "PT", 256: "MT", 257: "NO", 258: "NO", 259: "NO", 261: "PL",
    262: "ME", 263: "PT", 264: "RO", 265: "SE", 266: "SE", 267: "SK", 268: "SM", 269: "CH",
    270: "CZ", 271: "TR", 272: "UA", 273: "RU", 274: "MK", 275: "LV", 276: "EE", 277: "LT",
    278: "SI", 279: "RS",
    # Americas
    301: "AI", 303: "US", 304: "AG", 305: "AG", 306: "CW", 307: "AW", 308: "BS", 309: "BS",
    310: "BM", 311: "BS", 312: "BZ", 314: "BB", 316: "CA", 319: "KY", 321: "CR", 323: "CU",
    325: "DM", 327: "DO", 329: "GP", 330: "GD", 331: "GL", 332: "GT", 334: "HN", 336: "HT",
    338: "US", 339: "JM", 341: "KN", 343: "LC", 345: "MX", 347: "MQ", 348: "MS", 350: "NI",
    351: "PA", 352: "PA", 353: "PA", 354: "PA", 355: "PA", 356: "PA", 357: "PA", 358: "PR",
    359: "SV", 361: "PM", 362: "TT", 364: "TC", 366: "US", 367: "US", 368: "US", 369: "US",
    370: "PA", 371: "PA", 372: "PA", 373: "PA", 374: "PA", 375: "VC", 376: "VC", 377: "VC",
    378: "VG", 379: "VI",
    # Asia / Middle East
    401: "AF", 403: "SA", 405: "BD", 408: "BH", 410: "BT", 412: "CN", 413: "CN", 414: "CN",
    416: "TW", 417: "LK", 419: "IN", 422: "IR", 423: "AZ", 425: "IQ", 428: "IL", 431: "JP",
    432: "JP", 434: "TM", 436: "KZ", 437: "UZ", 438: "JO", 440: "KR", 441: "KR", 443: "PS",
    445: "KP", 447: "KW", 450: "LB", 451: "KG", 453: "MO", 455: "MV", 457: "MN", 459: "NP",
    461: "OM", 463: "PK", 466: "QA", 468: "SY", 470: "AE", 471: "AE", 472: "TJ", 473: "YE",
    475: "YE", 477: "HK", 478: "BA",
    # Oceania / SE Asia
    501: "TF", 503: "AU", 506: "MM", 508: "BN", 510: "FM", 511: "PW", 512: "NZ", 514: "KH",
    515: "KH", 516: "CX", 518: "CK", 520: "FJ", 523: "CC", 525: "ID", 529: "KI", 531: "LA",
    533: "MY", 536: "MP", 538: "MH", 540: "NC", 542: "NU", 544: "NR", 546: "PF", 548: "PH",
    550: "TL", 553: "PG", 555: "PN", 557: "SB", 559: "AS", 561: "WS", 563: "SG", 564: "SG",
    565: "SG", 566: "SG", 567: "TH", 570: "TO", 572: "TV", 574: "VN", 576: "VU", 577: "VU",
    578: "WF",
    # Africa
    601: "ZA", 603: "AO", 605: "DZ", 607: "TF", 608: "SH", 609: "BI", 610: "BJ", 611: "BW",
    612: "CF", 613: "CM", 615: "CG", 616: "KM", 617: "CV", 618: "TF", 619: "CI", 620: "KM",
    621: "DJ", 622: "EG", 624: "ET", 625: "ER", 626: "GA", 627: "GH", 629: "GM", 630: "GW",
    631: "GQ", 632: "GN", 633: "BF", 634: "KE", 635: "TF", 636: "LR", 637: "LR", 638: "SS",
    642: "LY", 644: "LS", 645: "MU", 647: "MG", 649: "ML", 650: "MZ", 654: "MR", 655: "MW",
    656: "NE", 657: "NG", 659: "NA", 660: "RE", 661: "RW", 662: "SD", 663: "SN", 664: "SC",
    665: "SH", 666: "SO", 667: "SL", 668: "ST", 669: "SZ", 670: "TD", 671: "TG", 672: "TN",
    674: "TZ", 675: "UG", 676: "CD", 677: "TZ", 678: "ZM", 679: "ZW",
    # South America
    701: "AR", 710: "BR", 720: "BO", 725: "CL", 730: "CO", 735: "EC", 740: "FK", 745: "GF",
    750: "GY", 755: "PY", 760: "PE", 765: "SR", 770: "UY", 775: "VE",
}

COUNTRY = {
    "AL": "Albania", "AD": "Andorra", "AT": "Austria", "PT": "Portugal", "BE": "Belgium",
    "BY": "Belarus", "BG": "Bulgaria", "VA": "Vatican", "CY": "Cyprus", "DE": "Germany",
    "GE": "Georgia", "MD": "Moldova", "MT": "Malta", "AM": "Armenia", "DK": "Denmark",
    "ES": "Spain", "FR": "France", "FI": "Finland", "FO": "Faroe Islands", "GB": "United Kingdom",
    "GI": "Gibraltar", "GR": "Greece", "HR": "Croatia", "MA": "Morocco", "HU": "Hungary",
    "NL": "Netherlands", "IT": "Italy", "IE": "Ireland", "IS": "Iceland", "LI": "Liechtenstein",
    "LU": "Luxembourg", "MC": "Monaco", "NO": "Norway", "PL": "Poland", "ME": "Montenegro",
    "RO": "Romania", "SE": "Sweden", "SK": "Slovakia", "SM": "San Marino", "CH": "Switzerland",
    "CZ": "Czechia", "TR": "Türkiye", "UA": "Ukraine", "RU": "Russia", "MK": "North Macedonia",
    "LV": "Latvia", "EE": "Estonia", "LT": "Lithuania", "SI": "Slovenia", "RS": "Serbia",
    "AI": "Anguilla", "US": "United States", "AG": "Antigua and Barbuda", "CW": "Curaçao",
    "AW": "Aruba", "BS": "Bahamas", "BM": "Bermuda", "BZ": "Belize", "BB": "Barbados",
    "CA": "Canada", "KY": "Cayman Islands", "CR": "Costa Rica", "CU": "Cuba", "DM": "Dominica",
    "DO": "Dominican Republic", "GP": "Guadeloupe", "GD": "Grenada", "GL": "Greenland",
    "GT": "Guatemala", "HN": "Honduras", "HT": "Haiti", "JM": "Jamaica",
    "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia", "MX": "Mexico", "MQ": "Martinique",
    "MS": "Montserrat", "NI": "Nicaragua", "PA": "Panama", "PR": "Puerto Rico",
    "SV": "El Salvador", "PM": "Saint Pierre and Miquelon", "TT": "Trinidad and Tobago",
    "TC": "Turks and Caicos", "VC": "Saint Vincent and the Grenadines",
    "VG": "British Virgin Islands", "VI": "US Virgin Islands", "AF": "Afghanistan",
    "SA": "Saudi Arabia", "BD": "Bangladesh", "BH": "Bahrain", "BT": "Bhutan", "CN": "China",
    "TW": "Taiwan", "LK": "Sri Lanka", "IN": "India", "IR": "Iran", "AZ": "Azerbaijan",
    "IQ": "Iraq", "IL": "Israel", "JP": "Japan", "TM": "Turkmenistan", "KZ": "Kazakhstan",
    "UZ": "Uzbekistan", "JO": "Jordan", "KR": "South Korea", "PS": "Palestine",
    "KP": "North Korea", "KW": "Kuwait", "LB": "Lebanon", "KG": "Kyrgyzstan", "MO": "Macao",
    "MV": "Maldives", "MN": "Mongolia", "NP": "Nepal", "OM": "Oman", "PK": "Pakistan",
    "QA": "Qatar", "SY": "Syria", "AE": "United Arab Emirates", "TJ": "Tajikistan",
    "YE": "Yemen", "HK": "Hong Kong", "BA": "Bosnia and Herzegovina",
    "TF": "French Southern Territories", "AU": "Australia", "MM": "Myanmar", "BN": "Brunei",
    "FM": "Micronesia", "PW": "Palau", "NZ": "New Zealand", "KH": "Cambodia",
    "CX": "Christmas Island", "CK": "Cook Islands", "FJ": "Fiji", "CC": "Cocos Islands",
    "ID": "Indonesia", "KI": "Kiribati", "LA": "Laos", "MY": "Malaysia",
    "MP": "Northern Mariana Islands", "MH": "Marshall Islands", "NC": "New Caledonia",
    "NU": "Niue", "NR": "Nauru", "PF": "French Polynesia", "PH": "Philippines",
    "TL": "Timor-Leste", "PG": "Papua New Guinea", "PN": "Pitcairn", "SB": "Solomon Islands",
    "AS": "American Samoa", "WS": "Samoa", "SG": "Singapore", "TH": "Thailand", "TO": "Tonga",
    "TV": "Tuvalu", "VN": "Vietnam", "VU": "Vanuatu", "WF": "Wallis and Futuna",
    "ZA": "South Africa", "AO": "Angola", "DZ": "Algeria", "SH": "Saint Helena",
    "BI": "Burundi", "BJ": "Benin", "BW": "Botswana", "CF": "Central African Republic",
    "CM": "Cameroon", "CG": "Congo", "KM": "Comoros", "CV": "Cabo Verde", "CI": "Côte d'Ivoire",
    "DJ": "Djibouti", "EG": "Egypt", "ET": "Ethiopia", "ER": "Eritrea", "GA": "Gabon",
    "GH": "Ghana", "GM": "Gambia", "GW": "Guinea-Bissau", "GQ": "Equatorial Guinea",
    "GN": "Guinea", "BF": "Burkina Faso", "KE": "Kenya", "LR": "Liberia", "SS": "South Sudan",
    "LY": "Libya", "LS": "Lesotho", "MU": "Mauritius", "MG": "Madagascar", "ML": "Mali",
    "MZ": "Mozambique", "MR": "Mauritania", "MW": "Malawi", "NE": "Niger", "NG": "Nigeria",
    "NA": "Namibia", "RE": "Réunion", "RW": "Rwanda", "SD": "Sudan", "SN": "Senegal",
    "SC": "Seychelles", "SO": "Somalia", "SL": "Sierra Leone", "ST": "São Tomé and Príncipe",
    "SZ": "Eswatini", "TD": "Chad", "TG": "Togo", "TN": "Tunisia", "TZ": "Tanzania",
    "UG": "Uganda", "CD": "DR Congo", "ZM": "Zambia", "ZW": "Zimbabwe", "AR": "Argentina",
    "BR": "Brazil", "BO": "Bolivia", "CL": "Chile", "CO": "Colombia", "EC": "Ecuador",
    "FK": "Falkland Islands", "GF": "French Guiana", "GY": "Guyana", "PY": "Paraguay",
    "PE": "Peru", "SR": "Suriname", "UY": "Uruguay", "VE": "Venezuela",
}

_TEST_MMSI = {"000000000", "111111111", "123456789", "987654321", "999999999", "012345678"}


def mmsi_info(mmsi):
    """MMSI'yi çözümler → {valid, kind, mid, iso2, country, problem}.
    Biçimler (ITU-R M.585): MIDxxxxxx gemi · 0MIDxxxxx grup · 00MIDxxxx kıyı istasyonu ·
    111MIDxxx SAR uçağı · 98MIDxxxx yardımcı tekne · 99MIDxxxx seyir yardımcısı (AtoN) ·
    970/972/974 SART / MOB / EPIRB."""
    s = str(mmsi or "").strip()
    out = {"valid": False, "kind": "unknown", "mid": None, "iso2": None, "country": None,
           "problem": None}
    if not s.isdigit() or len(s) != 9:
        out["problem"] = "MMSI is not 9 digits"
        return out
    if s in _TEST_MMSI or len(set(s)) == 1:
        out["problem"] = "Test / placeholder MMSI"
        return out
    mid = None
    if s.startswith("970"):   out["kind"] = "sart"
    elif s.startswith("972"): out["kind"] = "mob"
    elif s.startswith("974"): out["kind"] = "epirb"
    elif s.startswith("111"): out["kind"], mid = "sar_aircraft", s[3:6]
    elif s.startswith("00"):  out["kind"], mid = "coast_station", s[2:5]
    elif s.startswith("0"):   out["kind"], mid = "group", s[1:4]
    elif s.startswith("98"):  out["kind"], mid = "craft_assoc", s[2:5]
    elif s.startswith("99"):  out["kind"], mid = "aton", s[2:5]
    elif s[0] in "234567":    out["kind"], mid = "ship", s[:3]
    else:
        out["problem"] = "Non-standard MMSI prefix"
        return out
    out["valid"] = True
    if mid:
        out["mid"] = int(mid)
        iso = MID.get(int(mid))
        if iso:
            out["iso2"], out["country"] = iso, COUNTRY.get(iso, iso)
        else:
            out["problem"] = f"MID {mid} not allocated"
    return out


# ══════════════════════════════════════════════
#  Yardımcılar
# ══════════════════════════════════════════════
def _f(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def _i(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _clean_str(v, n=40):
    if v is None:
        return None
    s = str(v).replace("@", " ").strip()
    s = " ".join(s.split())
    return s[:n] or None


def haversine_km(a_lat, a_lon, b_lat, b_lon):
    r = 6371.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp, dl = p2 - p1, math.radians(b_lon - a_lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


def bbox_around(lat, lon, radius_km):
    dlat = radius_km / 111.32
    dlon = radius_km / (111.32 * max(0.05, math.cos(math.radians(lat))))
    return (max(-90.0, lat - dlat), max(-180.0, lon - dlon),
            min(90.0, lat + dlat), min(180.0, lon + dlon))


def bbox_contains(outer, inner):
    return (outer[0] <= inner[0] and outer[1] <= inner[1]
            and outer[2] >= inner[2] and outer[3] >= inner[3])


def bbox_intersects(a, b):
    return not (a[2] < b[0] or a[0] > b[2] or a[3] < b[1] or a[1] > b[3])


def in_bbox(bb, lat, lon):
    return bb[0] <= lat <= bb[2] and bb[1] <= lon <= bb[3]


def pad_bbox(bb, frac=0.25):
    dl, dn = (bb[2] - bb[0]) * frac, (bb[3] - bb[1]) * frac
    return (max(-90.0, bb[0] - dl), max(-180.0, bb[1] - dn),
            min(90.0, bb[2] + dl), min(180.0, bb[3] + dn))


def parse_time_utc(s):
    """aisstream MetaData.time_utc: '2023-05-10 11:46:52.509865357 +0000 UTC' → epoch."""
    if not s:
        return None
    try:
        dt = datetime.strptime(str(s)[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _valid_pos(lat, lon):
    return (lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180
            and not (abs(lat) < 1e-6 and abs(lon) < 1e-6))


def _norm_sog(v):
    v = _f(v)
    return None if v is None or v < 0 or v >= 102.25 else round(v, 1)   # 102.3 = n/a


def _norm_cog(v):
    v = _f(v)
    return None if v is None or v < 0 or v >= 360 else round(v, 1)      # 360 = n/a


def _norm_heading(v):
    v = _i(v)
    return None if v is None or v < 0 or v > 359 else v                 # 511 = n/a


def _eta_str(month, day, hour, minute):
    month, day, hour, minute = _i(month), _i(day), _i(hour), _i(minute)
    if not month or not day or month > 12 or day > 31:
        return None
    h = hour if hour is not None and hour < 24 else None
    m = minute if minute is not None and minute < 60 else None
    if h is None or m is None:
        return f"{month:02d}-{day:02d} (time n/a)"
    return f"{month:02d}-{day:02d} {h:02d}:{m:02d} UTC"


def _eta_digitraffic(v):
    """Digitraffic eta: AIS bit alanı — ay(19-16) gün(15-11) saat(10-6) dakika(5-0)."""
    v = _i(v)
    if v is None:
        return None
    return _eta_str((v >> 16) & 0xF, (v >> 11) & 0x1F, (v >> 6) & 0x1F, v & 0x3F)


def _dims(a, b, c, d):
    a, b, c, d = (_i(x) or 0 for x in (a, b, c, d))
    length = a + b if (a or b) else None
    width = c + d if (c or d) else None
    return length, width


# ══════════════════════════════════════════════
#  Gemi deposu (tüm kaynaklar ortak) — thread-safe, sınırlı
# ══════════════════════════════════════════════
class VesselStore:
    def __init__(self, max_items=MAX_VESSELS, ttl=TTL_S):
        self.lock = threading.RLock()
        self.items = OrderedDict()       # mmsi → kayıt (en son güncellenen sonda)
        self.max_items = max_items
        self.ttl = ttl

    def _get(self, mmsi):
        rec = self.items.get(mmsi)
        if rec is None:
            rec = {"mmsi": mmsi, "names": [], "sources": set(), "last_update": None,
                   "was_moving": False, "jump": None, "max_implied_kn": None}
            self.items[mmsi] = rec
            while len(self.items) > self.max_items:
                self.items.popitem(last=False)
        return rec

    def update_position(self, mmsi, lat, lon, sog=None, cog=None, heading=None, nav=None,
                        ts=None, source="aisstream", name_hint=None):
        if not mmsi or not _valid_pos(lat, lon):
            return False
        now = time.time()
        ts = min(ts or now, now)
        with self.lock:
            rec = self._get(mmsi)
            prev_ts = rec.get("last_update")
            if prev_ts is not None and ts <= prev_ts:
                rec["sources"].add(source)
                return False
            if prev_ts is not None and rec.get("lat") is not None:
                dist = haversine_km(rec["lat"], rec["lon"], lat, lon)
                dt = max(1.0, ts - prev_ts)
                kn = (dist / 1.852) / (dt / 3600.0)
                if dist > 1.0 and kn > 60:
                    rec["jump"] = {"km": round(dist, 2), "seconds": round(dt, 1),
                                   "implied_kn": round(kn, 1), "at": ts,
                                   "from": [round(rec["lat"], 5), round(rec["lon"], 5)]}
                    rec["max_implied_kn"] = max(rec.get("max_implied_kn") or 0, round(kn, 1))
            rec.update(lat=lat, lon=lon, last_update=ts, last_source=source)
            if sog is not None or "sog" not in rec: rec["sog"] = sog
            if cog is not None or "cog" not in rec: rec["cog"] = cog
            if heading is not None or "heading" not in rec: rec["heading"] = heading
            if nav is not None: rec["nav"] = nav
            if sog is not None and sog >= 1.0:
                rec["was_moving"] = True
            if name_hint and not rec.get("name"):
                rec["name_hint"] = name_hint
            rec["sources"].add(source)
            self.items.move_to_end(mmsi)
            return True

    def update_static(self, mmsi, source="aisstream", name=None, callsign=None, imo=None,
                      ship_type=None, destination=None, eta=None, length=None, width=None,
                      draught=None):
        if not mmsi:
            return
        with self.lock:
            rec = self._get(mmsi)
            if name:
                rec["name"] = name
                if name not in rec["names"]:
                    rec["names"].append(name)
                    rec["names"] = rec["names"][-5:]
            if callsign: rec["callsign"] = callsign
            if imo: rec["imo"] = imo
            if ship_type is not None: rec["ship_type"] = ship_type
            if destination: rec["destination"] = destination
            if eta: rec["eta"] = eta
            if length: rec["length"] = length
            if width: rec["width"] = width
            if draught: rec["draught"] = draught
            rec["static_at"] = time.time()
            rec["sources"].add(source)

    def prune(self, now=None):
        now = now or time.time()
        with self.lock:
            dead = [k for k, r in self.items.items()
                    if (r.get("last_update") or r.get("static_at") or 0) < now - self.ttl]
            for k in dead:
                del self.items[k]
            return len(dead)

    def query(self, bb, center=None, radius_km=None):
        now = time.time()
        out = []
        with self.lock:
            for r in self.items.values():
                lat, lon = r.get("lat"), r.get("lon")
                if lat is None or not in_bbox(bb, lat, lon):
                    continue
                if (r.get("last_update") or 0) < now - self.ttl:
                    continue
                if center and radius_km and haversine_km(center[0], center[1], lat, lon) > radius_km:
                    continue
                c = dict(r)
                c["sources"] = sorted(r["sources"])
                c["names"] = list(r["names"])
                out.append(c)
        return out

    def clear(self):
        with self.lock:
            self.items.clear()

    def __len__(self):
        return len(self.items)


STORE = VesselStore()


# ══════════════════════════════════════════════
#  aisstream.io — mesaj işleme
# ══════════════════════════════════════════════
def ingest_aisstream(msg, store=None):
    """Tek bir aisstream mesajını depoya işler. Döner: işlenen MMSI veya None."""
    store = store or STORE
    if not isinstance(msg, dict):
        return None
    mtype = msg.get("MessageType")
    meta = msg.get("MetaData") or {}
    body = (msg.get("Message") or {}).get(mtype) or {}
    if not isinstance(body, dict):
        return None
    raw = meta.get("MMSI") or meta.get("MMSI_String") or body.get("UserID")
    mmsi = str(_i(raw) if _i(raw) is not None else (raw or "")).strip()
    if mmsi.isdigit() and len(mmsi) < 9:
        mmsi = mmsi.zfill(9)                         # baştaki sıfırlar (kıyı istasyonu vb.)
    if not mmsi:
        return None
    ts = parse_time_utc(meta.get("time_utc")) or time.time()
    hint = _clean_str(meta.get("ShipName"))

    if mtype in ("PositionReport", "StandardClassBPositionReport", "ExtendedClassBPositionReport"):
        if body.get("Valid") is False:
            return None
        lat = _f(body.get("Latitude", meta.get("latitude")))
        lon = _f(body.get("Longitude", meta.get("longitude")))
        nav = _i(body.get("NavigationalStatus")) if mtype == "PositionReport" else None
        store.update_position(mmsi, lat, lon, _norm_sog(body.get("Sog")), _norm_cog(body.get("Cog")),
                              _norm_heading(body.get("TrueHeading")), nav, ts, "aisstream", hint)
        if mtype == "ExtendedClassBPositionReport":
            dim = body.get("Dimension") or {}
            ln, wd = _dims(dim.get("A"), dim.get("B"), dim.get("C"), dim.get("D"))
            store.update_static(mmsi, "aisstream", name=_clean_str(body.get("Name")),
                                ship_type=_i(body.get("Type")), length=ln, width=wd)
        return mmsi

    if mtype == "ShipStaticData":
        if body.get("Valid") is False:
            return None
        dim = body.get("Dimension") or {}
        ln, wd = _dims(dim.get("A"), dim.get("B"), dim.get("C"), dim.get("D"))
        eta = body.get("Eta") or {}
        imo = _i(body.get("ImoNumber"))
        store.update_static(
            mmsi, "aisstream", name=_clean_str(body.get("Name")),
            callsign=_clean_str(body.get("CallSign"), 12),
            imo=str(imo) if imo and 1000000 <= imo <= 9999999 else None,
            ship_type=_i(body.get("Type")), destination=_clean_str(body.get("Destination")),
            eta=_eta_str(eta.get("Month"), eta.get("Day"), eta.get("Hour"), eta.get("Minute")),
            length=ln, width=wd, draught=_f(body.get("MaximumStaticDraught")) or None)
        # MetaData konumu varsa (statik mesaj) konum güncellemesi yapma — sadece rapor mesajları
        return mmsi

    if mtype == "StaticDataReport":
        a = body.get("ReportA") or {}
        b = body.get("ReportB") or {}
        if a.get("Valid") and a.get("Name"):
            store.update_static(mmsi, "aisstream", name=_clean_str(a.get("Name")))
        if b.get("Valid"):
            dim = b.get("Dimension") or {}
            ln, wd = _dims(dim.get("A"), dim.get("B"), dim.get("C"), dim.get("D"))
            store.update_static(mmsi, "aisstream", callsign=_clean_str(b.get("CallSign"), 12),
                                ship_type=_i(b.get("ShipType")), length=ln, width=wd)
        return mmsi
    return None


def _ws_lib():
    """websocket-client tembel import — yoksa None (uygulama yine açılır)."""
    try:
        import websocket   # pip: websocket-client
        return websocket
    except Exception:
        return None


def _ws_connect(lib, url, timeout):
    """Ağ/OPSEC modülü (modules/net.py) yüklüyse Tor/proxy üzerinden bağlanır."""
    fn = getattr(_ctx, "ws_connect", None) if _ctx else None
    if fn:
        return fn(lib, url, timeout)
    return lib.create_connection(url, timeout=timeout)


def _is_timeout(e):
    return isinstance(e, (socket.timeout, TimeoutError)) or type(e).__name__ == "WebSocketTimeoutException"


def _sub_message(key, boxes):
    return json.dumps({
        "APIKey": key,
        "BoundingBoxes": [[[round(b[0], 4), round(b[1], 4)], [round(b[2], 4), round(b[3], 4)]]
                          for b in boxes],
        "FilterMessageTypes": AIS_MSG_TYPES,
    })


class AisStreamCollector:
    """Tek WebSocket aboneliği (≤ MAX_BOXES kutu). İstek gelmezse IDLE_CLOSE_S sonra kapanır."""

    def __init__(self, store):
        self.store = store
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.thread = None
        self.key = ""
        self.boxes = []            # [{"bb":(...), "added": t, "used": t}]
        self.sub_version = 0
        self.connected = False
        self.connected_since = None
        self.last_request = 0.0
        self.last_message = None
        self.messages = 0
        self.error = None
        self.retry_after = 0.0
        self.gen = 0               # her yeni iş parçacığı kendi neslini taşır; nesil değişirse durur

    # ── istemci tarafı ──
    def ensure(self, bb, key, now=None):
        """bb alanının abonelikte olmasını sağlar; asla bloklamaz. Döner: kutu eklenme zamanı."""
        now = now or time.time()
        with self.lock:
            self.last_request = now
            if key != self.key:
                self._stop_locked()
                self.key, self.error, self.retry_after = key, None, 0.0
                self.thread = None
            box = next((b for b in self.boxes if bbox_contains(b["bb"], bb)), None)
            if box:
                box["used"] = now
            else:
                nb = pad_bbox(bb)
                self.boxes = [b for b in self.boxes if not bbox_contains(nb, b["bb"])]
                box = {"bb": nb, "added": now, "used": now}
                self.boxes.append(box)
                self.boxes.sort(key=lambda b: b["used"])
                self.boxes = self.boxes[-MAX_BOXES:]
                self.sub_version += 1
            self.boxes = [b for b in self.boxes if now - b["used"] < IDLE_CLOSE_S or b is box]
            alive = (self.thread is not None and self.thread.is_alive()
                     and getattr(self.thread, "_so_gen", None) == self.gen)
            if not alive and now >= self.retry_after:
                self.gen += 1
                self.thread = threading.Thread(target=self._run, args=(self.gen,),
                                               name="aisstream", daemon=True)
                self.thread._so_gen = self.gen
                self.thread.start()
            self.wake.set()
            return box["added"]

    def stop(self):
        with self.lock:
            self._stop_locked()

    def _stop_locked(self):
        self.gen += 1
        self.wake.set()
        self.boxes = []
        self.connected = False

    def coverage_since(self, lat, lon):
        """Bu nokta kesintisiz olarak ne zamandan beri izleniyor? (None = izlenmiyor)"""
        with self.lock:
            if not self.connected or not self.connected_since:
                return None
            ts = [max(b["added"], self.connected_since) for b in self.boxes if in_bbox(b["bb"], lat, lon)]
            return min(ts) if ts else None

    def status(self):
        with self.lock:
            return {"active": bool(self.thread and self.thread.is_alive()
                                   and getattr(self.thread, "_so_gen", None) == self.gen),
                    "connected": self.connected, "since": self.connected_since,
                    "messages": self.messages, "last_message": self.last_message,
                    "boxes": len(self.boxes), "error": self.error}

    # ── arka plan iş parçacığı ──
    def _should_stop(self, gen):
        with self.lock:
            if gen != self.gen:
                return True
            if time.time() - self.last_request > IDLE_CLOSE_S:
                self.boxes = []
                return True
            return False

    def _set(self, gen, **kw):
        """Durum yazımı yalnızca güncel nesil için (eski iş parçacığı yeni durumu ezmesin)."""
        with self.lock:
            if gen == self.gen:
                for k, v in kw.items():
                    setattr(self, k, v)

    def _run(self, gen):
        lib = _ws_lib()
        if lib is None:
            self._set(gen, error="websocket-client not installed (pip install websocket-client)")
            return
        backoff = 2.0
        while not self._should_stop(gen):
            ws = None
            try:
                with self.lock:
                    key, boxes, ver = self.key, [b["bb"] for b in self.boxes], self.sub_version
                if not boxes:
                    return
                ws = _ws_connect(lib, AISSTREAM_URL, 10)
                ws.send(_sub_message(key, boxes))          # bağlantıdan sonra 3 sn içinde gönderilmeli
                sent_at = time.time()
                ws.settimeout(1.0)
                self._set(gen, connected=True, connected_since=time.time(), error=None)
                while not self._should_stop(gen):
                    with self.lock:
                        cur_ver = self.sub_version
                        cur_boxes = [b["bb"] for b in self.boxes]
                    # abonelik güncellemesi: tam abonelik yeniden gönderilir, eskisinin yerini alır (≤ 1/sn)
                    if cur_ver != ver and cur_boxes and time.time() - sent_at >= 1.2:
                        ws.send(_sub_message(key, cur_boxes))
                        sent_at, ver = time.time(), cur_ver
                    try:
                        raw = ws.recv()
                    except Exception as e:
                        if _is_timeout(e):
                            continue
                        raise
                    if not raw:
                        raise ConnectionError("stream closed")
                    try:
                        msg = json.loads(raw)
                    except ValueError:
                        continue
                    if isinstance(msg, dict) and msg.get("error"):
                        raise PermissionError(str(msg.get("error"))[:200])
                    with self.lock:
                        if gen != self.gen:
                            break
                        self.messages += 1
                        self.last_message = time.time()
                    try:
                        ingest_aisstream(msg, self.store)
                    except Exception as e:      # tek bozuk mesaj akışı düşürmesin
                        print(f"[ais] ingest error: {e}")
                    backoff = 2.0
            except PermissionError as e:
                # geçersiz anahtar vb. → 60 sn boyunca yeniden deneme yok
                self._set(gen, error=f"aisstream: {e}", retry_after=time.time() + 60, connected=False)
                print(f"[ais] aisstream error: {e}")
                return
            except Exception as e:
                self._set(gen, error=f"aisstream connection: {type(e).__name__}", connected=False)
            finally:
                self._set(gen, connected=False)
                if ws is not None:
                    try: ws.close()
                    except Exception: pass
            if self._should_stop(gen):
                break
            self.wake.clear()
            self.wake.wait(backoff)
            backoff = min(backoff * 2, 60.0)
        self._set(gen, connected=False)


COLLECTOR = AisStreamCollector(STORE)


# ══════════════════════════════════════════════
#  Digitraffic Marine
# ══════════════════════════════════════════════
_dt_lock = threading.Lock()
_dt_cache = {"loc": None, "loc_ts": 0.0, "ves": None, "ves_ts": 0.0, "error": None, "ok_ts": 0.0}
DT_LOC_TTL, DT_VES_TTL = 60, 15 * 60


def _dt_get(url):
    r = requests.get(url, headers=DIGITRAFFIC_HEADERS, timeout=(4, 8))
    r.raise_for_status()
    return r.json()


def digitraffic_refresh(now=None):
    """Konum (60 sn) ve statik (15 dk) önbelleklerini gerekirse yeniler."""
    now = now or time.time()
    with _dt_lock:
        try:
            if now - _dt_cache["loc_ts"] >= DT_LOC_TTL or _dt_cache["loc"] is None:
                j = _dt_get(DIGITRAFFIC_LOC)
                feats = j.get("features") if isinstance(j, dict) else None
                if not isinstance(feats, list):
                    raise ValueError("unexpected locations payload")
                _dt_cache["loc"], _dt_cache["loc_ts"] = feats, now
            if now - _dt_cache["ves_ts"] >= DT_VES_TTL or _dt_cache["ves"] is None:
                try:
                    j = _dt_get(DIGITRAFFIC_VES)
                    if isinstance(j, list):
                        _dt_cache["ves"] = {str(v.get("mmsi")): v for v in j if isinstance(v, dict)}
                except Exception as e:                    # statik veri opsiyonel
                    print(f"[ais/digitraffic] vessels: {e}")
                _dt_cache["ves_ts"] = now
            _dt_cache["error"], _dt_cache["ok_ts"] = None, now
            return True
        except Exception as e:
            _dt_cache["error"] = f"{type(e).__name__}"
            print(f"[ais/digitraffic] {e}")
            return False


def digitraffic_ingest(bb, store=None):
    """Önbellekteki Digitraffic verisini bb içindekilerle depoya yazar. Döner: sayı."""
    store = store or STORE
    feats = _dt_cache.get("loc") or []
    meta = _dt_cache.get("ves") or {}
    n = 0
    for f in feats:
        try:
            p = f.get("properties") or {}
            coords = (f.get("geometry") or {}).get("coordinates") or []
            lon, lat = _f(coords[0]), _f(coords[1])
            if lat is None or lon is None or not in_bbox(bb, lat, lon):
                continue
            raw = p.get("mmsi", f.get("mmsi"))
            mmsi = str(_i(raw)).zfill(9) if _i(raw) is not None else None
            if not mmsi:
                continue
            ts_ms = _f(p.get("timestampExternal"))
            ts = ts_ms / 1000.0 if ts_ms else None
            store.update_position(mmsi, lat, lon, _norm_sog(p.get("sog")), _norm_cog(p.get("cog")),
                                  _norm_heading(p.get("heading")), _i(p.get("navStat")), ts,
                                  "digitraffic")
            v = meta.get(str(_i(raw)))
            if v:
                ln, wd = _dims(v.get("referencePointA"), v.get("referencePointB"),
                               v.get("referencePointC"), v.get("referencePointD"))
                imo = _i(v.get("imo"))
                dr = _f(v.get("draught"))
                store.update_static(
                    mmsi, "digitraffic", name=_clean_str(v.get("name")),
                    callsign=_clean_str(v.get("callSign"), 12),
                    imo=str(imo) if imo and 1000000 <= imo <= 9999999 else None,
                    ship_type=_i(v.get("shipType")), destination=_clean_str(v.get("destination")),
                    eta=_eta_digitraffic(v.get("eta")), length=ln, width=wd,
                    draught=(dr / 10.0) if dr else None)   # Digitraffic draught: 1/10 m
            n += 1
        except Exception:
            continue
    return n


# ══════════════════════════════════════════════
#  Birleşik çıktı + sezgisel bayraklar
# ══════════════════════════════════════════════
FLAG_WEIGHTS = {
    "invalid_mmsi": 35, "unknown_mid": 20, "emergency_device": 40, "speed_implausible": 25,
    "dark": 25, "identity_mismatch": 25, "position_jump": 30, "military": 15, "law_enforcement": 10,
}


def build_vessel(rec, now=None, coverage_fn=None):
    now = now or time.time()
    mmsi = rec["mmsi"]
    info = mmsi_info(mmsi)
    st = rec.get("ship_type")
    cat = ship_category(st)
    nav = rec.get("nav")
    sog = rec.get("sog")
    age = max(0.0, now - (rec.get("last_update") or now))
    flags, codes = [], []

    def add(code, text):
        codes.append(code); flags.append(text)

    if not info["valid"]:
        add("invalid_mmsi", f"Invalid MMSI — {info['problem']}")
    elif info["problem"]:
        add("unknown_mid", f"Unknown flag code — {info['problem']}")
    if info["kind"] in ("sart", "mob", "epirb") or nav == 14:
        add("emergency_device", "Emergency device (AIS-SART / MOB / EPIRB) transmitting")
    if info["kind"] == "sar_aircraft" and cat == "other":
        cat = "sar"
    hsc = st is not None and 40 <= st <= 49
    if sog is not None and sog > 50 and not hsc and info["kind"] != "sar_aircraft":
        add("speed_implausible", f"Reported speed {sog} kn is implausible for this vessel type")
    if age > DARK_AFTER_S and (rec.get("was_moving") or (sog or 0) >= 1.0):
        cov = coverage_fn(rec["lat"], rec["lon"]) if coverage_fn else None
        if cov is not None and cov <= rec.get("last_update", now):
            add("dark", f"No reports for {int(age // 60)} min while previously moving (area still covered)")
    names = rec.get("names") or []
    if len(names) > 1:
        add("identity_mismatch", "Same MMSI seen with different names: " + " / ".join(names[-3:]))
    if rec.get("jump"):
        j = rec["jump"]
        add("position_jump", f"Position jump {j['km']} km in {j['seconds']} s (≈{j['implied_kn']} kn)")
    if st == 35:
        add("military", "Declares military operations type (informational)")
    elif st == 55:
        add("law_enforcement", "Declares law-enforcement type (informational)")
    risk = min(100, sum(FLAG_WEIGHTS.get(c, 0) for c in codes))

    return {
        "type": "vessel",
        "mmsi": mmsi,
        "name": rec.get("name") or rec.get("name_hint"),
        "callsign": rec.get("callsign"),
        "imo": rec.get("imo"),
        "lat": round(rec["lat"], 6), "lon": round(rec["lon"], 6),
        "sog": sog, "cog": rec.get("cog"), "heading": rec.get("heading"),
        "nav_status": {"code": nav, "text": NAV_STATUS.get(nav, "Unknown") if nav is not None else None},
        "ship_type": st, "ship_type_name": ship_type_name(st) if st is not None else "Unknown",
        "category": cat,
        "destination": rec.get("destination"), "eta": rec.get("eta"),
        "length": rec.get("length"), "width": rec.get("width"), "draught": rec.get("draught"),
        "flag_country": info["iso2"], "flag_country_name": info["country"],
        "mmsi_kind": info["kind"],
        "source": rec.get("last_source"), "sources": rec.get("sources") or [],
        "last_update": int(rec.get("last_update") or now), "age_s": int(age),
        "stale": age > STALE_UI_S,
        "risk": risk, "flags": flags, "flag_codes": codes,
        "names_seen": names,
    }


def summarize(vessels):
    by_type, moving, anchored, suspicious = {}, 0, 0, 0
    for v in vessels:
        by_type[v["category"]] = by_type.get(v["category"], 0) + 1
        nav = (v.get("nav_status") or {}).get("code")
        if (v.get("sog") or 0) >= 1.0 and nav not in (1, 5):
            moving += 1
        elif nav in (1, 5) or (v.get("sog") is not None and v["sog"] < 0.5):
            anchored += 1
        if any(FLAG_WEIGHTS.get(c, 0) >= 20 for c in v["flag_codes"]):
            suspicious += 1
    return {"by_type": by_type, "moving": moving, "anchored": anchored, "suspicious": suspicious}


# ══════════════════════════════════════════════
#  Rotalar
# ══════════════════════════════════════════════
def _aisstream_key():
    try:
        return (_ctx.get_key("AISSTREAM_API_KEY") if _ctx else "") or ""
    except Exception:
        return ""


def _arg_float(name):
    try:
        v = float(request.args.get(name))
        return v if math.isfinite(v) else None
    except (TypeError, ValueError):
        return None


def page_maritime():
    return render_template("maritime.html", active="Maritime")


def api_ais():
    validate = _ctx.validate_coords if _ctx else (lambda a, b: (a, b))
    lat, lon = validate(request.args.get("lat"), request.args.get("lon"))
    if lat is None:
        return jsonify({"error": "Valid lat/lon required"}), 400
    r = _arg_float("radius_km")
    radius = 50.0 if r is None else max(5.0, min(200.0, r))
    t0 = time.time()
    bb = bbox_around(lat, lon, radius)
    STORE.prune()

    # ── aisstream ──
    key = _aisstream_key().strip()
    lib_ok = _ws_lib() is not None
    ais_src = {"available": lib_ok, "configured": bool(key), "active": False, "connected": False,
               "count": 0, "since": None, "error": None, "hint": None}
    box_added = None
    if not lib_ok:
        ais_src["hint"] = "pip install websocket-client"
    elif not key:
        ais_src["hint"] = "Add an aisstream.io key in Settings → Maritime"
    else:
        box_added = COLLECTOR.ensure(bb, key, t0)

    # ── Digitraffic ──
    dt_cov = bbox_intersects(bb, DIGITRAFFIC_COVER)
    dt_src = {"active": dt_cov, "ok": None, "count": 0, "fetched_at": None, "error": None}
    if dt_cov:
        ok = None
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            fut = pool.submit(digitraffic_refresh)
            gather = getattr(_ctx, "gather_futures", None)
            if gather:
                ok = gather({fut: "digitraffic"}, REQUEST_BUDGET_S - 1.5, "ais").get("digitraffic")
            else:
                ok = fut.result(timeout=REQUEST_BUDGET_S - 1.5)
        except Exception:
            ok = None
        finally:
            pool.shutdown(wait=False)
        dt_src["ok"] = bool(ok) if ok is not None else False
        dt_src["error"] = _dt_cache.get("error") if not ok else None
        if ok is None and not dt_src["error"]:
            dt_src["error"] = "timeout (using cached data)"
        dt_src["fetched_at"] = int(_dt_cache["loc_ts"]) or None
        if _dt_cache.get("loc"):
            digitraffic_ingest(bb)

    # ── akış yeni başladıysa kısa bekleme (ilk mesajlar) ──
    st = COLLECTOR.status() if box_added else None
    just_started = bool(box_added) and (t0 - box_added) < 1.0
    if just_started:
        deadline = t0 + 3.0
        while time.time() < deadline:
            st = COLLECTOR.status()
            if st["error"] or STORE.query(bb, (lat, lon), radius):
                break
            time.sleep(0.25)
        st = COLLECTOR.status()

    now = time.time()
    recs = STORE.query(bb, (lat, lon), radius)
    vessels = [build_vessel(rec, now, COLLECTOR.coverage_since) for rec in recs]
    vessels.sort(key=lambda v: (-v["risk"], v["age_s"]))

    if st:
        ais_src.update(active=st["active"], connected=st["connected"], since=st["since"],
                       error=st["error"], messages=st["messages"], last_message=st["last_message"])
    ais_src["count"] = sum(1 for v in vessels if "aisstream" in v["sources"])
    dt_src["count"] = sum(1 for v in vessels if "digitraffic" in v["sources"])

    warming = bool(box_added) and not ais_src["error"] and (
        (now - box_added) < WARMUP_S or not ais_src["connected"])
    coverage = bool(box_added) or dt_cov
    return jsonify({
        "center": {"lat": lat, "lon": lon}, "radius_km": radius,
        "bbox": [round(x, 4) for x in bb],
        "vessels": vessels, "total": len(vessels),
        "sources": {"aisstream": ais_src, "digitraffic": dt_src},
        "warming_up": warming, "coverage": coverage,
        "summary": summarize(vessels),
        "heuristic_note": "Flags are heuristics, not proof.",
        "generated_at": int(now),
    })


# ══════════════════════════════════════════════
#  Ayarlar → bağlantı testi
# ══════════════════════════════════════════════
def _key_test_aisstream(seconds=4.0):
    lib = _ws_lib()
    if lib is None:
        return False, "websocket-client not installed (pip install websocket-client)"
    key = _aisstream_key().strip()
    if not key:
        return False, "Anahtar eksik — önce kaydet"
    ws = None
    try:
        ws = _ws_connect(lib, AISSTREAM_URL, 8)
        # küçük kutu: İstanbul Boğazı
        ws.send(_sub_message(key, [(41.0, 28.95, 41.25, 29.15)]))
        ws.settimeout(1.0)
        end, n = time.time() + seconds, 0
        while time.time() < end:
            try:
                raw = ws.recv()
            except Exception as e:
                if _is_timeout(e):
                    continue
                return False, f"Connection closed by server ({type(e).__name__}) — key rejected?"
            if not raw:
                return False, "Connection closed by server — key rejected?"
            try:
                m = json.loads(raw)
            except ValueError:
                continue
            if isinstance(m, dict) and m.get("error"):
                return False, str(m["error"])[:120]
            n += 1
        return True, f"OK — connected, {n} message(s) in {seconds:g} s"
    except Exception as e:
        return False, f"Bağlantı hatası: {type(e).__name__}"
    finally:
        if ws is not None:
            try: ws.close()
            except Exception: pass


def init(app, ctx):
    global _ctx
    _ctx = ctx
    if "ais" not in app.blueprints:
        rl = getattr(ctx, "rate_limit", None) or (lambda spec: (lambda f: f))
        bp.add_url_rule("/maritime", "page_maritime", page_maritime)
        bp.add_url_rule("/api/ais", "api_ais", rl("40 per minute")(api_ais))
        app.register_blueprint(bp)
    ctx.register_key_test("aisstream", ("AISSTREAM_KEY",), _key_test_aisstream)
