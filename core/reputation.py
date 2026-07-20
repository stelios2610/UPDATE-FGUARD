"""Reputation Enabled Defense (RED) + IP Geolocation + Anti-DDoS.
WatchGuard RED equivalent using open-source threat intel feeds."""
import os
import threading
import time
import ipaddress
import json
import urllib.request
from collections import defaultdict, deque
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

# ── Threat intel feeds (free/open-source) ────────────────────────────────────
FEED_URLS = {
    "emerging_threats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "feodo_tracker":    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "spamhaus_drop":    "https://www.spamhaus.org/drop/drop.txt",
    "firehol_1":        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
}

_blocklist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "blocklist.txt")
_geo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "geoip.json")
_blocked_ips = set()
_blocked_nets = []
_geo_data = {}

# ── Anti-DDoS state ───────────────────────────────────────────────────────────
_rate_tracker = defaultdict(lambda: deque(maxlen=1000))
_ddos_blocked = set()
_ddos_callbacks = []
_ddos_config = {
    "enabled": True,
    "pps_threshold": 500,       # packets/sec per IP
    "conns_threshold": 100,     # concurrent connections per IP
    "syn_threshold": 200,       # SYN packets/sec per IP
    "block_duration": 300,      # seconds to block
    "whitelist": {"127.0.0.1", "::1"},
}


def register_ddos_callback(fn):
    _ddos_callbacks.append(fn)


def _fire_ddos(event):
    for fn in _ddos_callbacks:
        try:
            fn(event)
        except Exception:
            pass


# ── Blocklist management ──────────────────────────────────────────────────────

def ensure_data_dir():
    d = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
    os.makedirs(d, exist_ok=True)
    return d


def update_blocklists():
    """Download and merge all threat intelligence feeds."""
    ensure_data_dir()
    all_ips = set()
    results = {}

    for feed_name, url in FEED_URLS.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "FGUARD-UTC/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                content = r.read().decode("utf-8", errors="ignore")
            count = 0
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                ip = line.split()[0] if " " in line else line
                if _is_valid_ip_or_cidr(ip):
                    all_ips.add(ip)
                    count += 1
            results[feed_name] = count
        except Exception as e:
            results[feed_name] = f"Error: {e}"

    with open(_blocklist_path, "w") as f:
        f.write("\n".join(sorted(all_ips)))

    database.add_log("INFO", details=f"Blocklist updated: {sum(v for v in results.values() if isinstance(v,int))} IPs from {len(FEED_URLS)} feeds")
    _load_blocklist()
    return results


def _is_valid_ip_or_cidr(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _load_blocklist():
    global _blocked_ips, _blocked_nets
    _blocked_ips = set()
    _blocked_nets = []
    if not os.path.isfile(_blocklist_path):
        return
    with open(_blocklist_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.prefixlen == 32:
                    _blocked_ips.add(str(net.network_address))
                else:
                    _blocked_nets.append(net)
            except ValueError:
                pass


def is_ip_blocked(ip):
    """Check if IP is in reputation blocklist."""
    if ip in _blocked_ips:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _blocked_nets)
    except ValueError:
        return False


def get_blocklist_stats():
    return {
        "total_ips": len(_blocked_ips),
        "total_networks": len(_blocked_nets),
        "file_exists": os.path.isfile(_blocklist_path),
        "file_mtime": datetime.fromtimestamp(
            os.path.getmtime(_blocklist_path)).isoformat() if os.path.isfile(_blocklist_path) else "",
    }


# ── Geolocation ───────────────────────────────────────────────────────────────

def update_geo_db():
    """Download MaxMind GeoLite2 country DB (free, requires license key in settings)."""
    key = database.get_setting("maxmind_license_key", "")
    if not key:
        # Fallback: use ip-api.com for individual lookups (free, no key needed)
        return False, "Set maxmind_license_key in Settings for offline GeoIP, or use live lookup"
    ensure_data_dir()
    url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key={key}&suffix=zip"
    try:
        urllib.request.urlretrieve(url, _geo_path + ".zip")
        import zipfile
        with zipfile.ZipFile(_geo_path + ".zip") as z:
            z.extractall(os.path.dirname(_geo_path))
        return True, "GeoLite2 database updated"
    except Exception as e:
        return False, str(e)


def lookup_ip(ip):
    """Lookup IP geolocation. Uses ip-api.com (free, 45 req/min limit)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting"
        req = urllib.request.Request(url, headers={"User-Agent": "FGUARD-UTC/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        return data
    except Exception:
        return {"status": "fail", "country": "Unknown", "countryCode": "XX"}


def lookup_ip_cache(ip):
    """Cached IP lookup."""
    if not _geo_data.get(ip):
        _geo_data[ip] = lookup_ip(ip)
    return _geo_data[ip]


def get_blocked_countries():
    conn = database.get_connection()
    rows = conn.execute("SELECT value FROM settings WHERE key = 'blocked_countries'").fetchone()
    conn.close()
    if rows and rows["value"]:
        try:
            return json.loads(rows["value"])
        except Exception:
            pass
    return []


def is_country_blocked(ip):
    blocked = get_blocked_countries()
    if not blocked:
        return False
    geo = lookup_ip_cache(ip)
    return geo.get("countryCode", "XX") in blocked


# ── Anti-DDoS ─────────────────────────────────────────────────────────────────

def record_connection(ip, timestamp=None):
    """Record a connection attempt. Call this for every new connection."""
    if not _ddos_config["enabled"]:
        return False
    if ip in _ddos_config["whitelist"]:
        return False
    now = timestamp or time.time()
    _rate_tracker[ip].append(now)
    return _check_ddos(ip, now)


def _check_ddos(ip, now):
    times = _rate_tracker[ip]
    recent_1s = sum(1 for t in times if now - t < 1.0)
    recent_10s = sum(1 for t in times if now - t < 10.0)

    triggered = False
    reason = ""

    if recent_1s >= _ddos_config["pps_threshold"]:
        triggered = True
        reason = f"PPS flood: {recent_1s} packets/sec"
    elif recent_10s >= _ddos_config["conns_threshold"] * 5:
        triggered = True
        reason = f"Connection flood: {recent_10s} in 10s"

    if triggered and ip not in _ddos_blocked:
        _ddos_blocked.add(ip)
        database.add_log("THREAT", src_ip=ip, rule_name="Anti-DDoS",
                         details=f"DDoS blocked: {reason}")
        alert = {"ip": ip, "reason": reason, "timestamp": datetime.now().isoformat()}
        _fire_ddos(alert)
        if IS_LINUX:
            _block_ip_kernel(ip)
        threading.Timer(_ddos_config["block_duration"], lambda: _unblock_ddos(ip)).start()
        return True
    return False


def _block_ip_kernel(ip):
    run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])


def _unblock_ddos(ip):
    _ddos_blocked.discard(ip)
    if IS_LINUX:
        run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])


def get_ddos_stats():
    return {
        "blocked_count": len(_ddos_blocked),
        "blocked_ips": list(_ddos_blocked),
        "config": _ddos_config,
        "tracking_count": len(_rate_tracker),
    }


def update_ddos_config(**kwargs):
    _ddos_config.update(kwargs)


def get_ddos_blocked():
    return list(_ddos_blocked)


def unblock_ip(ip):
    _ddos_blocked.discard(ip)
    if IS_LINUX:
        run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])


# ── Init ──────────────────────────────────────────────────────────────────────

def init():
    ensure_data_dir()
    _load_blocklist()
    # Auto-download on first run if no blocklist exists
    if not os.path.isfile(_blocklist_path):
        t = threading.Thread(target=update_blocklists, daemon=True)
        t.start()


init()
