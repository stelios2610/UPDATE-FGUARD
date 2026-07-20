"""Web Filter - domain blocking via dnsmasq (Linux) or hosts file (Windows)."""
import os
import re
import subprocess
from db import database
from core.platform import IS_LINUX, run

HOSTS_PATH      = "/etc/hosts" if IS_LINUX else r"C:\Windows\System32\drivers\etc\hosts"
DNSMASQ_FILTER  = "/etc/dnsmasq.d/aegisguard-filter.conf"
MARKER_BEGIN    = "# AegisGuard Web Filter BEGIN"
MARKER_END      = "# AegisGuard Web Filter END"

BUILTIN_CATEGORIES = {
    "Adult Content": [
        "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "youporn.com",
        "tube8.com", "xhamster.com", "beeg.com", "brazzers.com", "hentai.tv",
        "porn.com", "sex.com", "adult.com", "xxx.com",
    ],
    "Gambling": [
        "bet365.com", "pokerstars.com", "888casino.com", "betway.com",
        "draftkings.com", "fanduel.com", "caesarsonline.com", "unibet.com",
        "paddypower.com", "williamhill.com", "ladbrokes.com", "bwin.com",
    ],
    "Social Media": [
        "facebook.com", "instagram.com", "twitter.com", "x.com",
        "tiktok.com", "snapchat.com", "pinterest.com", "linkedin.com",
        "reddit.com", "tumblr.com", "discord.com", "telegram.org",
        "whatsapp.com", "threads.net", "mastodon.social", "vk.com",
    ],
    "Streaming": [
        "netflix.com", "youtube.com", "twitch.tv", "hulu.com",
        "disneyplus.com", "primevideo.com", "spotify.com", "soundcloud.com",
        "vimeo.com", "dailymotion.com", "crunchyroll.com", "hbomax.com",
        "peacocktv.com", "paramountplus.com", "appletv.apple.com",
    ],
    "Gaming": [
        "store.steampowered.com", "battle.net", "epicgames.com",
        "roblox.com", "minecraft.net", "origin.com", "ubisoft.com",
        "gog.com", "itch.io", "xbox.com",
    ],
    "Malware": [
        "malware-domain.com", "ransomware.site", "cryptolocker.biz",
        "trojandownloader.net", "botnet-cc.ru",
    ],
    "Phishing": [
        "phishing-example.com", "fake-paypal.com", "secure-login-update.com",
    ],
    "Anonymizers": [
        "hidemyass.com", "vpnbook.com", "hotspotshield.com",
        "torproject.org", "proxyfree.com", "proxysite.com",
        "hide.me", "tunnelbear.com", "protonvpn.com",
    ],
    "Hacking": [
        "exploitdb.com", "hackforums.net", "nulled.to",
        "crackingking.com", "hackthissite.org",
    ],
    "Ads & Tracking": [
        "doubleclick.net", "googleadservices.com", "googlesyndication.com",
        "scorecardresearch.com", "quantserve.com", "adnxs.com", "adsrvr.org",
        "moatads.com", "outbrain.com", "taboola.com", "advertising.com",
        "ads.yahoo.com", "cdn.taboola.com", "pixel.advertising.com",
        "criteo.com", "pubmatic.com", "rubiconproject.com",
    ],
}


def _get_blocked_domains():
    """Collect all enabled blocked domains from categories + custom filters."""
    blocked = set()
    categories = {c["name"]: c["enabled"] for c in database.get_web_categories()}
    for cat, domains in BUILTIN_CATEGORIES.items():
        if categories.get(cat, 1):
            blocked.update(domains)
    for f in database.get_web_filters():
        if f["enabled"] and f["action"] == "BLOCK":
            pattern = re.sub(r"^https?://", "", f["pattern"].strip().lower()).split("/")[0]
            if pattern:
                blocked.add(pattern)
    return blocked


# ── dnsmasq filter (Linux primary method) ────────────────────────────────────

def _write_dnsmasq_filter(domains):
    """Write /etc/dnsmasq.d/aegisguard-filter.conf with address= entries."""
    lines = ["# AegisGuard Web Filter — auto-generated", ""]
    for domain in sorted(domains):
        lines.append(f"address=/{domain}/0.0.0.0")
        lines.append(f"address=/{domain}/::")   # IPv6
    try:
        with open(DNSMASQ_FILTER, "w") as f:
            f.write("\n".join(lines) + "\n")
        return True, f"{len(domains)} domains written to dnsmasq"
    except Exception as e:
        return False, str(e)


def _remove_dnsmasq_filter():
    try:
        if os.path.isfile(DNSMASQ_FILTER):
            os.unlink(DNSMASQ_FILTER)
        return True, "dnsmasq filter removed"
    except Exception as e:
        return False, str(e)


# ── hosts file (fallback / Windows) ──────────────────────────────────────────

def _read_hosts():
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except PermissionError:
        return None
    except FileNotFoundError:
        return ""


def _write_hosts(content):
    try:
        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        return True, "OK"
    except PermissionError:
        msg = "Permission denied — run as root" if IS_LINUX else "Permission denied — run as Administrator"
        return False, msg
    except Exception as e:
        return False, str(e)


def _strip_aegisguard_block(content):
    lines, result, inside = content.splitlines(keepends=True), [], False
    for line in lines:
        if MARKER_BEGIN in line:
            inside = True; continue
        if MARKER_END in line:
            inside = False; continue
        if not inside:
            result.append(line)
    return "".join(result)


def _write_hosts_filter(domains):
    current = _read_hosts()
    if current is None:
        return False, "Cannot read hosts file (permission denied)"
    clean = _strip_aegisguard_block(current)
    if not clean.endswith("\n"):
        clean += "\n"
    block_lines = [f"\n{MARKER_BEGIN}\n"]
    for domain in sorted(domains):
        block_lines.append(f"0.0.0.0 {domain}\n")
        block_lines.append(f"0.0.0.0 www.{domain}\n")
    block_lines.append(f"{MARKER_END}\n")
    return _write_hosts(clean + "".join(block_lines))


# ── DNS redirect (force all LAN DNS through dnsmasq) ─────────────────────────

def _get_lan_interfaces():
    """Return list of LAN interface names from DHCP configs + enabled VLANs."""
    ifaces = []
    for cfg in database.get_dhcp_configs():
        if cfg.get("enabled") and cfg.get("interface"):
            ifaces.append(cfg["interface"])
    for v in database.get_vlans():
        if v.get("enabled"):
            ifaces.append(f"{v['parent_interface']}.{v['vlan_id']}")
    return list(dict.fromkeys(ifaces))  # deduplicate, preserve order


def _apply_dns_redirect():
    """Force all DNS queries from LAN clients through local dnsmasq."""
    for iface in _get_lan_interfaces():
        for proto in ("udp", "tcp"):
            ok, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING",
                            "-i", iface, "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
            if not ok:
                run(["iptables", "-t", "nat", "-A", "PREROUTING",
                     "-i", iface, "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        # Block DNS-over-TLS (port 853) — insert at top so it fires before ACCEPT rules
        for proto in ("tcp", "udp"):
            ok, _, _ = run(["iptables", "-C", "FORWARD",
                            "-i", iface, "-p", proto, "--dport", "853", "-j", "DROP"])
            if not ok:
                run(["iptables", "-I", "FORWARD", "1",
                     "-i", iface, "-p", proto, "--dport", "853", "-j", "DROP"])


def _remove_dns_redirect():
    for iface in _get_lan_interfaces():
        for proto in ("udp", "tcp"):
            run(["iptables", "-t", "nat", "-D", "PREROUTING",
                 "-i", iface, "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        for proto in ("tcp", "udp"):
            run(["iptables", "-D", "FORWARD",
                 "-i", iface, "-p", proto, "--dport", "853", "-j", "DROP"])


# ── DoH blocking (force DNS-over-HTTPS clients back to plain DNS) ─────────────

# Known DoH provider IPs — blocking port 443 to these forces clients to fall
# back to plain DNS (port 53), which is then intercepted by the PREROUTING rule.
_DOH_IPS = [
    "8.8.8.8", "8.8.4.4",           # Google
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15", # AdGuard
]


def _apply_doh_block():
    for iface in _get_lan_interfaces():
        for ip in _DOH_IPS:
            for proto in ("tcp", "udp"):
                ok, _, _ = run(["iptables", "-C", "FORWARD",
                                "-i", iface, "-p", proto, "-d", ip, "--dport", "443", "-j", "DROP"])
                if not ok:
                    run(["iptables", "-I", "FORWARD", "1",
                         "-i", iface, "-p", proto, "-d", ip, "--dport", "443", "-j", "DROP"])


def _remove_doh_block():
    for iface in _get_lan_interfaces():
        for ip in _DOH_IPS:
            for proto in ("tcp", "udp"):
                run(["iptables", "-D", "FORWARD",
                     "-i", iface, "-p", proto, "-d", ip, "--dport", "443", "-j", "DROP"])


# ── QUIC blocking (force HTTP/3 clients back to HTTP/2 so DNS is re-resolved) ─
# Browsers fall back to TCP:443 (HTTP/2) automatically when UDP:443 is dropped.
# HTTP/2 requires a fresh DNS lookup → dnsmasq intercepts → blocked domains fail.

def _apply_quic_block():
    for iface in _get_lan_interfaces():
        ok, _, _ = run(["iptables", "-C", "FORWARD",
                        "-i", iface, "-p", "udp", "--dport", "443", "-j", "DROP"])
        if not ok:
            run(["iptables", "-I", "FORWARD", "1",
                 "-i", iface, "-p", "udp", "--dport", "443", "-j", "DROP"])


def _remove_quic_block():
    for iface in _get_lan_interfaces():
        run(["iptables", "-D", "FORWARD",
             "-i", iface, "-p", "udp", "--dport", "443", "-j", "DROP"])


# ── Public API ────────────────────────────────────────────────────────────────

def apply_filters():
    """Apply web filter. On Linux: dnsmasq + hosts. On Windows: hosts only."""
    if database.get_setting("web_filter_enabled", "1") != "1":
        return remove_filters()

    domains = _get_blocked_domains()

    if IS_LINUX:
        ok, msg = _write_dnsmasq_filter(domains)
        _write_hosts_filter(domains)
        run(["systemctl", "restart", "dnsmasq"])
        _apply_dns_redirect()
        _apply_doh_block()
        _apply_quic_block()
        database.add_log("INFO", details=f"Web filter applied: {len(domains)} domains blocked via dnsmasq + DoH/QUIC blocked")
        return ok, msg

    ok, msg = _write_hosts_filter(domains)
    if ok:
        database.add_log("INFO", details=f"Web filter applied: {len(domains)} domains blocked via hosts file")
    return ok, msg


def remove_filters():
    """Remove web filter."""
    if IS_LINUX:
        _remove_dnsmasq_filter()
        _remove_dns_redirect()
        _remove_doh_block()
        _remove_quic_block()
        run(["systemctl", "restart", "dnsmasq"])
    current = _read_hosts()
    if current:
        _write_hosts(_strip_aegisguard_block(current))
    database.add_log("INFO", details="Web filter removed")
    return True, "Web filter removed"


def flush_dns():
    """Flush DNS cache."""
    try:
        if IS_LINUX:
            run(["systemctl", "restart", "dnsmasq"])
            for cmd in [["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"]]:
                subprocess.run(cmd, capture_output=True, timeout=5)
            return True
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
        return True
    except Exception:
        return False


def get_blocked_count():
    return len(_get_blocked_domains())


def get_hosts_status():
    if IS_LINUX and os.path.isfile(DNSMASQ_FILTER):
        try:
            lines = [l for l in open(DNSMASQ_FILTER).readlines() if l.startswith("address=")]
            # Each domain has 2 lines (IPv4 + IPv6), count unique domains
            domains = len(lines) // 2
            return "active", domains
        except Exception:
            pass
    content = _read_hosts()
    if content is None:
        return "error", 0
    if MARKER_BEGIN in content:
        count = sum(1 for l in content.splitlines() if l.startswith("0.0.0.0"))
        return "active", count
    return "inactive", 0
