"""Geoblock — network-level country blocking via ipset + iptables.

Reads blocked_countries from DB, builds a whitelist ipset of allowed
country CIDRs, and installs a DROP rule in AEGISGUARD_INPUT so all
WAN traffic from blocked countries is silently dropped before reaching
any service.  VPN ports (1194, 51820, 500, 4500) are always allowed
regardless of country so the admin can connect from anywhere.
"""
import os
import json
import urllib.request
import subprocess
import time
from db import database
from core.platform import IS_LINUX, run

IPSET_NAME   = "geo_allowed"
IPSET_SAVE   = "/etc/ipset.d/geo_allowed.ipset"
CHAIN        = "AEGISGUARD_INPUT"
WAN_IFACE    = None          # auto-detected from DB
COMMENT_TAG  = "aegis_geoblock"

# Ports that must stay open regardless of country (VPN access from abroad)
_VPN_PORTS = [
    ("udp", "1194"),   # OpenVPN
    ("tcp", "1194"),   # OpenVPN TCP
    ("udp", "51820"),  # WireGuard
    ("udp", "500"),    # IPSec IKE
    ("udp", "4500"),   # IPSec NAT-T
]

# Country CIDR source: ipdeny.com (free, no key needed)
_CIDR_URL = "https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone"


def _get_wan_iface():
    global WAN_IFACE
    if WAN_IFACE:
        return WAN_IFACE
    # Primary: read from default route (authoritative — always current)
    r = subprocess.run("ip route show default", shell=True, capture_output=True, text=True)
    tokens = r.stdout.split()
    if "dev" in tokens:
        idx = tokens.index("dev")
        if idx + 1 < len(tokens):
            WAN_IFACE = tokens[idx + 1]
            return WAN_IFACE
    # Fallback: DB setting
    try:
        ifaces = database.get_interfaces()
        for i in ifaces:
            if i.get("type") == "WAN" or i.get("role") == "WAN":
                name = i.get("name", "")
                # Only use if interface actually exists
                if name and os.path.exists("/sys/class/net/" + name):
                    WAN_IFACE = name
                    return WAN_IFACE
    except Exception:
        pass
    WAN_IFACE = "ens1"
    return WAN_IFACE


def _get_allowed_countries():
    """Return list of 2-letter country codes that are NOT blocked."""
    raw = database.get_setting("blocked_countries", "[]")
    try:
        blocked = set(json.loads(raw))
    except Exception:
        blocked = set()
    # All ISO 3166-1 alpha-2 codes
    ALL_COUNTRIES = [
        "AF","AX","AL","DZ","AS","AD","AO","AI","AQ","AG","AR","AM","AW","AU","AT","AZ",
        "BS","BH","BD","BB","BY","BE","BZ","BJ","BM","BT","BO","BA","BW","BR","BN","BG",
        "BF","BI","CV","KH","CM","CA","KY","CF","TD","CL","CN","CO","KM","CG","CD","CR",
        "CI","HR","CU","CW","CY","CZ","DK","DJ","DM","DO","EC","EG","SV","GQ","ER","EE",
        "SZ","ET","FK","FO","FJ","FI","FR","GF","PF","GA","GM","GE","DE","GH","GI","GL",
        "GD","GP","GU","GT","GG","GN","GW","GY","HT","HN","HK","HU","IS","IN","ID","IR",
        "IQ","IE","IM","IL","IT","JM","JP","JE","JO","KZ","KE","KI","KP","KR","XK","KW",
        "KG","LA","LV","LB","LS","LR","LY","LI","LT","LU","MO","MG","MW","MY","MV","ML",
        "MT","MH","MQ","MR","MU","YT","MX","FM","MD","MC","MN","ME","MS","MA","MZ","MM",
        "NA","NR","NP","NL","NC","NZ","NI","NE","NG","NU","NF","MK","MP","NO","OM","PK",
        "PW","PS","PA","PG","PY","PE","PH","PN","PL","PT","PR","QA","RE","RO","RU","RW",
        "BL","SH","KN","LC","MF","PM","VC","WS","SM","ST","SA","SN","RS","SC","SL","SG",
        "SX","SK","SI","SB","SO","ZA","SS","ES","LK","SD","SR","SJ","SE","CH","SY","TW",
        "TJ","TZ","TH","TL","TG","TK","TO","TT","TN","TR","TM","TC","TV","UG","UA","AE",
        "GB","US","UY","UZ","VU","VE","VN","VG","VI","WF","EH","YE","ZM","ZW",
        "GR","CY","EU",  # always include GR + a few extras as safety
    ]
    allowed = [cc for cc in ALL_COUNTRIES if cc not in blocked]
    return list(set(allowed))


def _download_cidrs(cc):
    """Download CIDR list for a country code. Returns list of CIDR strings."""
    url = _CIDR_URL.format(cc=cc.lower())
    try:
        req = urllib.request.urlopen(url, timeout=15)
        data = req.read().decode("utf-8", errors="ignore")
        cidrs = [l.strip() for l in data.splitlines() if l.strip() and not l.startswith("#")]
        return cidrs
    except Exception:
        return []


def apply_geoblock():
    """Download country CIDRs, build ipset, install iptables rules."""
    if not IS_LINUX:
        return False, "Geoblock requires Linux"

    wan = _get_wan_iface()
    allowed = _get_allowed_countries()

    if not allowed:
        return False, "No allowed countries — would block everything including LAN"

    print("Allowed countries: %s" % allowed)
    print("Downloading country CIDRs...")

    # Collect all CIDRs for allowed countries
    all_cidrs = []
    for cc in allowed:
        cidrs = _download_cidrs(cc)
        if cidrs:
            all_cidrs.extend(cidrs)
            print("  %s: %d ranges" % (cc, len(cidrs)))
        else:
            print("  %s: no data (skipped)" % cc)

    if not all_cidrs:
        return False, "Could not download any country CIDR data"

    # Deduplicate
    all_cidrs = list(set(all_cidrs))
    print("Total CIDRs: %d" % len(all_cidrs))

    # Create/replace ipset
    subprocess.run("ipset destroy %s 2>/dev/null" % IPSET_NAME, shell=True)
    r = subprocess.run("ipset create %s hash:net maxelem 131072" % IPSET_NAME,
                       shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        return False, "ipset create failed: " + r.stderr

    for cidr in all_cidrs:
        subprocess.run("ipset add %s %s 2>/dev/null" % (IPSET_NAME, cidr), shell=True)

    count = int(subprocess.run("ipset list %s | grep -c '/' 2>/dev/null" % IPSET_NAME,
                               shell=True, capture_output=True, text=True).stdout.strip() or "0")
    print("ipset populated: %d entries" % count)

    # Save ipset for persistence
    os.makedirs("/etc/ipset.d", exist_ok=True)
    subprocess.run("ipset save %s > %s" % (IPSET_NAME, IPSET_SAVE), shell=True)

    # Rebuild AEGISGUARD_INPUT chain with geoblock
    _apply_chain_rules(wan)

    # Save iptables rules
    subprocess.run("netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null", shell=True)

    # Install ipset restore on boot
    _install_persistence()

    database.set_setting("geoblock_enabled", "1")
    database.add_log("INFO", details="Geoblock applied: %d allowed CIDRs from %s" % (count, str(allowed)))
    return True, "Geoblock active: %d CIDRs, allowed countries: %s" % (count, ", ".join(allowed))


def _apply_chain_rules(wan):
    """Rebuild AEGISGUARD_INPUT with proper geoblock rules."""
    # Flush chain
    subprocess.run("iptables -F %s" % CHAIN, shell=True)

    def ipt(args):
        subprocess.run("iptables -A %s %s" % (CHAIN, args), shell=True)

    # 1. Always allow established/related (responses to server's outbound)
    ipt("-m state --state RELATED,ESTABLISHED -j ACCEPT")

    # 2. LAN traffic: skip geoblock (RETURN to INPUT chain)
    ipt("! -i %s -j RETURN" % wan)

    # 3. VPN ports: always open from any country (admin can connect from abroad)
    for proto, port in _VPN_PORTS:
        ipt("-i %s -p %s --dport %s -j ACCEPT" % (wan, proto, port))

    # 4. Allow IPs from allowed countries
    ipt("-i %s -m set --match-set %s src -j ACCEPT" % (wan, IPSET_NAME))

    # 5. DROP everything else from WAN
    ipt("-i %s -j DROP" % wan)

    print("AEGISGUARD_INPUT chain rebuilt with geoblock")


def remove_geoblock():
    """Remove geoblock — restore open access."""
    if not IS_LINUX:
        return False, "Not Linux"

    wan = _get_wan_iface()

    # Rebuild chain without geoblock
    subprocess.run("iptables -F %s" % CHAIN, shell=True)
    subprocess.run("iptables -A %s -m state --state RELATED,ESTABLISHED -j ACCEPT" % CHAIN, shell=True)
    subprocess.run("iptables -A %s ! -i %s -j RETURN" % (CHAIN, wan), shell=True)

    # Remove ipset
    subprocess.run("ipset destroy %s 2>/dev/null" % IPSET_NAME, shell=True)

    database.set_setting("geoblock_enabled", "0")
    database.add_log("INFO", details="Geoblock removed")
    return True, "Geoblock removed"


def get_status():
    enabled = database.get_setting("geoblock_enabled", "0") == "1"
    ipset_ok = subprocess.run("ipset list %s -name 2>/dev/null" % IPSET_NAME,
                              shell=True, capture_output=True).returncode == 0
    count = 0
    if ipset_ok:
        out = subprocess.run("ipset list %s | grep -c '/'" % IPSET_NAME,
                             shell=True, capture_output=True, text=True).stdout.strip()
        try:
            count = int(out)
        except Exception:
            pass
    allowed = _get_allowed_countries()
    return {
        "enabled": enabled,
        "ipset_active": ipset_ok,
        "cidr_count": count,
        "allowed_countries": allowed,
        "blocked_count": 249 - len(allowed),
    }


def _install_persistence():
    """Create a systemd service that restores ipset on boot."""
    service = """\
[Unit]
Description=FGUARD UTC GeoBlock ipset restore
Before=iptables.service netfilter-persistent.service
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/ipset restore -f /etc/ipset.d/geo_allowed.ipset
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    with open("/etc/systemd/system/aegisguard-geoblock.service", "w") as f:
        f.write(service)
    subprocess.run("systemctl daemon-reload && systemctl enable aegisguard-geoblock", shell=True)
