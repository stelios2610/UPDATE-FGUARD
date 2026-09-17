"""Geoblock — network-level country blocking via ipset + iptables.

Reads blocked_countries from DB, builds a whitelist ipset of allowed
country CIDRs, and DROPs WAN traffic from everywhere else in
FGUARD_INPUT (including VPN ports). Private WAN ranges (Cosmote LAN)
are exempt so the firewall stays reachable on 192.168.100.0/24.
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
CHAIN        = "FGUARD_INPUT"
WAN_IFACE    = None          # auto-detected from DB
COMMENT_TAG  = "aegis_geoblock"

# Site-to-site WG/IKE are peer-locked. SSL VPN 1194 is ACCEPTed on WAN
# so road warriors can reach 192.168.0.254 and 10.16.0.1.

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

    # Rebuild FGUARD_INPUT chain with geoblock
    _apply_chain_rules(wan)

    # Save iptables rules
    subprocess.run("netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null", shell=True)

    # Install ipset restore on boot
    _install_persistence()

    database.set_setting("geoblock_enabled", "1")
    database.add_log("INFO", details="Geoblock applied: %d allowed CIDRs from %s" % (count, str(allowed)))
    return True, "Geoblock active: %d CIDRs, allowed countries: %s" % (count, ", ".join(allowed))


def _apply_chain_rules(wan):
    """Rebuild FGUARD_INPUT with proper geoblock rules."""
    # Flush chain
    subprocess.run("iptables -F %s" % CHAIN, shell=True)

    def ipt(args):
        subprocess.run("iptables -A %s %s" % (CHAIN, args), shell=True)

    # 1. Always allow established/related (responses to server's outbound)
    ipt("-m state --state ESTABLISHED,RELATED -j ACCEPT")
    ipt("-i lo -j ACCEPT")

    # 2. Private ranges on WAN (Cosmote LAN 192.168.100.0/24, etc.)
    ipt("-i %s -s 10.0.0.0/8 -j RETURN" % wan)
    ipt("-i %s -s 172.16.0.0/12 -j RETURN" % wan)
    ipt("-i %s -s 192.168.0.0/16 -j RETURN" % wan)

    # 3. LAN / non-WAN traffic: skip geoblock
    ipt("! -i %s -j RETURN" % wan)

    # 4. Management never on the public WAN — EU scanners were still
    #    hitting SSH/GUI because EU is in the GeoIP allow list.
    ipt("-i %s -p tcp -m multiport --dports 22,80,8080,8888 -j DROP" % wan)

    # SSL VPN (OpenVPN) must stay reachable for road warriors on both
    # 192.168.0.254 and 10.16.0.1. Do not DROP 1194 here — GeoIP still
    # applies to everything else. Site-to-site WG/IKE stay peer-locked.
    ipt("-i %s -p udp --dport 1194 -j ACCEPT" % wan)
    ipt("-i %s -p tcp --dport 1194 -j ACCEPT" % wan)

    # 5. IKE / NAT-T / WireGuard only from known site-to-site peers
    peers = _s2s_peer_ips()
    for peer in peers:
        ipt("-i %s -p udp -m multiport --dports 500,4500,51820 -s %s -j ACCEPT" % (wan, peer))
    if peers:
        ipt("-i %s -p udp -m multiport --dports 500,4500,51820 -j DROP" % wan)

    # 6. Allow remaining WAN from allowed countries
    ipt("-i %s -m set --match-set %s src -j ACCEPT" % (wan, IPSET_NAME))

    # 7. DROP everything else from WAN
    ipt("-i %s -j DROP" % wan)

    _ensure_input_jump()
    _apply_ipv6_wan_drop(wan)
    print("FGUARD_INPUT chain rebuilt with geoblock")


def _s2s_peer_ips():
    """Public IPs of WireGuard / IPSec peers (Tavros etc.)."""
    peers = set()
    try:
        out = subprocess.check_output(["wg", "show", "all", "endpoints"], text=True, timeout=3)
        for line in out.splitlines():
            # iface\tpubkey\t1.2.3.4:51820
            parts = line.split()
            if len(parts) >= 3 and ":" in parts[-1]:
                host = parts[-1].rsplit(":", 1)[0].strip("[]")
                if host and host[0].isdigit():
                    peers.add(host)
    except Exception:
        pass
    if not peers:
        peers.add("94.71.89.93")
    return sorted(peers)


def _apply_ipv6_wan_drop(wan):
    """IPv6 had policy ACCEPT and no GeoIP — scanners hit [::]:22."""
    chain = "FGUARD_INPUT6"
    subprocess.run("ip6tables -N %s 2>/dev/null" % chain, shell=True)
    subprocess.run("ip6tables -F %s" % chain, shell=True)
    subprocess.run("ip6tables -A %s -m state --state ESTABLISHED,RELATED -j ACCEPT" % chain, shell=True)
    subprocess.run("ip6tables -A %s -i lo -j ACCEPT" % chain, shell=True)
    subprocess.run("ip6tables -A %s -p ipv6-icmp -j ACCEPT" % chain, shell=True)
    subprocess.run("ip6tables -A %s -i %s -p udp --dport 546 -j ACCEPT" % (chain, wan), shell=True)
    subprocess.run("ip6tables -A %s ! -i %s -j RETURN" % (chain, wan), shell=True)
    subprocess.run("ip6tables -A %s -i %s -j DROP" % (chain, wan), shell=True)
    subprocess.run("ip6tables -D INPUT -j %s 2>/dev/null" % chain, shell=True)
    subprocess.run("ip6tables -I INPUT 1 -j %s" % chain, shell=True)


def _ensure_input_jump():
    """Geo chain must be first in INPUT. A jump at the bottom is a no-op
    because UDP 500/4500 and LAN ACCEPTs already matched."""
    subprocess.run("iptables -N %s 2>/dev/null" % CHAIN, shell=True)
    subprocess.run("iptables -D INPUT -j %s 2>/dev/null" % CHAIN, shell=True)
    subprocess.run("iptables -I INPUT 1 -j %s" % CHAIN, shell=True)


def restore_geoblock():
    """Re-hook saved ipset after boot/restart without re-downloading CIDRs."""
    if not IS_LINUX:
        return False, "Not Linux"
    if database.get_setting("geoblock_enabled", "0") != "1":
        return False, "disabled"
    r = subprocess.run("ipset list %s -name" % IPSET_NAME, shell=True, capture_output=True)
    if r.returncode != 0:
        if os.path.isfile(IPSET_SAVE):
            subprocess.run("ipset restore -f %s" % IPSET_SAVE, shell=True)
        r = subprocess.run("ipset list %s -name" % IPSET_NAME, shell=True, capture_output=True)
        if r.returncode != 0:
            return False, "ipset missing — click Apply in GeoIP Blocking"
    _apply_chain_rules(_get_wan_iface())
    return True, "Geoblock restored"


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
    """Create systemd services that restore ipset and rebuild iptables chain on boot."""
    # 1. ipset restore service — runs BEFORE netfilter-persistent and chain rebuild
    ipset_svc = """\
[Unit]
Description=FGUARD GeoBlock ipset restore
Before=netfilter-persistent.service fguard-geoblock-rules.service
After=network.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/ipset restore -f /etc/ipset.d/geo_allowed.ipset
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    with open("/etc/systemd/system/fguard-geoblock.service", "w") as f:
        f.write(ipset_svc)

    # 2. iptables chain rebuild script — writes FGUARD_INPUT rules after ipset is ready
    wan = _get_wan_iface()
    rules_script = """\
#!/bin/bash
# FGUARD — Rebuild FGUARD_INPUT geoblock rules on boot
WAN={wan}
CHAIN=FGUARD_INPUT
IPSET=geo_allowed

if ! ipset list $IPSET -name &>/dev/null; then
    echo "fguard-geoblock-rules: ipset $IPSET not found, skipping" | systemd-cat -t fguard
    exit 1
fi

iptables -F $CHAIN 2>/dev/null
iptables -N $CHAIN 2>/dev/null
iptables -A $CHAIN -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A $CHAIN -i lo -j ACCEPT
iptables -A $CHAIN -i $WAN -s 10.0.0.0/8 -j RETURN
iptables -A $CHAIN -i $WAN -s 172.16.0.0/12 -j RETURN
iptables -A $CHAIN -i $WAN -s 192.168.0.0/16 -j RETURN
iptables -A $CHAIN ! -i $WAN -j RETURN
iptables -A $CHAIN -i $WAN -m set --match-set $IPSET src -j ACCEPT
iptables -A $CHAIN -i $WAN -j DROP
iptables -D INPUT -j $CHAIN 2>/dev/null
iptables -I INPUT 1 -j $CHAIN
echo "fguard-geoblock-rules: FGUARD_INPUT rebuilt (wan=$WAN, ipset=$IPSET)" | systemd-cat -t fguard
""".format(wan=wan)

    with open("/usr/local/bin/fguard-geoblock-rules.sh", "w") as f:
        f.write(rules_script)
    subprocess.run("chmod +x /usr/local/bin/fguard-geoblock-rules.sh", shell=True)

    # 3. chain rebuild service — runs AFTER ipset restore and netfilter-persistent
    chain_svc = """\
[Unit]
Description=FGUARD GeoBlock iptables chain rebuild
After=fguard-geoblock.service netfilter-persistent.service network.target
Requires=fguard-geoblock.service

[Service]
Type=oneshot
WorkingDirectory=/opt/fguard
Environment=PYTHONPATH=/opt/fguard
ExecStart=/usr/bin/python3 -c "from core.geoblock import restore_geoblock; restore_geoblock()"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    with open("/etc/systemd/system/fguard-geoblock-rules.service", "w") as f:
        f.write(chain_svc)

    subprocess.run(
        "systemctl daemon-reload && "
        "systemctl enable fguard-geoblock && "
        "systemctl enable fguard-geoblock-rules",
        shell=True
    )
