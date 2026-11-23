"""Traffic security for forwarded client flows.

Suricata inspects LAN-to-WAN traffic and fails open if it stops. Category
lists are enforced in DNS. Download antivirus scans files Suricata extracts.
HTTPS inspection stays off until an administrator confirms it.
"""
import json
import os
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime

from core.platform import IS_LINUX, is_root, run

QUEUE_NUM = 0
EVE_PATH = "/var/log/suricata/fguard-eve.json"
SURICATA_YAML = "/etc/suricata/fguard-ips.yaml"
RULES_DIR = "/var/lib/suricata/fguard"
APP_RULES = os.path.join(RULES_DIR, "fguard-apps.rules")
CATEGORY_DNS = "/etc/dnsmasq.d/fguard-categories.conf"
FILESTORE = "/var/lib/suricata/fguard-files"
TLS_DIR = "/etc/fguard/tls-inspect"
MAX_DOMAINS = 20000
MAX_FEED_BYTES = 5 * 1024 * 1024

CATEGORY_FEEDS = {
    "Malware": "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "Phishing": "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "Adult": "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
    "Gambling": "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
    "Ads & Tracking": "https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt",
}

TLS_BYPASS = (
    "windowsupdate.com",
    "apple.com",
    "icloud.com",
    "digicert.com",
    "letsencrypt.org",
)

_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
_reader_started = False


def home_net(cidrs):
    cleaned = [c for c in (cidrs or []) if c and "/" in c]
    if not cleaned:
        cleaned = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    return "[" + ",".join(cleaned) + "]"


def render_suricata_yaml(cidrs, interfaces, file_store=False):
    ifaces = [name for name in (interfaces or []) if name]
    if not ifaces:
        ifaces = ["eth1"]
    af = []
    for index, name in enumerate(ifaces, start=1):
        af.append(
            "  - interface: %s\n    cluster-id: %d\n    cluster-type: cluster_flow\n    defrag: yes"
            % (name, 98 + index)
        )
    files = ""
    if file_store:
        files = (
            "  - file-store:\n"
            "      version: 2\n"
            "      enabled: yes\n"
            "      dir: %s\n"
            "      write-fileinfo: yes\n" % FILESTORE
        )
    return (
        "%%YAML 1.1\n---\n"
        "vars:\n  address-groups:\n"
        "    HOME_NET: \"%s\"\n"
        "    EXTERNAL_NET: \"!$HOME_NET\"\n"
        "af-packet:\n%s\n"
        "nfq:\n  mode: accept\n  fail-open: yes\n"
        "default-rule-path: %s\n"
        "rule-files:\n  - fguard-apps.rules\n"
        "outputs:\n"
        "  - eve-log:\n"
        "      enabled: yes\n"
        "      filetype: regular\n"
        "      filename: %s\n"
        "      types:\n        - alert\n        - flow\n        - fileinfo\n"
        "%s"
        % (home_net(cidrs), "\n".join(af), RULES_DIR, EVE_PATH, files)
    )


def nfqueue_rules(lan_ifaces, wan_iface):
    """FORWARD rules that send client traffic to Suricata and fail open."""
    rules = []
    wan = (wan_iface or "").strip()
    for lan in lan_ifaces or []:
        lan = (lan or "").strip()
        if not lan or lan == wan:
            continue
        base = ["-i", lan]
        if wan:
            base += ["-o", wan]
        rules.append(base + [
            "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM), "--queue-bypass",
            "-m", "comment", "--comment", "fguard_traffic_ips",
        ])
    return rules


def render_app_rules(apps):
    """Suricata drop rules for application server names."""
    lines = ["# FGUARD application drops. Generated. Do not edit."]
    sid = 9100001
    for app in apps or []:
        name = str(app.get("name") or "app").replace('"', "")
        for domain in app.get("domains") or []:
            domain = str(domain).strip().lower().rstrip(".")
            if len(domain) < 7 or "." not in domain:
                continue
            lines.append(
                'drop tls any any -> any any (msg:"FGUARD %s"; tls.sni; content:"%s"; '
                "nocase; sid:%d; rev:1;)" % (name, domain, sid)
            )
            sid += 1
    lines.append("")
    return "\n".join(lines)


def parse_eve_line(line):
    """Return a normalized alert or file event, or None."""
    try:
        event = json.loads(line)
    except Exception:
        return None
    if not isinstance(event, dict):
        return None
    kind = event.get("event_type")
    if kind == "alert":
        alert = event.get("alert") or {}
        return {
            "kind": "alert",
            "src_ip": event.get("src_ip") or "",
            "dst_ip": event.get("dest_ip") or "",
            "src_port": event.get("src_port"),
            "dst_port": event.get("dest_port"),
            "signature": alert.get("signature") or "Suricata alert",
            "category": alert.get("category") or "",
            "severity": alert.get("severity") or 3,
            "action": (alert.get("action") or "allowed"),
        }
    if kind == "fileinfo":
        return {
            "kind": "file",
            "src_ip": event.get("src_ip") or "",
            "filename": (event.get("fileinfo") or {}).get("filename") or "",
            "stored": event.get("stored") or False,
            "sha256": (event.get("fileinfo") or {}).get("sha256") or "",
        }
    if kind == "flow":
        return {
            "kind": "flow",
            "src_ip": event.get("src_ip") or "",
            "dst_ip": event.get("dest_ip") or "",
            "app": event.get("app_proto") or "",
        }
    return None


def parse_domain_list(text):
    """Domains from a hosts file or a list of URLs."""
    found = []
    seen = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if "://" in line:
            host = urllib.parse.urlparse(line).hostname or ""
        else:
            parts = line.split()
            if not parts:
                continue
            host = parts[-1]
        host = host.strip(".").lower()
        if host.startswith("www."):
            host = host[4:]
        if not _DOMAIN.match(host) or host in seen:
            continue
        seen.add(host)
        found.append(host)
        if len(found) >= MAX_DOMAINS:
            break
    return found


def dnsmasq_lines(domains):
    lines = ["# FGUARD category feed. Generated."]
    for domain in domains:
        lines.append("address=/%s/0.0.0.0" % domain)
        lines.append("address=/%s/::" % domain)
    lines.append("")
    return "\n".join(lines)


def fetch_feed(url, limit=MAX_FEED_BYTES):
    if not str(url).startswith("https://"):
        raise ValueError("category feed must be https")
    request = urllib.request.Request(url, headers={"User-Agent": "FGUARD"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        data = data[:limit]
    return data.decode("utf-8", errors="ignore")


def parse_proc_net_dev(text):
    stats = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        cols = rest.split()
        if len(cols) < 9:
            continue
        stats[name] = {"rx_bytes": int(cols[0]), "tx_bytes": int(cols[8])}
    return stats


def interface_rates(before, after, seconds):
    seconds = float(seconds or 0)
    if seconds <= 0:
        return {}
    rates = {}
    for name, end in (after or {}).items():
        start = (before or {}).get(name)
        if not start:
            continue
        rx = max(0, end["rx_bytes"] - start["rx_bytes"])
        tx = max(0, end["tx_bytes"] - start["tx_bytes"])
        rates[name] = {
            "rx_mbps": round(rx * 8 / seconds / 1_000_000, 2),
            "tx_mbps": round(tx * 8 / seconds / 1_000_000, 2),
        }
    return rates


def summarize_blocks(rows):
    by_rule = {}
    by_src = {}
    for row in rows or []:
        rule = row.get("rule_name") or "unknown"
        src = row.get("src_ip") or ""
        by_rule[rule] = by_rule.get(rule, 0) + 1
        if src:
            by_src[src] = by_src.get(src, 0) + 1
    return {
        "total": len(rows or []),
        "by_rule": sorted(by_rule.items(), key=lambda item: item[1], reverse=True)[:15],
        "by_src": sorted(by_src.items(), key=lambda item: item[1], reverse=True)[:15],
    }


def tls_plan(enabled, confirmed):
    """HTTPS inspection does not start unless the administrator confirms it."""
    if not enabled:
        return {"enabled": False, "reason": "off"}
    if not confirmed:
        raise ValueError("Confirm HTTPS inspection before enabling it. Clients must trust the firewall CA.")
    return {
        "enabled": True,
        "ca_cert": os.path.join(TLS_DIR, "ca.crt"),
        "ca_key": os.path.join(TLS_DIR, "ca.key"),
        "listen_port": 8443,
        "bypass": list(TLS_BYPASS),
    }


def sslsplit_command(plan):
    return [
        "sslsplit", "-D",
        "-k", plan["ca_key"],
        "-c", plan["ca_cert"],
        "-P",
        "-l", "/var/log/fguard-tls.log",
        "ssl", "0.0.0.0", str(plan["listen_port"]),
    ]


def record_eve_line(line):
    """Store one Suricata event in the firewall log. Returns True when stored."""
    event = parse_eve_line(line)
    if not event:
        return False
    from db import database
    if event["kind"] == "file" and database.get_setting("traffic_av_enabled", "0") == "1":
        folder = os.path.realpath(FILESTORE)
        candidate = os.path.realpath(os.path.join(folder, event.get("sha256") or ""))
        if candidate.startswith(folder + os.sep) and os.path.isfile(candidate):
            from core import gateway_av
            clean, threat = gateway_av.scan_file(candidate)
            if not clean:
                database.add_log(
                    "BLOCK", src_ip=event.get("src_ip") or "", rule_name="ClamAV",
                    details="Download blocked: %s" % (threat or event.get("filename") or "malware"),
                )
                return True
        return False
    if event["kind"] != "alert":
        return False
    database.add_log(
        "THREAT",
        direction="IN",
        src_ip=event["src_ip"],
        dst_ip=event["dst_ip"],
        src_port=event["src_port"],
        dst_port=event["dst_port"],
        rule_name=event["signature"][:180],
        details="Suricata %s severity %s" % (event["action"], event["severity"]),
    )
    return True


def _drop_nfqueue_rules():
    for _ in range(32):
        ok, out, _ = run(["iptables", "-S", "FORWARD"])
        if not ok or "fguard_traffic_ips" not in (out or ""):
            return
        for line in out.splitlines():
            if "fguard_traffic_ips" not in line or not line.startswith("-A FORWARD "):
                continue
            run(["iptables", "-D", "FORWARD"] + line.split()[2:])
            break


def package_install_argv(packages):
    """apt-get command that downloads a missing program. Names stay package names."""
    if isinstance(packages, str):
        packages = [packages]
    cleaned = []
    for package in packages:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", str(package or "")):
            raise ValueError("package name is not allowed")
        cleaned.append(str(package))
    if not cleaned:
        raise ValueError("package name is not allowed")
    return ["apt-get", "install", "-y"] + cleaned


def ensure_package(binary, packages):
    """Download and install a program when the firewall does not have it yet."""
    ok, _, _ = run(["which", binary])
    if ok:
        return True, ""
    run(["apt-get", "update"], timeout=120)
    ok, _, err = run(package_install_argv(packages), timeout=240)
    if not ok:
        return False, err or "Could not install %s" % packages
    if binary == "suricata":
        run(["systemctl", "disable", "--now", "suricata"], timeout=30)
    ok, _, _ = run(["which", binary])
    if not ok:
        return False, "%s was installed but %s is still missing" % (packages, binary)
    return True, ""


def apply_ips(enabled, cidrs, interfaces, wan_iface, lan_ifaces):
    """Install or remove the fail-open Suricata path. Traffic continues if Suricata is down."""
    if not IS_LINUX or not is_root():
        return False, "Traffic IPS requires Linux root"
    if not enabled:
        _drop_nfqueue_rules()
        run(["systemctl", "stop", "fguard-suricata"])
        return True, "Traffic IPS stopped"
    ok, err = ensure_package("suricata", "suricata")
    if not ok:
        return False, err
    os.makedirs(RULES_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(EVE_PATH), exist_ok=True)
    store_files = False
    try:
        from db import database
        store_files = database.get_setting("traffic_av_enabled", "0") == "1"
    except Exception:
        store_files = False
    with open(SURICATA_YAML, "w", encoding="utf-8") as handle:
        handle.write(render_suricata_yaml(cidrs, interfaces, file_store=store_files))
    if not os.path.isfile(APP_RULES):
        with open(APP_RULES, "w", encoding="utf-8") as handle:
            handle.write(render_app_rules([]))
    unit = (
        "[Service]\nExecStart=/usr/bin/suricata -c %s -q %d --pidfile /run/fguard-suricata.pid\n"
        "Restart=on-failure\n[Install]\nWantedBy=multi-user.target\n"
        % (SURICATA_YAML, QUEUE_NUM)
    )
    os.makedirs("/etc/systemd/system", exist_ok=True)
    with open("/etc/systemd/system/fguard-suricata.service", "w", encoding="utf-8") as handle:
        handle.write("[Unit]\nDescription=FGUARD Suricata\n\n" + unit)
    run(["systemctl", "daemon-reload"])
    ok, _, err = run(["systemctl", "restart", "fguard-suricata"], timeout=30)
    if not ok:
        return False, err or "suricata did not start"
    for rule in nfqueue_rules(lan_ifaces, wan_iface):
        check, _, _ = run(["iptables", "-C", "FORWARD"] + rule)
        if not check:
            run(["iptables", "-I", "FORWARD", "1"] + rule)
    start_eve_reader()
    return True, "Traffic IPS started with fail-open"


def apply_app_rules(apps):
    if not IS_LINUX or not is_root():
        return False, "Application rules require Linux root"
    os.makedirs(RULES_DIR, exist_ok=True)
    with open(APP_RULES, "w", encoding="utf-8") as handle:
        handle.write(render_app_rules(apps))
    run(["systemctl", "reload", "fguard-suricata"])
    return True, "Application rules written"


def apply_categories(domains):
    if not IS_LINUX or not is_root():
        return False, "Category DNS requires Linux root"
    os.makedirs(os.path.dirname(CATEGORY_DNS), exist_ok=True)
    with open(CATEGORY_DNS, "w", encoding="utf-8") as handle:
        handle.write(dnsmasq_lines(domains))
    ok, _, err = run(["systemctl", "restart", "dnsmasq"], timeout=20)
    if not ok:
        return False, err or "dnsmasq did not restart"
    return True, "%d domains installed" % len(domains)


def remove_categories():
    if os.path.isfile(CATEGORY_DNS):
        try:
            os.remove(CATEGORY_DNS)
        except OSError as exc:
            return False, str(exc)
    if IS_LINUX and is_root():
        run(["systemctl", "restart", "dnsmasq"], timeout=20)
    return True, "Category DNS removed"


def measure_interfaces(seconds=1):
    path = "/proc/net/dev"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            before = parse_proc_net_dev(handle.read())
    except OSError as exc:
        return False, str(exc)
    time.sleep(max(0.2, float(seconds)))
    with open(path, "r", encoding="utf-8") as handle:
        after = parse_proc_net_dev(handle.read())
    return True, interface_rates(before, after, seconds)


def start_eve_reader():
    global _reader_started
    if _reader_started:
        return
    _reader_started = True
    import threading
    threading.Thread(target=_eve_loop, daemon=True).start()


def _eve_loop():
    offset = 0
    while True:
        try:
            if os.path.isfile(EVE_PATH):
                with open(EVE_PATH, "r", encoding="utf-8", errors="ignore") as handle:
                    handle.seek(offset)
                    for line in handle:
                        record_eve_line(line)
                    offset = handle.tell()
        except Exception:
            pass
        time.sleep(2)


def _comment_rules(table, comment):
    ok, out, _ = run(["iptables", "-t", table, "-S"])
    if not ok:
        return []
    found = []
    for line in (out or "").splitlines():
        if comment in line and line.startswith("-A "):
            chain = line.split()[1]
            found.append((chain, line.split()[2:]))
    return found


def enable_tls(confirmed, lan_iface):
    plan = tls_plan(True, confirmed)
    if not IS_LINUX or not is_root():
        return False, "HTTPS inspection requires Linux root"
    if not lan_iface:
        return False, "Set the LAN interface first"
    ok, err = ensure_package("sslsplit", "sslsplit")
    if not ok:
        return False, err
    os.makedirs(TLS_DIR, exist_ok=True)
    if not os.path.isfile(plan["ca_cert"]) or not os.path.isfile(plan["ca_key"]):
        ok, _, err = run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", plan["ca_key"], "-out", plan["ca_cert"],
            "-days", "3650", "-subj", "/CN=FGUARD TLS Inspect",
        ], timeout=30)
        if not ok:
            return False, err or "could not create the inspection CA"
        os.chmod(plan["ca_key"], 0o600)
    for domain in plan["bypass"]:
        rule = [
            "-i", lan_iface, "-p", "tcp", "--dport", "443",
            "-m", "string", "--string", domain, "--algo", "bm",
            "-m", "comment", "--comment", "fguard_tls_bypass", "-j", "RETURN",
        ]
        check, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING"] + rule)
        if not check:
            run(["iptables", "-t", "nat", "-I", "PREROUTING", "1"] + rule)
    redirect = [
        "-i", lan_iface, "-p", "tcp", "--dport", "443",
        "-m", "comment", "--comment", "fguard_tls_inspect",
        "-j", "REDIRECT", "--to-ports", str(plan["listen_port"]),
    ]
    check, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING"] + redirect)
    if not check:
        run(["iptables", "-t", "nat", "-A", "PREROUTING"] + redirect)
    command = " ".join(sslsplit_command(plan))
    unit = (
        "[Unit]\nDescription=FGUARD HTTPS inspection\n\n"
        "[Service]\nExecStart=%s\nRestart=on-failure\n\n"
        "[Install]\nWantedBy=multi-user.target\n" % command
    )
    with open("/etc/systemd/system/fguard-tls.service", "w", encoding="utf-8") as handle:
        handle.write(unit)
    run(["systemctl", "daemon-reload"])
    ok, _, err = run(["systemctl", "restart", "fguard-tls"], timeout=20)
    if not ok:
        return False, err or "sslsplit did not start"
    return True, "HTTPS inspection started. Install the CA on every client."


def disable_tls():
    if IS_LINUX and is_root():
        for comment in ("fguard_tls_bypass", "fguard_tls_inspect"):
            for _ in range(32):
                rules = _comment_rules("nat", comment)
                if not rules:
                    break
                chain, args = rules[0]
                run(["iptables", "-t", "nat", "-D", chain] + args)
        run(["systemctl", "stop", "fguard-tls"])
    return True, "HTTPS inspection stopped"


def update_category_feeds():
    domains = []
    errors = []
    seen = set()
    for name, url in CATEGORY_FEEDS.items():
        try:
            for domain in parse_domain_list(fetch_feed(url)):
                if domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
        except Exception as exc:
            errors.append("%s: %s" % (name, exc))
    return domains, errors


def restore():
    """Re-apply traffic IPS after boot only when an administrator already enabled it."""
    from db import database
    if database.get_setting("traffic_ips_enabled", "0") != "1":
        return False, "Traffic IPS is off"
    wan = database.get_setting("wan_interface", "") or ""
    lan = database.get_setting("lan_interface", "") or ""
    lans = [item.strip() for item in lan.split(",") if item.strip()]
    ifaces = list(lans)
    if wan and wan not in ifaces:
        ifaces.append(wan)
    return apply_ips(True, [], ifaces, wan, lans)


def status():
    from db import database
    suricata = False
    if IS_LINUX:
        ok, out, _ = run(["systemctl", "is-active", "fguard-suricata"])
        suricata = ok and out == "active"
    return {
        "ips_enabled": database.get_setting("traffic_ips_enabled", "0") == "1",
        "suricata_active": suricata,
        "categories_enabled": database.get_setting("traffic_categories_enabled", "0") == "1",
        "av_enabled": database.get_setting("traffic_av_enabled", "0") == "1",
        "tls_enabled": database.get_setting("tls_inspect_enabled", "0") == "1",
        "updated": datetime.now().isoformat(),
    }
