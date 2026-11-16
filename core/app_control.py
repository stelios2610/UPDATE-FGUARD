"""Application Control - per-application firewall rules (Linux: iptables owner, Windows: netsh)."""
import subprocess
import os
import psutil
from db import database
from core.platform import IS_LINUX, run

# ─── Predefined app blocks (gateway-level) ────────────────────────────────────
# The chain is jumped only for LAN → WAN, ahead of the accept that lets the
# LAN out. Anything that is not one of these apps returns to that path.
# TCP 443 is dropped only when the packet carries that app's name.

APPBLOCK_DNSMASQ = "/etc/dnsmasq.d/fguard-appblock.conf"
APPBLOCK_CHAIN = "FGUARD_APPBLK"

# A drop on these ports would hit DNS, the web, or STUN used by other calls.
_SHARED_PORTS = {53, 80, 443, 853, 3478, 3479}
# Cloudflare addresses. Other sites use them, so they never go in front.
_SHARED_RANGES = {"104.18.30.170/32", "104.18.31.170/32"}
_MIN_PREFIX = 20
_CONNBYTES = [
    "-m", "connbytes", "--connbytes", "1:8",
    "--connbytes-dir", "original", "--connbytes-mode", "packets",
]
_BYPASS = [
    ["-i", "tun0", "-j", "RETURN"],
    ["-o", "tun0", "-j", "RETURN"],
    ["-d", "10.16.0.0/24", "-j", "RETURN"],
    ["-s", "10.16.0.0/24", "-j", "RETURN"],
    ["-d", "10.8.0.0/24", "-j", "RETURN"],
    ["-s", "10.8.0.0/24", "-j", "RETURN"],
]

PREDEFINED_APPS = {
    "AnyDesk": {
        "description": "Remote desktop access tool",
        "icon": "🖥",
        "domains": ["anydesk.com", "relay.anydesk.com", "net.anydesk.com", "static.anydesk.com"],
        "ports": [("tcp", 7070), ("udp", 7070), ("tcp", 6568)],
        # Port 80 stays open for the web. Only a packet that carries the name is dropped.
        "name_ports": [80],
        # AnyDesk's own relay ranges. Shared Cloudflare addresses are not listed.
        "ip_ranges": ["195.211.220.0/23", "194.165.82.0/24", "194.165.16.0/24"],
    },
    "TeamViewer": {
        "description": "Remote support & desktop sharing",
        "icon": "🖥",
        "domains": ["teamviewer.com", "router.teamviewer.com", "teamviewerrelay.com"],
        "ports": [("tcp", 5938), ("udp", 5938)],
        "ip_ranges": ["178.77.120.0/21"],
    },
    "Discord": {
        "description": "Gaming chat & VoIP",
        "icon": "💬",
        "domains": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"],
        "ports": [],
    },
    "TikTok": {
        "description": "Short video social media",
        "icon": "📱",
        "domains": ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "muscdn.com", "bytedance.com"],
        "ports": [],
    },
    "Zoom": {
        "description": "Video conferencing",
        "icon": "📹",
        "domains": ["zoom.us", "zoom.com", "zoomgov.com"],
        "ports": [("tcp", 8801), ("tcp", 8802), ("udp", 8801), ("udp", 8802)],
    },
    "WhatsApp": {
        "description": "Messaging & calls",
        "icon": "💬",
        "domains": ["web.whatsapp.com", "whatsapp.com", "whatsapp.net"],
        "ports": [],
    },
    "Telegram": {
        "description": "Messaging & channels",
        "icon": "✈",
        "domains": ["telegram.org", "telegram.me", "t.me", "telegram.im", "telegra.ph"],
        "ports": [],
        # Published Telegram data-center ranges (core.telegram.org/resources/cidr.txt).
        "ip_ranges": [
            "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22",
            "91.108.12.0/22", "149.154.160.0/20", "91.105.192.0/23",
            "91.108.20.0/22", "185.76.151.0/24",
        ],
    },
    "Torrent": {
        "description": "BitTorrent P2P file sharing",
        "icon": "⬇",
        "domains": ["thepiratebay.org", "1337x.to", "rarbg.to", "nyaa.si"],
        "ports": [("tcp", 6881), ("tcp", 6882), ("tcp", 6883), ("tcp", 6884),
                  ("tcp", 6885), ("tcp", 6886), ("tcp", 6887), ("tcp", 6888), ("tcp", 6889),
                  ("udp", 6881), ("udp", 6889)],
    },
    "Skype": {
        "description": "Video calls & messaging",
        "icon": "📞",
        "domains": ["skype.com", "skypeassets.com", "skypecdn.com"],
        # 3478/3479 are STUN. They stay out of the gateway drop so other calls keep working.
        "ports": [("tcp", 3478), ("tcp", 3479), ("udp", 3478), ("udp", 3479)],
    },
    "TeamSpeak": {
        "description": "Voice chat for gaming",
        "icon": "🎙",
        "domains": ["teamspeak.com", "teamspeak.net"],
        "ports": [("udp", 9987), ("tcp", 10011), ("tcp", 30033)],
    },
}


def _appblock_comment(app_name):
    safe = app_name.replace(" ", "_")
    return f"fguard_appblock_{safe}"


def sni_names(domains):
    """Names long enough to match inside a TLS handshake without catching other sites."""
    cleaned = []
    for raw in domains or []:
        name = (raw or "").strip().lower().rstrip(".")
        # t.me is four characters and would match unrelated packets.
        # zoom.us is the shortest name in the list that still identifies one app.
        if len(name) < 7 or "." not in name:
            continue
        cleaned.append(name)
    needles = []
    for name in cleaned:
        if any(name != other and name.endswith("." + other) for other in cleaned):
            continue
        if name not in needles:
            needles.append(name)
    return needles


def _prefix_ok(cidr):
    if cidr in _SHARED_RANGES:
        return False
    try:
        ip, prefix = cidr.split("/")
        prefix = int(prefix)
        parts = ip.split(".")
    except ValueError:
        return False
    if prefix < _MIN_PREFIX or prefix > 32 or len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _without_connbytes(args):
    out = []
    i = 0
    width = len(_CONNBYTES)
    while i < len(args):
        if args[i:i + width] == _CONNBYTES:
            i += width
            continue
        out.append(args[i])
        i += 1
    return out


def chain_rules(enabled_names):
    """Ordered rules for FGUARD_APPBLK. The chain always returns what it does not drop."""
    rules = [list(item) for item in _BYPASS]
    for name in enabled_names:
        cfg = PREDEFINED_APPS.get(name)
        if not cfg:
            continue
        comment = _appblock_comment(name)
        for proto, port in cfg.get("ports", []):
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            if proto not in ("tcp", "udp") or port in _SHARED_PORTS:
                continue
            rules.append([
                "-p", proto, "--dport", str(port),
                "-m", "comment", "--comment", comment, "-j", "DROP",
            ])
        for cidr in cfg.get("ip_ranges", []):
            if not _prefix_ok(cidr):
                continue
            rules.append([
                "-d", cidr, "-m", "comment", "--comment", comment, "-j", "DROP",
            ])
        name_ports = [443]
        for port in cfg.get("name_ports", []):
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            if port not in name_ports and port not in (53, 853):
                name_ports.append(port)
        for port in name_ports:
            for needle in sni_names(cfg.get("domains", [])):
                rules.append([
                    "-p", "tcp", "--dport", str(port),
                    "-m", "string", "--string", needle, "--algo", "bm",
                    *_CONNBYTES,
                    "-m", "comment", "--comment", comment, "-j", "DROP",
                ])
    rules.append(["-j", "RETURN"])
    return rules


def _enabled_app_names():
    return [
        name for name in PREDEFINED_APPS
        if database.get_setting(f"appblock_{name}") == "1"
    ]


def _write_appblock_dnsmasq():
    """Rewrite the app-block DNS file. Restart dnsmasq only when the file changes."""
    if not IS_LINUX:
        return
    lines = ["# FGUARD App Block — auto-generated", ""]
    enabled = False
    for name, cfg in PREDEFINED_APPS.items():
        if database.get_setting(f"appblock_{name}") != "1":
            continue
        enabled = True
        for domain in cfg["domains"]:
            lines.append(f"address=/{domain}/0.0.0.0")
            lines.append(f"address=/{domain}/::")
    body = "\n".join(lines) + "\n"
    try:
        if not enabled and not os.path.isfile(APPBLOCK_DNSMASQ):
            return
        current = ""
        if os.path.isfile(APPBLOCK_DNSMASQ):
            with open(APPBLOCK_DNSMASQ) as handle:
                current = handle.read()
        if current == body:
            return
        with open(APPBLOCK_DNSMASQ, "w") as handle:
            handle.write(body)
        run(["systemctl", "restart", "dnsmasq"])
    except Exception:
        pass


def _purge_legacy(chain):
    """Drop the old end-of-FORWARD app rules. Leave the jump into our chain alone."""
    ok, out, _ = run(["iptables", "-S", chain])
    if not ok:
        return
    for line in out.splitlines():
        if "fguard_appblock_" not in line or f"-j {APPBLOCK_CHAIN}" in line:
            continue
        parts = line.split()
        if not parts or parts[0] != "-A":
            continue
        parts[0] = "-D"
        run(["iptables"] + parts)


def _delete_jumps():
    ok, out, _ = run(["iptables", "-S", "FORWARD"])
    if not ok:
        return
    for line in out.splitlines():
        if line.startswith("-A FORWARD ") and line.endswith(f"-j {APPBLOCK_CHAIN}"):
            parts = line.split()
            parts[0] = "-D"
            run(["iptables"] + parts)


def _wan_iface():
    setting = (database.get_setting("wan_interface") or "").strip()
    if setting:
        return setting
    ok, out, _ = run(["ip", "route", "show", "default"])
    parts = (out or "").split()
    if "dev" in parts:
        return parts[parts.index("dev") + 1]
    return ""


def _lan_ifaces():
    found = []
    try:
        main = (database.get_setting("lan_interface") or "").strip()
        if main:
            found.append(main)
        for cfg in database.get_dhcp_configs() or []:
            if cfg.get("enabled") and cfg.get("interface"):
                found.append(cfg["interface"])
        for vlan in database.get_vlans() or []:
            if not vlan.get("enabled"):
                continue
            if (vlan.get("zone") or "LAN").upper() != "LAN":
                continue
            parent = vlan.get("parent_interface") or ""
            vid = vlan.get("vlan_id")
            if parent and vid is not None:
                found.append(f"{parent}.{vid}")
    except Exception:
        return []
    out = []
    for name in found:
        if name and name not in out:
            out.append(name)
    return out


def _chain_exists():
    ok, _, _ = run(["iptables", "-L", APPBLOCK_CHAIN, "-n"])
    return ok


def _install_jumps():
    """Put the LAN→WAN jump at the front of FORWARD. No jump when nothing is blocked.

    If the WAN or LAN name cannot be read, leave an existing jump where it is.
    Deleting it first would drop the block until the next successful read.
    """
    if not _enabled_app_names() or not _chain_exists():
        _delete_jumps()
        return
    wan = _wan_iface()
    ifaces = [iface for iface in _lan_ifaces() if iface and iface != wan]
    if not wan or not ifaces:
        return
    _delete_jumps()
    for iface in ifaces:
        run(["iptables", "-I", "FORWARD", "1",
             "-i", iface, "-o", wan, "-j", APPBLOCK_CHAIN])


def _add_chain_rule(args):
    ok, _, _ = run(["iptables", "-A", APPBLOCK_CHAIN] + args)
    if ok or "connbytes" not in args:
        return ok
    return run(["iptables", "-A", APPBLOCK_CHAIN] + _without_connbytes(args))[0]


def _rebuild_appblock():
    """Rebuild the app chain from the saved switches. Does not turn a new app on."""
    if not IS_LINUX:
        return
    enabled = _enabled_app_names()
    for chain in ("FORWARD", "INPUT", "OUTPUT"):
        _purge_legacy(chain)
    run(["iptables", "-N", APPBLOCK_CHAIN])
    run(["iptables", "-F", APPBLOCK_CHAIN])
    if not enabled:
        _delete_jumps()
        return
    for args in chain_rules(enabled):
        _add_chain_rule(args)
    _install_jumps()


def _persist_rules():
    run(["netfilter-persistent", "save"])


def apply_app_block(app_name):
    """Enable gateway-level blocking for a predefined app."""
    if app_name not in PREDEFINED_APPS:
        return False, f"Unknown app: {app_name}"
    database.set_setting(f"appblock_{app_name}", "1")
    if IS_LINUX:
        _rebuild_appblock()
        _write_appblock_dnsmasq()
        _persist_rules()
    return True, f"{app_name} blocked"


def remove_app_block(app_name):
    """Disable gateway-level blocking for a predefined app."""
    database.set_setting(f"appblock_{app_name}", "0")
    if IS_LINUX:
        _rebuild_appblock()
        _write_appblock_dnsmasq()
        _persist_rules()
    return True, f"{app_name} unblocked"


def reseat_appblock():
    """Move the app jump back in front of later LAN→WAN accepts. No new blocks."""
    if not IS_LINUX:
        return
    try:
        enabled = _enabled_app_names()
        if not _chain_exists():
            if enabled:
                _rebuild_appblock()
                _persist_rules()
            return
        _install_jumps()
        if enabled:
            _persist_rules()
    except Exception:
        return


def get_app_block_status():
    """Return dict {app_name: bool} with current block state."""
    return {
        name: database.get_setting(f"appblock_{name}") == "1"
        for name in PREDEFINED_APPS
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _rule_name(app_rule):
    return f"FGUARD-App-{app_rule['id']}-{app_rule['name']}"


def _get_uids_for_exe(exe_path):
    """Return set of real UIDs currently running this executable."""
    uids = set()
    try:
        for proc in psutil.process_iter(["exe", "uids"]):
            try:
                if proc.info.get("exe") == exe_path:
                    uids.add(proc.uids().real)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return uids


# ─── Linux backend (iptables owner match) ────────────────────────────────────

def _ipt_comment(app_rule):
    return f"fguard_app_{app_rule['id']}"


def _remove_app_rule_linux(app_rule):
    tag = _ipt_comment(app_rule)
    for chain in ("INPUT", "OUTPUT"):
        while True:
            ok, out, _ = run(["iptables", "-L", chain, "--line-numbers", "-n"])
            if not ok:
                break
            lines = [l for l in out.splitlines() if tag in l]
            if not lines:
                break
            num = lines[0].split()[0]
            run(["iptables", "-D", chain, num])
    return True, "OK"


def _gateway_app(app_rule):
    """Map a saved exe rule onto a gateway block. None if it is not one of those apps."""
    blob = f"{app_rule.get('name', '')} {app_rule.get('exe_path', '')}".lower()
    for key, app in (
        ("anydesk", "AnyDesk"),
        ("teamviewer", "TeamViewer"),
        ("qbittorrent", "Torrent"),
        ("utorrent", "Torrent"),
        ("bittorrent", "Torrent"),
        ("transmission", "Torrent"),
        ("deluge", "Torrent"),
    ):
        if key in blob:
            return app
    return None


def sync_app_rule_linux(app_rule):
    app = _gateway_app(app_rule)
    if app:
        if app_rule.get("enabled") and (app_rule.get("action") or "").upper() == "BLOCK":
            return apply_app_block(app)
        return remove_app_block(app)

    _remove_app_rule_linux(app_rule)

    if not app_rule["enabled"]:
        return True, "Disabled"

    exe = app_rule.get("exe_path", "")
    uids = _get_uids_for_exe(exe)
    if not uids:
        return True, f"Rule saved — process not running, will apply on next sync"

    action    = "ACCEPT" if app_rule["action"] == "ALLOW" else "DROP"
    direction = app_rule.get("direction", "BOTH")
    comment   = _ipt_comment(app_rule)

    chains = []
    if direction in ("OUT", "BOTH"):
        chains.append("OUTPUT")
    if direction in ("IN", "BOTH"):
        chains.append("INPUT")

    for uid in uids:
        for chain in chains:
            args = [
                "iptables", "-A", chain,
                "-m", "owner", "--uid-owner", str(uid),
                "-m", "comment", "--comment", comment,
                "-j", action,
            ]
            ok, out, err = run(args)
            if not ok:
                return False, err

    return True, f"Applied for UID(s): {', '.join(str(u) for u in uids)}"


def remove_app_rule_linux(app_rule):
    return _remove_app_rule_linux(app_rule)


# ─── Windows backend (netsh) ──────────────────────────────────────────────────

def _run_netsh(args):
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall"] + args,
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def sync_app_rule_windows(app_rule):
    name = _rule_name(app_rule)
    _run_netsh(["delete", "rule", f"name={name}"])

    if not app_rule["enabled"]:
        return True, "Disabled"

    action    = "allow" if app_rule["action"] == "ALLOW" else "block"
    direction = app_rule.get("direction", "BOTH")
    dirs      = ["in", "out"] if direction == "BOTH" else [direction.lower()]
    exe       = app_rule["exe_path"]

    for d in dirs:
        args = ["add", "rule", f"name={name}", f"dir={d}",
                f"action={action}", f"program={exe}", "enable=yes"]
        ok, msg = _run_netsh(args)
        if not ok:
            return False, msg
    return True, "OK"


def remove_app_rule_windows(app_rule):
    name = _rule_name(app_rule)
    return _run_netsh(["delete", "rule", f"name={name}"])


# ─── Public API ───────────────────────────────────────────────────────────────

def sync_app_rule(app_rule):
    if IS_LINUX:
        return sync_app_rule_linux(app_rule)
    return sync_app_rule_windows(app_rule)


def remove_app_rule(app_rule):
    if IS_LINUX:
        return remove_app_rule_linux(app_rule)
    return remove_app_rule_windows(app_rule)


def sync_all_app_rules():
    rules = database.get_app_rules()
    results = []
    for rule in rules:
        ok, msg = sync_app_rule(rule)
        results.append((rule["name"], ok, msg))
    return results


def restore_gateway_blocks():
    """Re-apply gateway blocks that were already turned on. Does not enable new ones."""
    if not IS_LINUX:
        return
    _rebuild_appblock()
    _write_appblock_dnsmasq()


def get_running_apps():
    """Return list of running processes that have network connections."""
    apps = {}
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "uids"]):
            try:
                info  = proc.info
                exe   = info.get("exe") or ""
                name  = info.get("name") or f"PID {info['pid']}"
                if exe and exe not in apps:
                    conns = proc.net_connections()
                    if conns:
                        uid = info.get("uids")
                        apps[exe] = {
                            "name": name,
                            "exe": exe,
                            "connections": len(conns),
                            "pid": info["pid"],
                            "uid": uid.real if uid else None,
                        }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return list(apps.values())


def block_process_now(pid):
    """Best-effort: immediately block all connections for a PID."""
    try:
        proc = psutil.Process(pid)
        exe  = proc.exe()
        name = proc.name()

        if IS_LINUX:
            uid  = proc.uids().real
            for chain in ("INPUT", "OUTPUT"):
                run(["iptables", "-I", chain, "1",
                     "-m", "owner", "--uid-owner", str(uid),
                     "-m", "comment", "--comment", f"fguard_block_pid_{pid}",
                     "-j", "DROP"])
            return True, f"Blocked {name} (PID {pid}, UID {uid})"

        tmp_name = f"FGUARD-TempBlock-{pid}"
        _run_netsh(["delete", "rule", f"name={tmp_name}"])
        for d in ["in", "out"]:
            _run_netsh(["add", "rule", f"name={tmp_name}",
                        f"dir={d}", "action=block", f"program={exe}", "enable=yes"])
        return True, f"Blocked {name} (PID {pid})"

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return False, str(e)
