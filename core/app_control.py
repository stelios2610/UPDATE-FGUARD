"""Application Control - per-application firewall rules (Linux: iptables owner, Windows: netsh)."""
import subprocess
import os
import psutil
from db import database
from core.platform import IS_LINUX, run

# ─── Predefined app blocks (gateway-level: DNS + port blocking) ───────────────

APPBLOCK_DNSMASQ = "/etc/dnsmasq.d/aegisguard-appblock.conf"

PREDEFINED_APPS = {
    "AnyDesk": {
        "description": "Remote desktop access tool",
        "icon": "🖥",
        "domains": ["anydesk.com", "relay.anydesk.com", "net.anydesk.com", "static.anydesk.com"],
        "ports": [("tcp", 7070), ("udp", 7070)],
        # AnyDesk GmbH own relay server IP ranges (not Cloudflare, these are their actual relays)
        "ip_ranges": ["195.211.220.0/23", "194.165.82.0/24", "194.165.16.0/24",
                      "104.18.30.170/32", "104.18.31.170/32"],
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
    return f"aegisguard_appblock_{safe}"


def _write_appblock_dnsmasq():
    """Rewrite /etc/dnsmasq.d/aegisguard-appblock.conf with all enabled app blocks."""
    if not IS_LINUX:
        return
    lines = ["# AegisGuard App Block — auto-generated", ""]
    for name, cfg in PREDEFINED_APPS.items():
        key = f"appblock_{name}"
        if database.get_setting(key) == "1":
            for domain in cfg["domains"]:
                lines.append(f"address=/{domain}/0.0.0.0")
                lines.append(f"address=/{domain}/::")
    try:
        with open(APPBLOCK_DNSMASQ, "w") as f:
            f.write("\n".join(lines) + "\n")
        run(["systemctl", "restart", "dnsmasq"])
    except Exception:
        pass


def _remove_appblock_iptables(app_name):
    """Remove all iptables FORWARD rules for this app block."""
    tag = _appblock_comment(app_name)
    for chain in ("FORWARD", "INPUT", "OUTPUT"):
        while True:
            ok, out, _ = run(["iptables", "-L", chain, "--line-numbers", "-n"])
            if not ok:
                break
            lines = [l for l in out.splitlines() if tag in l]
            if not lines:
                break
            num = lines[0].split()[0]
            run(["iptables", "-D", chain, num])


def apply_app_block(app_name):
    """Enable gateway-level blocking for a predefined app."""
    cfg = PREDEFINED_APPS.get(app_name)
    if not cfg:
        return False, f"Unknown app: {app_name}"
    database.set_setting(f"appblock_{app_name}", "1")
    if IS_LINUX:
        _remove_appblock_iptables(app_name)
        comment = _appblock_comment(app_name)
        # Block by destination port
        for proto, port in cfg.get("ports", []):
            run(["iptables", "-A", "FORWARD",
                 "-p", proto, "--dport", str(port),
                 "-m", "comment", "--comment", comment,
                 "-j", "DROP"])
        # Block by destination IP range (catches hardcoded IPs and fallback connections)
        for ip_range in cfg.get("ip_ranges", []):
            run(["iptables", "-A", "FORWARD",
                 "-d", ip_range,
                 "-m", "comment", "--comment", comment,
                 "-j", "DROP"])
        _write_appblock_dnsmasq()
        run(["netfilter-persistent", "save"])
    return True, f"{app_name} blocked"


def remove_app_block(app_name):
    """Disable gateway-level blocking for a predefined app."""
    database.set_setting(f"appblock_{app_name}", "0")
    if IS_LINUX:
        _remove_appblock_iptables(app_name)
        _write_appblock_dnsmasq()
        run(["netfilter-persistent", "save"])
    return True, f"{app_name} unblocked"


def get_app_block_status():
    """Return dict {app_name: bool} with current block state."""
    return {
        name: database.get_setting(f"appblock_{name}") == "1"
        for name in PREDEFINED_APPS
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _rule_name(app_rule):
    return f"AegisGuard-App-{app_rule['id']}-{app_rule['name']}"


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
    return f"aegisguard_app_{app_rule['id']}"


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


def sync_app_rule_linux(app_rule):
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
                     "-m", "comment", "--comment", f"aegisguard_block_pid_{pid}",
                     "-j", "DROP"])
            return True, f"Blocked {name} (PID {pid}, UID {uid})"

        tmp_name = f"AegisGuard-TempBlock-{pid}"
        _run_netsh(["delete", "rule", f"name={tmp_name}"])
        for d in ["in", "out"]:
            _run_netsh(["add", "rule", f"name={tmp_name}",
                        f"dir={d}", "action=block", f"program={exe}", "enable=yes"])
        return True, f"Blocked {name} (PID {pid})"

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return False, str(e)
