"""Depth that pfSense and OPNsense already have. Every switch stays off until enabled.

Groups, schedules, and VLAN-to-VLAN rules do nothing until rules_groups_enabled is on.
HA policy sync does nothing until ha_full_policy is on. Suricata interface choice,
signature mode, larger block lists, traffic graphs, and protocol identification
stay off the same way. Session sync itself is still conntrackd.
"""
import ipaddress
import json
import os
import re
from datetime import datetime

BASIC_FEED_CAP = 20000
EXTENDED_FEED_CAP = 100000
POLICY_NAME = "ha-policy.json"
NODE_LOCAL_SETTINGS = {
    "admin_password_hash",
    "fleet_token",
    "wan_interface",
    "lan_interface",
}
POLICY_SETTINGS = (
    "rules_groups_enabled",
    "rules_hits_enabled",
    "traffic_ips_scope_enabled",
    "traffic_ips_ifaces",
    "traffic_sig_mode_enabled",
    "traffic_sig_mode",
    "traffic_sig_autoupdate",
    "traffic_lists_extended",
    "traffic_lists_autoupdate",
    "traffic_stats_enabled",
    "traffic_protoid_enabled",
    "ha_full_policy",
)
_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_IFACE = re.compile(r"^[A-Za-z0-9._:-]{1,15}$")
_SID = re.compile(r"\bsid\s*:\s*(\d+)")
PROTOCOLS = (
    ("HTTP", "http"),
    ("TLS", "tls"),
    ("DNS", "dns"),
    ("SSH", "ssh"),
    ("SMTP", "smtp"),
    ("FTP", "ftp"),
    ("RDP", "rdp"),
    ("SMB", "smb"),
    ("QUIC", "quic"),
    ("SIP", "sip"),
)


def _flag(key):
    from db import database
    return database.get_setting(key, "0") == "1"


def groups_enabled():
    return _flag("rules_groups_enabled")


def hits_enabled():
    return _flag("rules_hits_enabled")


def full_policy_enabled():
    return _flag("ha_full_policy")


def custom_scope_enabled():
    return _flag("traffic_ips_scope_enabled")


def signature_mode_enabled():
    return _flag("traffic_sig_mode_enabled")


def lists_extended():
    return _flag("traffic_lists_extended")


def boot_restore_plan(settings):
    """What comes back after reboot. Only switches that are already on."""
    settings = settings or {}

    def on(key):
        return str(settings.get(key, "0")) == "1"

    return {
        "ips": on("traffic_ips_enabled"),
        "tls": on("tls_inspect_enabled") and on("tls_inspect_confirmed"),
        "ipset": on("traffic_lists_extended"),
    }


def protoid_enabled():
    return _flag("traffic_protoid_enabled")


def feed_cap(extended=None):
    if extended is None:
        extended = lists_extended()
    return EXTENDED_FEED_CAP if extended else BASIC_FEED_CAP


def schedule_allows(spec, moment):
    """Empty means always. Otherwise 'mon,tue,wed,thu,fri 09:00-17:00'."""
    spec = (spec or "").strip().lower()
    if spec in ("", "always", "*"):
        return True
    parts = spec.split()
    if len(parts) != 2 or "-" not in parts[1]:
        raise ValueError("Schedule must look like mon,tue,wed,thu,fri 09:00-17:00")
    days = [item.strip() for item in parts[0].split(",") if item.strip()]
    if any(day not in _DAYS for day in days):
        raise ValueError("Schedule days must be mon,tue,wed,thu,fri,sat,sun")
    if _DAYS[moment.weekday()] not in days:
        return False
    start, end = parts[1].split("-", 1)
    now_m = moment.hour * 60 + moment.minute
    sh, sm = [int(part) for part in start.split(":", 1)]
    eh, em = [int(part) for part in end.split(":", 1)]
    open_m = sh * 60 + sm
    close_m = eh * 60 + em
    if close_m >= open_m:
        return open_m <= now_m < close_m
    return now_m >= open_m or now_m < close_m


def rule_active(rule, moment=None):
    if not groups_enabled():
        return True
    return schedule_allows(rule.get("schedule") or "", moment or datetime.now())


def resolve_group(value, aliases, kind):
    text = (value or "").strip()
    if not text.startswith("@"):
        return [text]
    name = text[1:]
    entry = (aliases or {}).get(name)
    if not entry or entry.get("kind") != kind or not entry.get("values"):
        raise ValueError("Unknown %s group %s" % (kind, name))
    return list(entry["values"])


def expand_rule(rule, aliases):
    """One concrete rule per address and port in the groups. Capped at 64."""
    local_ips = resolve_group(rule.get("local_ip"), aliases, "address")
    remote_ips = resolve_group(rule.get("remote_ip"), aliases, "address")
    local_ports = resolve_group(rule.get("local_port"), aliases, "port")
    remote_ports = resolve_group(rule.get("remote_port"), aliases, "port")
    copies = []
    for local_ip in local_ips:
        for remote_ip in remote_ips:
            for local_port in local_ports:
                for remote_port in remote_ports:
                    copy = dict(rule)
                    copy["local_ip"] = local_ip
                    copy["remote_ip"] = remote_ip
                    copy["local_port"] = local_port
                    copy["remote_port"] = remote_port
                    copies.append(copy)
                    if len(copies) > 64:
                        raise ValueError("A rule group expands to more than 64 firewall rules")
    return copies


def clean_iface(name):
    name = (name or "").strip()
    if not name or name in ("ANY", "*"):
        return ""
    if not _IFACE.match(name):
        raise ValueError("Interface name is not valid")
    return name


def parse_rule_hits(text):
    hits = {}
    for line in (text or "").splitlines():
        match = re.search(r"/\* fguard_(\d+) \*/", line)
        if not match:
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        hits[int(match.group(1))] = int(parts[0])
    return hits


def rsync_excludes(full_policy):
    names = ["*.pyc", "__pycache__", "build/iso-work", "build/*.iso", "license-private.pem"]
    if full_policy:
        names.append("firewall.db")
    return names


def build_policy(rules, nat_rules, aliases, settings):
    kept = {}
    for key in POLICY_SETTINGS:
        if key in (settings or {}):
            kept[key] = "1" if str(settings[key]) == "1" else str(settings[key])
    return {
        "rules": list(rules or []),
        "nat_rules": list(nat_rules or []),
        "aliases": list(aliases or []),
        "settings": kept,
    }


def sanitize_policy(document):
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise ValueError("HA policy file has no rules")
    if len(document["rules"]) > 5000 or len(document.get("nat_rules") or []) > 2000:
        raise ValueError("HA policy file is too large")
    settings = document.get("settings") or {}
    if not isinstance(settings, dict):
        raise ValueError("HA policy settings are invalid")
    cleaned = {}
    for key, value in settings.items():
        if key in NODE_LOCAL_SETTINGS or key not in POLICY_SETTINGS:
            continue
        cleaned[key] = str(value)
    document = dict(document)
    document["settings"] = cleaned
    document["nat_rules"] = list(document.get("nat_rules") or [])
    document["aliases"] = list(document.get("aliases") or [])
    return document


def parse_ip_network_list(text, limit=50000):
    found = []
    seen = set()
    for raw in (text or "").splitlines():
        line = raw.split(";")[0].split("#")[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        text_net = str(network)
        if text_net in seen:
            continue
        seen.add(text_net)
        found.append(text_net)
        if len(found) >= limit:
            break
    return found


def ipset_restore_lines(networks):
    lines = [
        "create fguard_block_ips hash:net family inet hashsize 4096 maxelem 200000 -exist",
        "flush fguard_block_ips",
    ]
    for network in networks or []:
        lines.append("add fguard_block_ips %s" % network)
    lines.append("")
    return "\n".join(lines)


def render_proto_rules():
    """Name the protocol Suricata already detects. These alert. They do not drop."""
    lines = ["# FGUARD protocol identification. Generated. Do not edit."]
    sid = 9500001
    for label, keyword in PROTOCOLS:
        lines.append(
            'alert %s any any -> any any (msg:"FGUARD proto %s"; sid:%d; rev:1;)'
            % (keyword, label, sid)
        )
        sid += 1
    lines.append("")
    return "\n".join(lines)


def rewrite_signatures(text, mode, disabled_sids):
    disabled = {int(sid) for sid in (disabled_sids or [])}
    mode = (mode or "").strip().lower()
    lines = []
    for line in (text or "").splitlines():
        match = _SID.search(line)
        sid = int(match.group(1)) if match else None
        if sid is not None and sid in disabled:
            lines.append("# disabled sid %s" % sid)
            continue
        if mode in ("alert", "drop") and line.startswith(("alert ", "drop ", "reject ")):
            line = re.sub(r"^(alert|drop|reject)\b", mode, line, count=1)
        lines.append(line)
    lines.append("")
    return "\n".join(lines)


def top_talkers(rows, limit=10):
    counts = {}
    for row in rows or []:
        ip = (row.get("src_ip") or "").strip()
        if not ip:
            continue
        counts[ip] = counts.get(ip, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"ip": ip, "count": count} for ip, count in ranked[:limit]]


def custom_ifaces():
    from db import database
    raw = database.get_setting("traffic_ips_ifaces", "") or ""
    names = []
    for part in raw.split(","):
        try:
            name = clean_iface(part)
        except ValueError:
            continue
        if name and name not in names:
            names.append(name)
    return names


def export_policy(directory):
    from db import database
    document = build_policy(
        database.get_rules(),
        database.get_nat_rules(),
        database.list_aliases(),
        database.get_all_settings(),
    )
    path = os.path.join(directory, POLICY_NAME)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
        handle.write("\n")
    return path


def import_policy_on_backup():
    """BACKUP nodes apply ha-policy.json when the master turned policy sync on."""
    from db import database
    config = database.get_ha_config()
    if (config.get("role") or "") != "BACKUP":
        return False
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, POLICY_NAME)
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as handle:
        document = sanitize_policy(json.load(handle))
    if document["settings"].get("ha_full_policy") != "1" and not full_policy_enabled():
        return False
    database.replace_synced_policy(document)
    return True
