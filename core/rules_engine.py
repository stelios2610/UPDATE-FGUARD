"""Firewall rules engine - cross-platform (Windows: netsh, Linux: iptables/nftables)."""
import subprocess
import re
from db import database
from core.platform import IS_LINUX, IS_WINDOWS, run


def _match_ip(pattern, ip):
    if not pattern or pattern in ("", "ANY", "*"):
        return True
    if "/" in pattern:
        import ipaddress
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    return pattern == ip


def _match_port(pattern, port):
    if not pattern or pattern in ("", "ANY", "*", "0"):
        return True
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    if "-" in str(pattern):
        parts = pattern.split("-")
        return int(parts[0]) <= port <= int(parts[1])
    if "," in str(pattern):
        return port in [int(p.strip()) for p in pattern.split(",")]
    try:
        return port == int(pattern)
    except ValueError:
        return False


def evaluate_connection(src_ip, dst_ip, src_port, dst_port, protocol, direction):
    rules = database.get_rules()
    for rule in rules:
        if not rule["enabled"]:
            continue
        rule_dir = rule["direction"]
        if rule_dir != "BOTH" and rule_dir != direction:
            continue
        rule_proto = rule.get("protocol", "ANY")
        if rule_proto not in ("ANY", "", "*") and rule_proto.upper() != protocol.upper():
            continue
        if not _match_ip(rule.get("remote_ip", ""), dst_ip if direction == "OUT" else src_ip):
            continue
        if not _match_ip(rule.get("local_ip", ""), src_ip if direction == "OUT" else dst_ip):
            continue
        if not _match_port(rule.get("remote_port", ""), dst_port if direction == "OUT" else src_port):
            continue
        if not _match_port(rule.get("local_port", ""), src_port if direction == "OUT" else dst_port):
            continue
        return rule["action"], rule["name"]
    default = database.get_setting("default_policy", "ALLOW")
    return default, "Default Policy"


# ─── Windows backend ──────────────────────────────────────────────────────────

def _netsh(args):
    ok, out, err = run(["netsh", "advfirewall", "firewall"] + args)
    return ok, out + err


def _sync_rule_windows(rule):
    name = f"FGUARD-{rule['id']}-{rule['name']}"
    _netsh(["delete", "rule", f"name={name}"])
    if not rule["enabled"]:
        return True, "Disabled"

    action = "allow" if rule["action"] == "ALLOW" else "block"
    dirs = ["in", "out"] if rule["direction"] == "BOTH" else [rule["direction"].lower()]

    for d in dirs:
        args = ["add", "rule", f"name={name}", f"dir={d}", f"action={action}"]
        proto = rule.get("protocol", "ANY")
        args.append(f"protocol={'any' if proto in ('ANY','','*') else proto.lower()}")
        rip = rule.get("remote_ip", "")
        if rip and rip not in ("", "ANY", "*"):
            args.append(f"remoteip={rip}")
        lip = rule.get("local_ip", "")
        if lip and lip not in ("", "ANY", "*"):
            args.append(f"localip={lip}")
        rport = rule.get("remote_port", "")
        if rport and rport not in ("", "ANY", "*", "0"):
            args.append(f"remoteport={rport}")
        lport = rule.get("local_port", "")
        if lport and lport not in ("", "ANY", "*", "0"):
            args.append(f"localport={lport}")
        ok, msg = _netsh(args)
        if not ok:
            return False, msg
    return True, "OK"


def _remove_rule_windows(rule):
    name = f"FGUARD-{rule['id']}-{rule['name']}"
    return _netsh(["delete", "rule", f"name={name}"])


# ─── Linux backend (iptables) ─────────────────────────────────────────────────

CHAIN_PREFIX = "FGUARD"


def _ipt(args, table=None):
    cmd = ["iptables"]
    if table:
        cmd += ["-t", table]
    ok, out, err = run(cmd + args)
    return ok, out + err


def _ipt6(args, table=None):
    cmd = ["ip6tables"]
    if table:
        cmd += ["-t", table]
    ok, out, err = run(cmd + args)
    return ok, out + err


def _ensure_chains():
    _setup_linux_forwarding()
    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        ag_chain = f"{CHAIN_PREFIX}_{chain}"
        _ipt(["-N", ag_chain])
        # Do not flush: GeoIP and other INPUT rules live in FGUARD_INPUT.
        # A flush on every fguard start silently disables geoblock.
        ok, _, _ = run([
            "iptables", "-C", ag_chain,
            "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])
        if not ok:
            _ipt(["-I", ag_chain, "1",
                  "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        if chain == "INPUT":
            ok, _, _ = run(["iptables", "-C", ag_chain, "-i", "lo", "-j", "ACCEPT"])
            if not ok:
                _ipt(["-I", ag_chain, "2", "-i", "lo", "-j", "ACCEPT"])
        ok, _, _ = run(["iptables", "-C", chain, "-j", ag_chain])
        if not ok:
            _ipt(["-I", chain, "1", "-j", ag_chain])


def _proto_args(proto):
    if proto in ("ANY", "", "*"):
        return []
    return ["-p", proto.lower()]


def _port_to_iptables(port_str):
    if not port_str or port_str in ("", "ANY", "*", "0"):
        return None
    if "-" in port_str:
        return port_str.replace("-", ":")
    return port_str


# User policy lives here so GeoBlock can rebuild FGUARD_INPUT without wiping it.
RULES_IN = "FGUARD_RULES_IN"
RULES_OUT = "FGUARD_RULES_OUT"
RULES_FWD = "FGUARD_RULES_FWD"
# File sharing between VLANs crosses FORWARD. Do not drop these there.
_LAN_SHARE_PORTS = {"137", "138", "139", "445", "137:139", "137-139"}


def _blank_match(value):
    return not value or str(value).strip() in ("", "ANY", "*", "0", "0.0.0.0/0", "::/0")


def _service_port(rule):
    """The port the rule is about, whichever column the GUI stored it in."""
    local_p = (rule.get("local_port") or "").strip()
    remote_p = (rule.get("remote_port") or "").strip()
    if (rule.get("direction") or "") == "OUT":
        return remote_p or local_p
    return local_p or remote_p


def _is_default_deny(rule):
    name = rule.get("name") or ""
    if name.startswith("Default Block"):
        return True
    port = _service_port(rule)
    if port or not _blank_match(rule.get("remote_ip")) or not _blank_match(rule.get("local_ip")):
        return False
    try:
        return int(rule.get("priority") or 0) >= 9999
    except (TypeError, ValueError):
        return False


def _enforce_default_deny():
    return database.get_setting("enforce_default_deny", "0") == "1"


def _wan_scoped(rule):
    """Seeded 'from WAN' / 'from internet' rules must not also drop the LAN."""
    text = f"{rule.get('name') or ''} {rule.get('description') or ''}".lower()
    return "from wan" in text or "from internet" in text


def _should_install(rule):
    if not rule.get("enabled"):
        return False
    if _is_default_deny(rule):
        return _enforce_default_deny()
    if rule.get("action") == "ALLOW" and not _enforce_default_deny():
        # Under ACCEPT policy an allow does nothing, and a wide allow
        # installed by mistake would sit in front of later drops.
        return False
    return True


def _ensure_rule_chains():
    for chain, parent in ((RULES_IN, "INPUT"), (RULES_OUT, "OUTPUT"), (RULES_FWD, "FORWARD")):
        _ipt(["-N", chain])
        ok, _, _ = run(["iptables", "-C", parent, "-j", chain])
        if not ok:
            _ipt(["-A", parent, "-j", chain])
        ok, _, _ = run([
            "iptables", "-C", chain, "-m", "state",
            "--state", "ESTABLISHED,RELATED", "-j", "RETURN",
        ])
        if not ok:
            _ipt(["-I", chain, "1", "-m", "state",
                  "--state", "ESTABLISHED,RELATED", "-j", "RETURN"])


def _rule_chains(rule):
    direction = rule.get("direction") or "BOTH"
    port = (_service_port(rule) or "").replace("-", ":")
    chains = []
    if direction in ("IN", "BOTH"):
        chains.append(RULES_IN)
    if direction in ("OUT", "BOTH"):
        chains.append(RULES_OUT)
    share = port in _LAN_SHARE_PORTS or port.startswith("137")
    if direction == "BOTH" and not share:
        chains.append(RULES_FWD)
    return chains


def _addrs_for(rule, chain):
    remote = rule.get("remote_ip") or ""
    local = rule.get("local_ip") or ""
    src = dst = None
    if chain == RULES_OUT:
        if not _blank_match(local):
            src = local.strip()
        if not _blank_match(remote):
            dst = remote.strip()
    else:
        if not _blank_match(remote):
            src = remote.strip()
        if not _blank_match(local):
            dst = local.strip()
    return src, dst


def _append_rule(rule):
    """Install one enabled rule. Groups and schedules apply only when that switch is on."""
    try:
        from core.parity import expand_rule, groups_enabled, rule_active
        if groups_enabled():
            if not rule_active(rule):
                return True, "Outside schedule"
            concrete_rules = expand_rule(rule, database.alias_map())
        else:
            concrete_rules = [rule]
    except ValueError as exc:
        return False, str(exc)
    installed = False
    for concrete in concrete_rules:
        ok, message, did = _append_one(concrete)
        if not ok:
            return False, message
        installed = installed or did
    return True, "OK" if installed else "Stored"


def _append_one(rule):
    """Install one concrete rule into the policy chains. Never a catch-all."""
    port = _port_to_iptables(_service_port(rule))
    action = "ACCEPT" if rule.get("action") == "ALLOW" else "DROP"
    proto = (rule.get("protocol") or "ANY").upper()
    if proto in ("TCP", "UDP", "ICMP"):
        protos = [proto.lower()]
    elif port:
        protos = ["tcp", "udp"]
    else:
        protos = [None]
    comment = f"fguard_{rule['id']}"
    installed = False
    iface = (rule.get("interface") or "").strip()
    if iface in ("", "ANY", "*") and _wan_scoped(rule):
        iface = _detect_wan_iface()
    chains = _rule_chains(rule)
    try:
        from core.parity import clean_iface, groups_enabled
        if groups_enabled() and clean_iface(rule.get("in_iface")) and clean_iface(rule.get("out_iface")):
            if RULES_FWD not in chains:
                chains = list(chains) + [RULES_FWD]
    except ValueError as exc:
        return False, str(exc), False
    for chain in chains:
        src, dst = _addrs_for(rule, chain)
        if not port and not src and not dst and action == "DROP" and not _enforce_default_deny():
            continue
        for proto_name in protos:
            args = ["-A", chain]
            if proto_name:
                args += ["-p", proto_name]
            if src:
                args += ["-s", src]
            if dst:
                args += ["-d", dst]
            if iface and iface not in ("ANY", "*") and chain != RULES_FWD:
                args += ["-o" if chain == RULES_OUT else "-i", iface]
            if chain == RULES_FWD:
                from core.parity import groups_enabled
                if groups_enabled():
                    in_iface = (rule.get("in_iface") or "").strip()
                    out_iface = (rule.get("out_iface") or "").strip()
                    if in_iface and in_iface not in ("ANY", "*"):
                        args += ["-i", in_iface]
                    if out_iface and out_iface not in ("ANY", "*"):
                        args += ["-o", out_iface]
            if port and proto_name in ("tcp", "udp"):
                args += ["--dport", port]
            args += ["-m", "comment", "--comment", comment, "-j", action]
            ok, msg = _ipt(args)
            if not ok:
                return False, msg, False
            installed = True
    return True, "OK" if installed else "Stored", installed


def _install_deny_guards():
    """Allow the firewall to keep working if default deny is explicitly on."""
    guards = [
        ["-p", "udp", "-m", "multiport", "--dports", "53,67,68,123,500,4500,1194,51820", "-j", "RETURN"],
        ["-p", "tcp", "-m", "multiport", "--dports", "53,22,80,443,8080,8888", "-j", "RETURN"],
        ["-p", "icmp", "-j", "RETURN"],
        ["-p", "esp", "-j", "RETURN"],
        ["-p", "ah", "-j", "RETURN"],
        ["-p", "gre", "-j", "RETURN"],
    ]
    for chain in (RULES_IN, RULES_OUT, RULES_FWD):
        for guard in guards:
            _ipt(["-A", chain] + guard)


def _sync_rule_linux(rule):
    """Rebuild the policy chains from the database so one save cannot stack duplicates."""
    sync_all_rules()
    return True, "OK"


def _remove_rule_linux(rule):
    sync_all_rules()
    return True, "OK"


def _setup_linux_forwarding():
    """Enable IP forwarding and persist it across reboots."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        run(["sysctl", "-w", "net.ipv4.conf.all.forwarding=1"])
        # Persist across reboots
        sysctl_conf = "/etc/sysctl.d/99-fguard.conf"
        try:
            with open(sysctl_conf, "w") as f:
                f.write("net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.forwarding = 1\n")
        except PermissionError:
            run(["bash", "-c",
                 "echo 'net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.forwarding = 1' "
                 f"> {sysctl_conf}"])
        return True
    except Exception:
        return False


def _detect_wan_iface():
    """WAN iface from the default route, then DB, then ens1."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        )
        tokens = result.stdout.split()
        if "dev" in tokens:
            return tokens[tokens.index("dev") + 1]
    except Exception:
        pass
    try:
        ifaces = database.get_interfaces()
        for iface in ifaces:
            if iface.get("type") == "WAN" or iface.get("role") == "WAN":
                name = iface.get("name") or ""
                if name:
                    return name
    except Exception:
        pass
    return "ens1"


def _nft_has_wan_masquerade(wan_iface):
    try:
        result = subprocess.run(
            ["nft", "list", "chain", "ip", "nat", "POSTROUTING"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return False
        return f'oifname "{wan_iface}" masquerade' in result.stdout
    except Exception:
        return False


def _setup_nat_masquerade(wan_iface):
    """Enable NAT masquerade on WAN (idempotent — safe on every boot)."""
    ok, _, _ = run([
        "iptables", "-t", "nat", "-C", "POSTROUTING",
        "-o", wan_iface, "-j", "MASQUERADE",
    ])
    if ok:
        return True
    ok, _msg = _ipt([
        "-t", "nat", "-A", "POSTROUTING",
        "-o", wan_iface, "-j", "MASQUERADE",
    ])
    if ok:
        return True
    if _nft_has_wan_masquerade(wan_iface):
        return True
    subprocess.run(
        ["nft", "insert", "rule", "ip", "nat", "POSTROUTING",
         "oifname", wan_iface, "masquerade"],
        capture_output=True, text=True, timeout=5,
    )
    return _nft_has_wan_masquerade(wan_iface)


def ensure_lan_nat_masquerade():
    """Re-apply LAN→WAN MASQUERADE on startup so it survives reboot/nft restore."""
    if not IS_LINUX:
        return False, "Linux only"
    wan_iface = _detect_wan_iface()
    _setup_linux_forwarding()
    _setup_nat_masquerade(wan_iface)
    try:
        from core.bov_manager import pin_ipsec_nat_rules
        pin_ipsec_nat_rules()
    except Exception:
        pass
    run(["netfilter-persistent", "save"])
    database.add_log("INFO", details=f"LAN NAT masquerade ensured on {wan_iface}")
    return True, wan_iface


# ─── Public API ───────────────────────────────────────────────────────────────

def sync_rule_to_system(rule):
    if IS_LINUX:
        return _sync_rule_linux(rule)
    return _sync_rule_windows(rule)


def remove_rule_from_system(rule):
    if IS_LINUX:
        return _remove_rule_linux(rule)
    return _remove_rule_windows(rule)


# Keep old names for compatibility
def sync_rule_to_windows(rule):
    return sync_rule_to_system(rule)


def remove_rule_from_windows(rule):
    return remove_rule_from_system(rule)


def sync_all_rules():
    """Install enabled, specific firewall rules.

    Default Block All stays off unless settings.enforce_default_deny is 1.
    Turning that on with the current rule list would drop DNS, DHCP and ESP.
    GeoBlock's FGUARD_INPUT chain is not flushed.
    """
    if not IS_LINUX:
        rules = database.get_rules()
        return [(r["name"],) + sync_rule_to_windows(r) for r in rules]
    _ensure_chains()
    _ensure_rule_chains()
    for chain in (RULES_IN, RULES_OUT, RULES_FWD):
        _ipt(["-F", chain])
        _ipt(["-A", chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "RETURN"])
    rules = database.get_rules()
    deny = [r for r in rules if _should_install(r) and _is_default_deny(r)]
    specific = [r for r in rules if _should_install(r) and not _is_default_deny(r)]
    results = []
    for rule in specific:
        ok, msg = _append_rule(rule)
        results.append((rule["name"], ok, msg))
    if deny:
        _install_deny_guards()
        for rule in deny:
            ok, msg = _append_rule(rule)
            results.append((rule["name"], ok, msg))
    return results


def get_firewall_status():
    if IS_LINUX:
        ok, out, err = run(["iptables", "-L", "-n", "--line-numbers"])
        return out if ok else f"Error: {err}"
    ok, out, err = run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    return out if ok else "Unable to query Windows Firewall"


# keep old name
def get_windows_firewall_state():
    return get_firewall_status()


def setup_router_mode(wan_iface, lan_iface):
    """Configure system as a network router/firewall gateway."""
    if not IS_LINUX:
        return False, "Router mode only supported on Linux"
    _ensure_chains()
    _setup_linux_forwarding()
    _setup_nat_masquerade(wan_iface)
    # Allow established/related traffic
    _ipt(["-A", f"{CHAIN_PREFIX}_FORWARD", "-m", "state",
          "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    # Allow LAN to WAN
    _ipt(["-A", f"{CHAIN_PREFIX}_FORWARD", "-i", lan_iface, "-o", wan_iface, "-j", "ACCEPT"])
    database.add_log("INFO", details=f"Router mode enabled: WAN={wan_iface} LAN={lan_iface}")
    return True, f"Router mode active (WAN={wan_iface}, LAN={lan_iface})"


def flush_all_rules():
    """Remove all FGUARD rules from the system."""
    if IS_LINUX:
        for chain in (f"{CHAIN_PREFIX}_INPUT", f"{CHAIN_PREFIX}_OUTPUT", f"{CHAIN_PREFIX}_FORWARD",
                      RULES_IN, RULES_OUT, RULES_FWD):
            _ipt(["-F", chain])
        return True, "Flushed"
    return False, "Use Windows FW panel to reset"
