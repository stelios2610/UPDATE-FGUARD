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
    name = f"AegisGuard-{rule['id']}-{rule['name']}"
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
    name = f"AegisGuard-{rule['id']}-{rule['name']}"
    return _netsh(["delete", "rule", f"name={name}"])


# ─── Linux backend (iptables) ─────────────────────────────────────────────────

CHAIN_PREFIX = "AEGISGUARD"


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
        # Always ensure ESTABLISHED/RELATED is rule #1 in each chain
        # so that reply packets are never blocked regardless of other rules.
        # Flush first to avoid duplicates, then re-add as rule 1.
        _ipt(["-F", ag_chain])
        _ipt(["-I", ag_chain, "1",
              "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        # Also always allow loopback in INPUT
        if chain == "INPUT":
            _ipt(["-I", ag_chain, "2", "-i", "lo", "-j", "ACCEPT"])
        # Jump from main chain if not already there
        ok, out, _ = run(["iptables", "-C", chain, "-j", ag_chain])
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


def _sync_rule_linux(rule):
    rule_tag = f"--comment aegisguard_{rule['id']}"
    # Remove old rule first
    _remove_rule_linux(rule)

    if not rule["enabled"]:
        return True, "Disabled"

    action = "ACCEPT" if rule["action"] == "ALLOW" else "DROP"
    dirs = []
    if rule["direction"] in ("IN", "BOTH"):
        dirs.append(("INPUT", rule.get("remote_ip", ""), rule.get("local_ip", ""),
                     rule.get("remote_port", ""), rule.get("local_port", "")))
    if rule["direction"] in ("OUT", "BOTH"):
        dirs.append(("OUTPUT", rule.get("local_ip", ""), rule.get("remote_ip", ""),
                     rule.get("local_port", ""), rule.get("remote_port", "")))

    for chain, src_ip, dst_ip, src_port, dst_port in dirs:
        ag_chain = f"{CHAIN_PREFIX}_{chain}"
        args = ["-A", ag_chain]
        args += _proto_args(rule.get("protocol", "ANY"))

        if src_ip and src_ip not in ("", "ANY", "*"):
            args += ["-s", src_ip]
        if dst_ip and dst_ip not in ("", "ANY", "*"):
            args += ["-d", dst_ip]

        proto = rule.get("protocol", "ANY")
        if proto.upper() in ("TCP", "UDP"):
            sp = _port_to_iptables(src_port)
            dp = _port_to_iptables(dst_port)
            if sp:
                args += ["--sport", sp]
            if dp:
                args += ["--dport", dp]

        args += ["-m", "comment", "--comment", f"aegisguard_{rule['id']}"]
        args += ["-j", action]

        ok, msg = _ipt(args)
        if not ok:
            return False, msg
    return True, "OK"


def _remove_rule_linux(rule):
    tag = f"aegisguard_{rule['id']}"
    for chain in (f"{CHAIN_PREFIX}_INPUT", f"{CHAIN_PREFIX}_OUTPUT", f"{CHAIN_PREFIX}_FORWARD"):
        while True:
            ok, out, _ = run(["iptables", "-L", chain, "--line-numbers", "-n"])
            if not ok:
                break
            lines = [l for l in out.splitlines() if tag in l]
            if not lines:
                break
            num = lines[0].split()[0]
            _ipt(["-D", chain, num])
    return True, "OK"


def _setup_linux_forwarding():
    """Enable IP forwarding and persist it across reboots."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        run(["sysctl", "-w", "net.ipv4.conf.all.forwarding=1"])
        # Persist across reboots
        sysctl_conf = "/etc/sysctl.d/99-aegisguard.conf"
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


def _setup_nat_masquerade(wan_iface):
    """Enable NAT masquerade on WAN interface (router mode)."""
    _ipt(["-t", "nat", "-A", "POSTROUTING", "-o", wan_iface, "-j", "MASQUERADE"])
    return True


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
    if IS_LINUX:
        _ensure_chains()
    rules = database.get_rules()
    results = []
    for rule in rules:
        ok, msg = sync_rule_to_system(rule)
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
    """Remove all FGUARD UTC rules from the system."""
    if IS_LINUX:
        for chain in (f"{CHAIN_PREFIX}_INPUT", f"{CHAIN_PREFIX}_OUTPUT", f"{CHAIN_PREFIX}_FORWARD"):
            _ipt(["-F", chain])
        return True, "Flushed"
    return False, "Use Windows FW panel to reset"
