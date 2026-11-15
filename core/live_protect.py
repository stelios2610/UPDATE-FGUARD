"""One iptables hook for DDoS, IPS and reputation.

Blocks go into ipsets. The hook matches only NEW connections, so an
established VPN, DNS reply or web session is not cut when an address
is added. Private networks and site-to-site peers are never inserted.
"""
import ipaddress
import os
import time
from core.platform import IS_LINUX, run

_SETS = {
    "fguard_ddos": ["hash:ip", "timeout", "300"],
    "fguard_ips": ["hash:ip", "timeout", "600"],
    "fguard_reputation": ["hash:net", "family", "inet", "hashsize", "4096", "maxelem", "200000"],
}

_SAFE = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("1.1.1.1/32"),
    ipaddress.ip_network("1.0.0.1/32"),
    ipaddress.ip_network("8.8.8.8/32"),
    ipaddress.ip_network("8.8.4.4/32"),
    ipaddress.ip_network("9.9.9.9/32"),
    ipaddress.ip_network("149.112.112.112/32"),
]

_peer_cache = {"at": 0.0, "nets": []}
_local_cache = {"at": 0.0, "ips": set()}


def _peer_nets():
    now = time.time()
    if now - _peer_cache["at"] < 60:
        return _peer_cache["nets"]
    nets = []
    try:
        from db import database
        for tunnel in database.get_bov_tunnels():
            gw = (tunnel.get("remote_gateway") or "").split(":")[0].strip()
            try:
                nets.append(ipaddress.ip_network(gw + "/32", strict=False))
            except ValueError:
                pass
    except Exception:
        pass
    if IS_LINUX:
        ok, out, _ = run(["wg", "show", "all", "endpoints"], timeout=4)
        if ok:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and ":" in parts[-1]:
                    host = parts[-1].rsplit(":", 1)[0].strip("[]")
                    try:
                        nets.append(ipaddress.ip_network(host + "/32", strict=False))
                    except ValueError:
                        pass
        ok, sas, _ = run(["swanctl", "--list-sas"], timeout=6)
        if ok:
            import re
            for found in re.findall(r"\d+\.\d+\.\d+\.\d+", sas or ""):
                try:
                    nets.append(ipaddress.ip_network(found + "/32", strict=False))
                except ValueError:
                    pass
    _peer_cache["at"] = now
    _peer_cache["nets"] = nets
    return nets


def local_addrs():
    now = time.time()
    if now - _local_cache["at"] < 60 and _local_cache["ips"]:
        return _local_cache["ips"]
    found = set()
    if IS_LINUX:
        ok, out, _ = run(["ip", "-4", "-o", "addr", "show"], timeout=4)
        if ok:
            for token in out.split():
                if token.count(".") == 3 and "/" in token:
                    found.add(token.split("/")[0])
    _local_cache["at"] = now
    _local_cache["ips"] = found
    return found


def is_protected(ip):
    """True when this address must never be auto-blocked."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return True
    if addr.version != 4:
        return True
    if any(addr in net for net in _SAFE) or any(addr in net for net in _peer_nets()):
        return True
    return str(addr) in local_addrs()


def usable_network(text):
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4 or net.prefixlen < 16:
        return None
    if net.is_private or net.is_loopback or net.is_multicast or net.is_reserved or net.is_unspecified:
        return None
    if any(net.overlaps(safe) for safe in _SAFE):
        return None
    if any(peer.network_address in net for peer in _peer_nets()):
        return None
    return net


def ensure():
    """Create the sets and the NEW-only hooks. Safe to call on every boot."""
    if not IS_LINUX:
        return
    for name, spec in _SETS.items():
        run(["ipset", "create", name, *spec, "-exist"])
    for parent in ("INPUT", "FORWARD"):
        for name in _SETS:
            matchers = (
                ["-m", "conntrack", "--ctstate", "NEW"],
                ["-m", "state", "--state", "NEW"],
            )
            hooked = False
            for match in matchers:
                ok, _, _ = run(["iptables", "-C", parent, *match,
                                "-m", "set", "--match-set", name, "src", "-j", "DROP"])
                if ok:
                    hooked = True
                    break
            if hooked:
                continue
            for match in matchers:
                ok, _, _ = run(["iptables", "-I", parent, "1", *match,
                                "-m", "set", "--match-set", name, "src", "-j", "DROP"])
                if ok:
                    break


def block_ip(set_name, ip, timeout):
    if not IS_LINUX or is_protected(ip):
        return False
    ensure()
    args = ["ipset", "add", set_name, str(ip), "-exist"]
    if timeout and int(timeout) > 0:
        args += ["timeout", str(int(timeout))]
    ok, _, _ = run(args)
    return ok


def unblock_ip(set_name, ip):
    if not IS_LINUX:
        return
    run(["ipset", "del", set_name, str(ip)])


def load_reputation(path=None):
    """Replace the reputation set from the on-disk blocklist. Does not download."""
    if not IS_LINUX:
        return 0
    ensure()
    if not path:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "blocklist.txt")
    if not os.path.isfile(path):
        return 0
    lines = ["create fguard_reputation_new hash:net family inet hashsize 4096 maxelem 200000 -exist",
             "flush fguard_reputation_new"]
    count = 0
    with open(path, errors="ignore") as handle:
        for raw in handle:
            net = usable_network(raw.split()[0] if raw.split() else "")
            if not net:
                continue
            lines.append(f"add fguard_reputation_new {net}")
            count += 1
            if count >= 150000:
                break
    if count == 0:
        return 0
    blob = "\n".join(lines) + "\n"
    try:
        import subprocess
        subprocess.run(["ipset", "restore"], input=blob, text=True, timeout=60, check=False)
        run(["ipset", "swap", "fguard_reputation_new", "fguard_reputation"])
        run(["ipset", "destroy", "fguard_reputation_new"])
    except Exception:
        return 0
    return count


def half_open_counts(limit=8000):
    """Map public source IP -> number of unanswered flows in conntrack."""
    path = "/proc/net/nf_conntrack"
    counts = {}
    if not IS_LINUX or not os.path.isfile(path):
        return counts
    try:
        handle = open(path, errors="ignore")
    except OSError:
        return counts
    with handle:
        for index, line in enumerate(handle):
            if index >= limit:
                break
            if "SYN_SENT" not in line and "SYN_RECV" not in line and "UNREPLIED" not in line:
                continue
            src = dst = dport = None
            parts = line.split()
            for token in parts:
                if token.startswith("src=") and src is None:
                    src = token[4:]
                elif token.startswith("dst=") and dst is None:
                    dst = token[4:]
                elif token.startswith("dport=") and dport is None:
                    dport = token[6:]
            if not src or is_protected(src) or is_protected(dst or ""):
                continue
            bucket = counts.setdefault(src, {"n": 0, "ports": set()})
            bucket["n"] += 1
            if dport and dport.isdigit():
                bucket["ports"].add(int(dport))
    return counts
