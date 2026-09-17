"""Network interface, DHCP, DNS, NAT, and routing management (Linux/Windows)."""
import subprocess
import os
import json
import re
from db import database
from core.platform import IS_LINUX, IS_WINDOWS, run


# ─── Interface discovery ──────────────────────────────────────────────────────

def get_system_interfaces():
    """Return list of physical interfaces from the OS."""
    import psutil
    ifaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        s = stats.get(name)
        ipv4 = next((a for a in addr_list if a.family.name in ("AF_INET", "2")), None)
        ifaces.append({
            "name": name,
            "ip": ipv4.address if ipv4 else "",
            "netmask": ipv4.netmask if ipv4 else "",
            "up": s.isup if s else False,
            "speed": s.speed if s else 0,
            "mtu": s.mtu if s else 1500,
        })
    return ifaces


def apply_interface(iface):
    """Apply interface config to the OS (Linux only)."""
    if not IS_LINUX:
        return False, "Interface config is Linux only"
    name = iface["name"]
    ip = iface.get("ip_address", "")
    netmask = iface.get("netmask", "255.255.255.0")
    gateway = iface.get("gateway", "")
    mode = iface.get("ip_mode", "static")

    if mode == "dhcp":
        ok, out, err = run(["dhclient", "-r", name])
        ok, out, err = run(["dhclient", name])
        return ok, out + err

    if mode == "static" and ip:
        prefix = _netmask_to_prefix(netmask)
        run(["ip", "addr", "flush", "dev", name])
        ok, out, err = run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", name])
        if not ok:
            return False, err
        run(["ip", "link", "set", name, "up"])
        if gateway:
            run(["ip", "route", "add", "default", "via", gateway, "dev", name])
        return True, f"Interface {name} configured: {ip}/{prefix}"

    return True, "No changes applied"


def _netmask_to_prefix(netmask):
    try:
        return sum(bin(int(x)).count("1") for x in netmask.split("."))
    except Exception:
        return 24


def write_network_config(ifaces):
    """Write /etc/network/interfaces or Netplan config."""
    if not IS_LINUX:
        return False, "Linux only"

    # Try netplan first (Ubuntu)
    netplan_dir = "/etc/netplan"
    if os.path.isdir(netplan_dir):
        return _write_netplan(ifaces)
    return _write_interfaces_file(ifaces)


def _write_netplan(ifaces):
    """Write 50-fguard.yaml. Always keep VLANs; never put a default
    route on LAN. Saving/deleting a NIC must not wipe eth1.10 / eth1.20."""
    wan_if = database.get_setting("wan_interface") or "ens1"
    vlans = [v for v in database.get_vlans() if v.get("enabled")]
    vlan_parents = {v["parent_interface"] for v in vlans}
    vlan_ips = set()
    for v in vlans:
        ip = (v.get("ip_address") or "").split("/")[0].strip()
        if ip:
            vlan_ips.add(ip)

    ethernets = {}
    for iface in ifaces or []:
        if not iface.get("enabled"):
            continue
        name = iface.get("name") or ""
        if not name or "." in name:
            continue
        role = (iface.get("role") or iface.get("type") or "").upper()
        is_wan = name == wan_if or role == "WAN"
        mode = iface.get("ip_mode", "dhcp")
        entry = {}
        if is_wan or mode == "dhcp":
            entry["dhcp4"] = True
        else:
            entry["dhcp4"] = False
            ip = (iface.get("ip_address") or "").split("/")[0].strip()
            # VLAN parent is untagged trunk — do not park 192.168.0.254 on eth1
            if name in vlan_parents:
                pass
            elif ip and ip not in vlan_ips:
                nm = iface.get("netmask", "255.255.255.0")
                entry["addresses"] = [f"{ip}/{_netmask_to_prefix(nm)}"]
            if name not in (wan_if,) and not entry.get("addresses"):
                entry["optional"] = True
        if iface.get("mtu", 1500) != 1500:
            entry["mtu"] = iface["mtu"]
        ethernets[name] = entry

    if wan_if not in ethernets:
        ethernets[wan_if] = {"dhcp4": True}
    for p in vlan_parents:
        if p not in ethernets:
            ethernets[p] = {"dhcp4": False}

    config = {"network": {"version": 2, "ethernets": ethernets}}
    if vlans:
        vmap = {}
        for v in vlans:
            parent = v["parent_interface"]
            vid = v["vlan_id"]
            key = f"{parent}.{vid}"
            ip = (v.get("ip_address") or "").strip()
            prefix = _netmask_to_prefix(v.get("netmask", "255.255.255.0"))
            vent = {"id": int(vid), "link": parent, "dhcp4": False}
            if ip:
                vent["addresses"] = [ip if "/" in ip else f"{ip}/{prefix}"]
            vmap[key] = vent
        config["network"]["vlans"] = vmap

    path = "/etc/netplan/50-fguard.yaml"
    try:
        import yaml
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        os.chmod(path, 0o600)
        try:
            if os.path.isfile("/etc/netplan/50-aegisguard.yaml"):
                os.remove("/etc/netplan/50-aegisguard.yaml")
        except Exception:
            pass
        run(["netplan", "apply"])
        return True, "Netplan config applied"
    except ImportError:
        import json as _json
        with open(path.replace(".yaml", ".json"), "w") as f:
            _json.dump(config, f, indent=2)
        return True, "Config written (yaml module not installed)"
    except Exception as e:
        return False, str(e)


def _write_interfaces_file(ifaces):
    lines = ["# FGUARD network config", "auto lo", "iface lo inet loopback", ""]
    for iface in ifaces:
        if not iface.get("enabled"):
            continue
        name = iface["name"]
        mode = iface.get("ip_mode", "dhcp")
        lines.append(f"auto {name}")
        if mode == "dhcp":
            lines.append(f"iface {name} inet dhcp")
        elif mode == "static":
            ip = iface.get("ip_address", "")
            nm = iface.get("netmask", "255.255.255.0")
            gw = iface.get("gateway", "")
            lines.append(f"iface {name} inet static")
            if ip:
                lines.append(f"  address {ip}")
            lines.append(f"  netmask {nm}")
            if gw:
                lines.append(f"  gateway {gw}")
        lines.append("")
    try:
        with open("/etc/network/interfaces", "w") as f:
            f.write("\n".join(lines))
        return True, "Written to /etc/network/interfaces"
    except Exception as e:
        return False, str(e)


# ─── DHCP server (dnsmasq) ────────────────────────────────────────────────────

# Many CGNAT ISPs intercept Google Public DNS: ICMP to 8.8.8.8 works, UDP/53
# stalls. dnsmasq then fills its query pool and the LAN looks like "no internet".
_STALLED_DNS_UPSTREAMS = {"8.8.8.8", "8.8.4.4"}


def _dnsmasq_upstream(addr, fallback):
    a = (addr or "").strip()
    if not a or a in _STALLED_DNS_UPSTREAMS:
        return fallback
    return a


def write_dhcp_config():
    """Write dnsmasq config for DHCP server."""
    if not IS_LINUX:
        return False, "DHCP server config is Linux only"
    configs = database.get_dhcp_configs()
    leases = database.get_dhcp_leases()
    iface_ips = {i["name"]: i.get("ip_address", "") for i in database.get_interfaces()}
    # Also index VLAN interfaces (e.g. eth1.10) so gateway lookup works without fallback
    for v in database.get_vlans():
        vkey = f"{v['parent_interface']}.{v['vlan_id']}"
        if v.get("ip_address"):
            iface_ips.setdefault(vkey, v["ip_address"])

    lines = [
        "# FGUARD DHCP config (dnsmasq)",
        "no-resolv",
        "no-poll",
        # One slow upstream (e.g. ISP-intercepted 8.8.8.8) must not fill the
        # query pool and black-hole the LAN while ICMP still works.
        "dns-forward-max=2500",
        "cache-size=10000",
        "strict-order",
        "bogus-priv",
        "domain-needed",
    ]

    dns_s = database.get_dns_settings()
    primary = _dnsmasq_upstream(dns_s.get("primary_dns"), "1.1.1.1")
    secondary = _dnsmasq_upstream(dns_s.get("secondary_dns"), "1.0.0.1")
    if secondary == primary:
        secondary = "9.9.9.9" if primary != "9.9.9.9" else "1.0.0.1"
    lines.append(f"server={primary}")
    lines.append(f"server={secondary}")
    if dns_s.get("local_domain"):
        lines.append(f"local=/{dns_s['local_domain']}/")
        lines.append(f"domain={dns_s['local_domain']}")

    relay_ifaces = set()
    # When DHCP relay points at a remote AD/DNS, forward the AD zone there.
    # LAN DNS is intercepted by FGUARD, so without this, names like stelios.local
    # go to 1.1.1.1/8.8.8.8 and NXDOMAIN — IP works, domain does not.
    relay_cfg = database.get_dhcp_relay()
    if relay_cfg.get("enabled") and (relay_cfg.get("server_ip") or "").strip():
        sip = relay_cfg["server_ip"].strip()
        search = (dns_s.get("search_domain") or "").strip().strip(".")
        zones = []
        if search:
            zones.append(search)
        if "local" not in [z.lower() for z in zones]:
            zones.append("local")
        for z in zones:
            lines.append(f"server=/{z}/{sip}")
            lines.append(f"rebind-domain-ok=/{z}/")
        # Reverse lookups for the remote AD subnet (and typical LAN)
        try:
            import ipaddress
            net = ipaddress.ip_network(sip + "/24", strict=False)
            lines.append(f"rev-server={net.with_prefixlen},{sip}")
        except Exception:
            pass
        lines.append(f"rev-server=192.168.0.0/24,{sip}")
        relay_if = (relay_cfg.get("interfaces") or "").split(",")[0].strip()
        if relay_if:
            rif, rip = _resolve_relay_iface(relay_if)
            if rip:
                # Replies come via IPSec (ens1), so do not pass a third
                # interface name — that would drop OFFERs not seen on LAN.
                # Never use dhcp-range=...,relay (invalid IPv4 on 2.92).
                lines.append(f"dhcp-relay={rip},{sip}")
                relay_ifaces.add(rif)

    for cfg in configs:
        if not cfg["enabled"]:
            continue
        iface = cfg["interface"]
        # Interface IP is always the gateway (the firewall IS the router).
        # Fallback to manual config only if interface not in DB.
        gw = iface_ips.get(iface, "") or cfg.get("gateway") or "10.0.0.1"
        lines.append(f"interface={iface}")
        lines.append(f"dhcp-range={iface},{cfg['start_ip']},{cfg['end_ip']},{cfg['subnet_mask']},{cfg['lease_time']}s")
        lines.append(f"dhcp-option={iface},3,{gw}")
        # Always point clients to this server for DNS so web filter works.
        lines.append(f"dhcp-option={iface},6,{gw}")

    # Add interface= for all enabled VLANs so DNS always works on those subnets.
    # Add DHCP config only when dhcp_enabled is set.
    for v in database.get_vlans():
        if not v.get("enabled"):
            continue
        viface = f"{v['parent_interface']}.{v['vlan_id']}"
        lines.append(f"interface={viface}")
        if viface in relay_ifaces or not v.get("dhcp_enabled"):
            continue
        start = v.get("dhcp_start", "").strip()
        end = v.get("dhcp_end", "").strip()
        gw = v.get("ip_address", "").strip()
        nm = v.get("netmask", "255.255.255.0")
        if not (start and end and gw):
            continue
        router = v.get("dhcp_gateway", "").strip() or gw
        dns1 = v.get("dhcp_dns1", "").strip() or gw
        dns2 = v.get("dhcp_dns2", "").strip()
        dns_opt = f"{dns1},{dns2}" if dns2 else dns1
        lines.append(f"dhcp-range={viface},{start},{end},{nm},86400s")
        lines.append(f"dhcp-option={viface},3,{router}")
        lines.append(f"dhcp-option={viface},6,{dns_opt}")

    for lease in leases:
        lines.append(f"dhcp-host={lease['mac']},{lease['ip']}" + (f",{lease['hostname']}" if lease.get("hostname") else ""))

    conf = "\n".join(lines) + "\n"
    try:
        # Remove old FGUARD block if it was previously embedded in dnsmasq.conf
        main_conf_path = "/etc/dnsmasq.conf"
        try:
            with open(main_conf_path) as f:
                main = f.read()
            idx = main.find("# FGUARD DHCP config")
            if idx != -1:
                with open(main_conf_path, "w") as f:
                    f.write(main[:idx].rstrip() + "\n")
        except Exception:
            pass

        with open("/etc/dnsmasq.d/fguard.conf", "w") as f:
            f.write(conf)
        try:
            if os.path.isfile("/etc/dnsmasq.d/aegisguard.conf"):
                os.remove("/etc/dnsmasq.d/aegisguard.conf")
        except Exception:
            pass

        # Safety net: re-read and patch any missing VLAN interface= lines.
        # Guards against DB edge-cases or future regressions that would break
        # DNS for LAN clients without affecting DHCP.
        with open("/etc/dnsmasq.d/fguard.conf") as f:
            written = f.read()
        missing_ifaces = [
            f"interface={v['parent_interface']}.{v['vlan_id']}"
            for v in database.get_vlans()
            if v.get("enabled") and f"interface={v['parent_interface']}.{v['vlan_id']}" not in written
        ]
        if missing_ifaces:
            with open("/etc/dnsmasq.d/fguard.conf", "a") as f:
                f.write("\n" + "\n".join(missing_ifaces) + "\n")

        write_dns_hosts(restart=False)
        run(["systemctl", "restart", "dnsmasq"])
        return True, "dnsmasq config applied"
    except Exception as e:
        return False, str(e)


def get_dhcp_active_leases():
    """Read active DHCP leases from dnsmasq lease file."""
    path = "/var/lib/misc/dnsmasq.leases"
    if not os.path.isfile(path):
        path = "/var/lib/dnsmasq/dnsmasq.leases"
    leases = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    leases.append({
                        "expires": parts[0], "mac": parts[1],
                        "ip": parts[2], "hostname": parts[3]
                    })
    except Exception:
        pass
    return leases


def write_dns_hosts(restart=True):
    """Write GUI local DNS hosts to dnsmasq. Does not rewrite fguard.conf."""
    if not IS_LINUX:
        return False, "Linux only"
    hosts = database.get_dns_hosts()
    lines = [
        "# FGUARD local DNS hosts — Network → DNS",
        "# address= wins over forwarded AD zones (e.g. stelios.local)",
    ]
    search = (database.get_dns_settings().get("search_domain") or "").strip().strip(".")
    for h in hosts:
        name = (h.get("hostname") or "").strip().rstrip(".")
        ip = (h.get("ip") or "").strip()
        if not name or not ip:
            continue
        if "." in name:
            lines.append(f"address=/{name}/{ip}")
        else:
            lines.append(f"host-record={name},{ip}")
            if search:
                lines.append(f"address=/{name}.{search}/{ip}")
    conf = "\n".join(lines) + "\n"
    path = "/etc/dnsmasq.d/fguard-hosts.conf"
    try:
        old = ""
        if os.path.isfile(path):
            with open(path) as f:
                old = f.read()
        changed = old != conf
        if changed:
            with open(path, "w") as f:
                f.write(conf)
        try:
            if os.path.isfile("/etc/dnsmasq.d/fguard-unifi.conf"):
                os.remove("/etc/dnsmasq.d/fguard-unifi.conf")
                changed = True
        except Exception:
            pass
        if changed and restart:
            run(["systemctl", "restart", "dnsmasq"])
        return True, "Local DNS hosts applied" if changed else "Local DNS hosts unchanged"
    except Exception as e:
        return False, str(e)


# ─── DNS (resolv.conf / systemd-resolved) ─────────────────────────────────────

def apply_dns_settings():
    if not IS_LINUX:
        return False, "Linux only"
    write_dns_hosts(restart=True)
    s = database.get_dns_settings()
    servers = [s.get("primary_dns", "1.1.1.1"),
               s.get("secondary_dns", "8.8.8.8"),
               s.get("tertiary_dns", "")]
    servers = [x for x in servers if x]

    # Try systemd-resolved
    resolved_conf = "/etc/systemd/resolved.conf"
    if os.path.isfile(resolved_conf):
        try:
            dns_line = "DNS=" + " ".join(servers)
            domain = s.get("search_domain", "")
            content = f"[Resolve]\n{dns_line}\n"
            if domain:
                content += f"Domains={domain}\n"
            content += f"DNSSEC={'yes' if s.get('enable_dnssec') else 'no'}\n"
            with open(resolved_conf, "w") as f:
                f.write(content)
            run(["systemctl", "restart", "systemd-resolved"])
            return True, "DNS applied via systemd-resolved"
        except Exception as e:
            return False, str(e)

    # Fallback to resolv.conf
    try:
        lines = [f"nameserver {s}" for s in servers]
        if s.get("search_domain"):
            lines.insert(0, f"search {s['search_domain']}")
        with open("/etc/resolv.conf", "w") as f:
            f.write("\n".join(lines) + "\n")
        return True, "DNS applied via /etc/resolv.conf"
    except Exception as e:
        return False, str(e)


# ─── Static routes ────────────────────────────────────────────────────────────

def apply_routes():
    if not IS_LINUX:
        return False, "Linux only"
    routes = database.get_routes()
    results = []
    for r in routes:
        if not r["enabled"]:
            continue
        prefix = _netmask_to_prefix(r["netmask"])
        # Use "replace" instead of "add" to avoid duplicate route errors
        cmd = ["ip", "route", "replace", f"{r['destination']}/{prefix}", "via", r["gateway"]]
        if r.get("interface"):
            cmd += ["dev", r["interface"]]
        if r.get("metric"):
            cmd += ["metric", str(r["metric"])]
        ok, out, err = run(cmd)
        results.append((r["destination"], ok, err or out))
    return True, f"Applied {len(results)} routes"


def get_system_routes():
    if IS_LINUX:
        ok, out, _ = run(["ip", "route", "show"])
        return out if ok else ""
    ok, out, _ = run(["route", "print"])
    return out if ok else ""


# ─── NAT ──────────────────────────────────────────────────────────────────────

def apply_nat_rules():
    if not IS_LINUX:
        return False, "NAT management is Linux only"
    from core.rules_engine import _ipt
    nat_rules = database.get_nat_rules()
    results = []
    for r in nat_rules:
        if not r["enabled"]:
            continue
        if r["type"] == "DNAT":
            # Port forwarding: external:port -> internal:port
            args = ["-t", "nat", "-A", "PREROUTING"]
            if r.get("interface"):
                args += ["-i", r["interface"]]
            proto = r.get("protocol", "TCP").lower()
            args += ["-p", proto]
            if r.get("external_port"):
                args += ["--dport", r["external_port"]]
            args += ["-j", "DNAT", "--to-destination",
                     f"{r['internal_ip']}" + (f":{r['internal_port']}" if r.get("internal_port") else "")]
            ok, msg = _ipt(args)
        elif r["type"] == "SNAT":
            args = ["-t", "nat", "-A", "POSTROUTING"]
            args += ["-s", r["internal_ip"]]
            args += ["-j", "SNAT", "--to-source", r["external_ip"]]
            ok, msg = _ipt(args)
        elif r["type"] == "PAT":
            args = ["-t", "nat", "-A", "POSTROUTING"]
            if r.get("interface"):
                args += ["-o", r["interface"]]
            args += ["-j", "MASQUERADE"]
            ok, msg = _ipt(args)
        elif r["type"] == "1-to-1":
            ok, msg = _apply_static_nat(r)
        else:
            ok, msg = False, f"Unknown NAT type: {r['type']}"
        results.append((r["name"], ok, msg))
    try:
        from core.bov_manager import pin_ipsec_nat_rules
        pin_ipsec_nat_rules()
    except Exception:
        pass
    return True, f"Applied {sum(1 for _,ok,_ in results if ok)}/{len(results)} NAT rules"


def _apply_static_nat(rule):
    """1-to-1 Static NAT: public_ip <-> private_ip (bidirectional)."""
    public_ip  = rule.get("external_ip", "").strip()
    private_ip = rule.get("internal_ip", "").strip()
    iface      = rule.get("interface", "")

    if not public_ip or not private_ip:
        return False, "Static NAT requires both external_ip (public) and internal_ip (private)"

    from core.rules_engine import _ipt

    # DNAT: incoming traffic to public IP → redirect to private IP
    dnat_args = ["-t", "nat", "-A", "PREROUTING"]
    if iface:
        dnat_args += ["-i", iface]
    dnat_args += ["-d", public_ip, "-j", "DNAT", "--to-destination", private_ip]
    ok1, msg1 = _ipt(dnat_args)

    # SNAT: outgoing traffic from private IP → appear as public IP
    snat_args = ["-t", "nat", "-A", "POSTROUTING",
                 "-s", private_ip, "-j", "SNAT", "--to-source", public_ip]
    ok2, msg2 = _ipt(snat_args)

    # Allow forwarding between public and private
    _ipt(["-A", "FORWARD", "-d", private_ip, "-j", "ACCEPT"])
    _ipt(["-A", "FORWARD", "-s", private_ip, "-j", "ACCEPT"])

    ok = ok1 and ok2
    msg = f"DNAT: {msg1} | SNAT: {msg2}" if not ok else f"Static NAT: {public_ip} <-> {private_ip}"
    return ok, msg


def remove_static_nat(rule):
    """Remove a 1-to-1 Static NAT rule from iptables."""
    public_ip  = rule.get("external_ip", "").strip()
    private_ip = rule.get("internal_ip", "").strip()

    if not public_ip or not private_ip:
        return False, "Missing IPs"

    from core.rules_engine import _ipt
    _ipt(["-t", "nat", "-D", "PREROUTING", "-d", public_ip, "-j", "DNAT",
          "--to-destination", private_ip])
    _ipt(["-t", "nat", "-D", "POSTROUTING", "-s", private_ip, "-j", "SNAT",
          "--to-source", public_ip])
    return True, "Static NAT removed"


# ─── QoS (tc - Linux Traffic Control) ────────────────────────────────────────

def apply_qos_rules(interface="eth0"):
    """Apply QoS/traffic shaping via tc (Linux only)."""
    if not IS_LINUX:
        return False, "QoS is Linux only"
    rules = database.get_qos_rules()
    if not rules:
        return True, "No QoS rules"

    # Clear existing
    run(["tc", "qdisc", "del", "dev", interface, "root"])
    # Add HTB root
    run(["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "30"])

    priority_map = {"HIGHEST": 1, "HIGH": 2, "NORMAL": 3, "LOW": 4, "LOWEST": 5}
    results = []
    for i, r in enumerate(rules):
        if not r["enabled"]:
            continue
        class_id = f"1:{10 + i}"
        prio = priority_map.get(r["priority"], 3)
        bw = r.get("bandwidth_limit", 0)
        unit = r.get("bandwidth_unit", "kbps")
        rate = f"{bw}{unit}" if bw else "1gbit"

        run(["tc", "class", "add", "dev", interface, "parent", "1:", "classid", class_id,
             "htb", "rate", rate, "prio", str(prio)])
        results.append(r["name"])

    return True, f"QoS applied: {len(results)} classes on {interface}"


# ─── Firewall status ──────────────────────────────────────────────────────────

def get_connection_tracking():
    """Get conntrack entries (Linux)."""
    if not IS_LINUX:
        return []
    ok, out, _ = run(["conntrack", "-L", "-n"], timeout=5)
    if not ok:
        return []
    entries = []
    for line in out.splitlines()[:100]:
        entries.append(line.strip())
    return entries


# ─── DHCP Relay ───────────────────────────────────────────────────────────────

_RELAY_SCRIPT = "/usr/local/bin/fguard-dhcp-relay.py"
_RELAY_SERVICE = "fguard-dhcp-relay"
_RELAY_CONF = "/etc/default/fguard-dhcp-relay"


def _iface_ipv4(ifname):
    """Return IPv4 address of ifname, or None if it has none."""
    if not ifname:
        return None
    ok, out, _ = run(["ip", "-4", "-o", "addr", "show", "dev", ifname])
    if not ok or not out.strip():
        return None
    for tok in out.split():
        if tok.count(".") == 3 and "/" in tok:
            return tok.split("/")[0]
    return None


def _resolve_relay_iface(ifname):
    """If parent iface has no IPv4 (VLAN trunk), use the first child with an IP."""
    ip = _iface_ipv4(ifname)
    if ip:
        return ifname, ip
    ok, out, _ = run(["ip", "-4", "-o", "addr"])
    prefix = ifname + "."
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1].startswith(prefix):
            addr = parts[3].split("/")[0]
            return parts[1], addr
    return ifname, None


_RELAY_SCRIPT_CONTENT = r"""#!/usr/bin/env python3
# FGUARD DHCP Relay — uses SO_BINDTODEVICE so broadcasts reach the correct LAN interface.
# Config: /etc/default/fguard-dhcp-relay  (RELAY_IF, DHCP_SRV)
import os, socket, struct, select, fcntl, sys, logging, glob

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s',
                    stream=sys.stdout)
log = logging.getLogger('fguard-dhcp-relay')

RELAY_IF  = os.environ.get('RELAY_IF', 'eth1')
DHCP_SRV  = os.environ.get('DHCP_SRV', '192.168.0.26')
SO_BINDTODEVICE = 25
SO_REUSEPORT = 15

def _iface_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,
            struct.pack('256s', ifname[:15].encode())
        )[20:24])
    finally:
        s.close()

def _pick_iface(name):
    try:
        return name, _iface_ip(name)
    except OSError:
        pass
    for path in sorted(glob.glob('/sys/class/net/' + name + '.*')):
        child = os.path.basename(path)
        try:
            return child, _iface_ip(child)
        except OSError:
            continue
    raise SystemExit(f'No IPv4 on {name} or VLAN children — set RELAY_IF to e.g. eth1.10')

RELAY_IF, RELAY_IP = _pick_iface(RELAY_IF)

def giaddr(pkt):     return socket.inet_ntoa(pkt[24:28])
def set_giaddr(pkt): return pkt[:24] + socket.inet_aton(RELAY_IP) + pkt[28:]
def inc_hops(pkt):   return pkt[:3] + bytes([pkt[3] + 1]) + pkt[4:]
def get_mac(pkt):    return ':'.join(f'{b:02x}' for b in pkt[28:34])
def get_xid(pkt):    return struct.unpack('!I', pkt[4:8])[0]

# client_sock: bound to eth1 via SO_BINDTODEVICE — receives LAN broadcasts and
# sends the OFFER broadcast back on the same interface.
client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    client_sock.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
except OSError:
    pass
client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
client_sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, RELAY_IF.encode())
client_sock.bind(('', 67))

# server_sock: bound to RELAY_IP:67 — unicasts requests to the DHCP server and
# receives the unicast reply (wg0/tun path).
server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    server_sock.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
except OSError:
    pass
server_sock.bind((RELAY_IP, 67))

log.info(f"DHCP relay: {RELAY_IF}/{RELAY_IP} -> {DHCP_SRV}")

while True:
    readable, _, _ = select.select([client_sock, server_sock], [], [], 60)
    for sock in readable:
        data, _ = sock.recvfrom(4096)
        if not data or len(data) < 240:
            continue
        op  = data[0]
        mac = get_mac(data)
        xid = get_xid(data)
        if sock is client_sock and op == 1:
            pkt = inc_hops(data)
            if giaddr(pkt) == '0.0.0.0':
                pkt = set_giaddr(pkt)
            server_sock.sendto(pkt, (DHCP_SRV, 67))
            log.info(f"DISCOVER {mac} xid={xid:08x} -> {DHCP_SRV}")
        elif sock is server_sock and op == 2:
            if giaddr(data) == RELAY_IP:
                client_sock.sendto(data, ('255.255.255.255', 68))
                log.info(f"OFFER for {mac} xid={xid:08x} -> {RELAY_IF} broadcast")
"""

_RELAY_UNIT_CONTENT = """\
[Unit]
Description=FGUARD DHCP Relay
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/default/fguard-dhcp-relay
ExecStart=/usr/bin/python3 /usr/local/bin/fguard-dhcp-relay.py
Restart=always
RestartSec=5
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
"""


def _install_relay_service():
    """Write the relay script and systemd unit if they don't exist yet."""
    import subprocess as _sp
    script_path = _RELAY_SCRIPT
    unit_path = f"/etc/systemd/system/{_RELAY_SERVICE}.service"
    try:
        with open(script_path, "w") as f:
            f.write(_RELAY_SCRIPT_CONTENT)
        os.chmod(script_path, 0o755)
        with open(unit_path, "w") as f:
            f.write(_RELAY_UNIT_CONTENT)
        _sp.run(["systemctl", "daemon-reload"], capture_output=True)
    except Exception as e:
        return False, str(e)
    return True, ""


def apply_dhcp_relay():
    """Enable or disable DHCP relay using the fguard-dhcp-relay Python service."""
    if not IS_LINUX:
        return False, "DHCP Relay is Linux only"

    cfg = database.get_dhcp_relay()
    enabled    = cfg.get("enabled", 0)
    server_ip  = cfg.get("server_ip", "").strip()
    interfaces = cfg.get("interfaces", "").strip()

    run(["systemctl", "stop", _RELAY_SERVICE])
    # Also stop legacy isc-dhcp-relay if still present
    run(["systemctl", "stop", "isc-dhcp-relay"])
    run(["pkill", "-f", "dhcrelay"])

    if not enabled:
        run(["systemctl", "disable", _RELAY_SERVICE])
        write_dhcp_config()
        return True, "DHCP Relay stopped"

    if not server_ip:
        return False, "DHCP Relay: no server IP configured"
    if not interfaces:
        return False, "DHCP Relay: no interfaces configured"

    # Use the first configured interface as the relay interface.
    # VLAN trunks (eth1) often have no IPv4 — the address is on eth1.10 etc.
    relay_if = interfaces.split(",")[0].strip()
    resolved_if, resolved_ip = _resolve_relay_iface(relay_if)
    if not resolved_ip:
        return False, f"DHCP Relay: {relay_if} has no IPv4 (use the VLAN iface, e.g. eth1.10)"
    if resolved_if != relay_if:
        relay_if = resolved_if
        database.save_dhcp_relay(1, server_ip, relay_if)

    # Ensure relay script and unit are installed
    ok, err = _install_relay_service()
    if not ok:
        return False, f"Cannot install relay service: {err}"

    # Write config consumed by the systemd EnvironmentFile
    relay_conf = f'RELAY_IF="{relay_if}"\nDHCP_SRV="{server_ip}"\n'
    try:
        with open(_RELAY_CONF, "w") as f:
            f.write(relay_conf)
    except Exception as e:
        return False, f"Cannot write relay config: {e}"

    run(["systemctl", "enable", _RELAY_SERVICE])
    write_dhcp_config()
    # dnsmasq already owns UDP/67. Use its dhcp-relay instead of a second
    # process that cannot bind the same port (EADDRINUSE).
    run(["systemctl", "stop", _RELAY_SERVICE])
    run(["systemctl", "disable", _RELAY_SERVICE])
    ok, dns_state, _ = run(["systemctl", "is-active", "dnsmasq"])
    if ok and dns_state.strip() == "active":
        database.add_log("INFO", details=f"DHCP Relay via dnsmasq → {server_ip} on {relay_if}")
        return True, f"DHCP Relay active via dnsmasq → {server_ip} on {relay_if}"

    run(["systemctl", "enable", _RELAY_SERVICE])
    ok, _, err = run(["systemctl", "restart", _RELAY_SERVICE])
    if not ok:
        database.add_log("INFO", details=f"DHCP Relay via dnsmasq → {server_ip} on {relay_if}")
        return True, f"DHCP Relay via dnsmasq → {server_ip} on {relay_if} (helper bind failed)"

    database.add_log("INFO", details=f"DHCP Relay started → {server_ip} on {relay_if}")
    return True, f"DHCP Relay active → {server_ip} on {relay_if}"


def get_dhcp_relay_status():
    """Check if DHCP relay is active (dnsmasq dhcp-relay or helper process)."""
    ok, out, _ = run(["systemctl", "is-active", "dnsmasq"])
    if ok:
        try:
            with open("/etc/dnsmasq.d/fguard.conf") as f:
                if "dhcp-relay=" in f.read():
                    return {"running": True, "process": "dnsmasq dhcp-relay"}
        except Exception:
            pass
    ok, out, _ = run(["systemctl", "is-active", _RELAY_SERVICE])
    if not ok:
        ok, out, _ = run(["pgrep", "-fa", "fguard-dhcp-relay"])
    return {"running": ok, "process": out.strip() if ok else ""}


# ─── VLANs (802.1Q) ───────────────────────────────────────────────────────────

def _fw_ensure(table_args):
    """Add an iptables rule only if it doesn't already exist."""
    check = ["iptables", "-C"] + table_args
    ok, _, _ = run(check)
    if not ok:
        run(["iptables", "-A"] + table_args)


def _fw_ensure_insert(pos, table_args):
    """Insert an iptables rule at position only if it doesn't already exist.
    table_args must start with chain name, e.g. ["FORWARD", "-i", ...]
    """
    check = ["iptables", "-C"] + table_args
    ok, _, _ = run(check)
    if not ok:
        chain = table_args[0]
        rest = table_args[1:]
        run(["iptables", "-I", chain, str(pos)] + rest)


def apply_vlans():
    """Create/update 802.1Q VLAN subinterfaces for all enabled VLANs in DB."""
    if not IS_LINUX:
        return False, "VLAN management is Linux only"

    vlans = database.get_vlans()
    wan_if = database.get_setting("wan_interface") or "eth0"
    lan_if = database.get_setting("lan_interface") or "eth1"
    errors = []
    applied = []

    # Classify interfaces by zone
    # Main LAN interface is always in the LAN zone
    lan_ifaces = [lan_if]
    isolated_ifaces = []  # DMZ / OPTIONAL — LAN cannot reach these

    for v in vlans:
        if not v.get("enabled"):
            continue

        parent = v["parent_interface"]
        vid = v["vlan_id"]
        iface = f"{parent}.{vid}"
        ip = v.get("ip_address", "").strip()
        netmask = v.get("netmask", "255.255.255.0")
        mtu = v.get("mtu", 1500) or 1500
        prefix = _netmask_to_prefix(netmask)
        zone = (v.get("zone") or "LAN").upper()

        # Ensure parent interface is up
        run(["ip", "link", "set", parent, "up"])

        # Create VLAN subinterface if it doesn't exist
        ok, _, _ = run(["ip", "link", "show", iface])
        if not ok:
            ok, _, err = run(["ip", "link", "add", "link", parent,
                               "name", iface, "type", "vlan", "id", str(vid)])
            if not ok:
                errors.append(f"{iface}: {err}")
                continue

        run(["ip", "link", "set", iface, "mtu", str(mtu)])
        run(["ip", "link", "set", iface, "up"])

        if ip:
            run(["ip", "addr", "flush", "dev", iface])
            ok, _, err = run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", iface])
            if not ok:
                errors.append(f"{iface} IP: {err}")

        # Allow VLAN → WAN forwarding
        _fw_ensure_insert(1, ["FORWARD", "-i", iface, "-o", wan_if, "-j", "ACCEPT"])

        # Allow firewall itself to be reachable from VLAN (DNS, DHCP, web UI)
        _fw_ensure_insert(3, ["INPUT", "-i", iface, "-j", "ACCEPT"])

        if zone == "LAN":
            lan_ifaces.append(iface)
        elif zone in ("DMZ", "OPTIONAL"):
            isolated_ifaces.append(iface)

        applied.append(iface)

    # Inter-LAN routing: all LAN zone interfaces can reach each other
    for i, a in enumerate(lan_ifaces):
        for b in lan_ifaces[i + 1:]:
            _fw_ensure_insert(1, ["FORWARD", "-i", a, "-o", b, "-j", "ACCEPT"])
            _fw_ensure_insert(1, ["FORWARD", "-i", b, "-o", a, "-j", "ACCEPT"])

    # Isolation: block LAN → DMZ/OPTIONAL (append so it runs after ESTABLISHED)
    for lan in lan_ifaces:
        for iso in isolated_ifaces:
            _fw_ensure(["FORWARD", "-i", lan, "-o", iso, "-j", "DROP"])

    # Persist VLAN interfaces in netplan
    _write_vlan_netplan(vlans, wan_if)

    # Single writer for dnsmasq — never overwrite fguard.conf here.
    # A separate VLAN-only dump wipes dhcp-relay and AD DNS forwards.
    write_dhcp_config()

    # Save iptables
    run(["netfilter-persistent", "save"])

    if errors:
        return False, f"Applied {applied}, errors: {errors}"
    return True, f"VLANs applied: {applied or 'none enabled'}"


def _write_vlan_netplan(vlans, wan_if):
    """Same writer as interface save — must not overwrite VLANs or WAN."""
    _write_netplan(database.get_interfaces())


def _write_vlan_dnsmasq(vlans):
    """VLAN DHCP is written by write_dhcp_config(); do not dump a second file."""
    return write_dhcp_config()

