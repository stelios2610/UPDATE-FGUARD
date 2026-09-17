"""Branch Office VPN (BOV) Manager - Site-to-Site with all protocols.
Supports: IKEv2/IPSec, IKEv1/IPSec, L2TP/IPSec, SSL/OpenVPN, WireGuard, GRE."""
import os
import subprocess
import threading
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run
from core.vpn_keygen import generate_wireguard_keypair, generate_wireguard_preshared_key

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SWANCTL_CONF_DIR = "/etc/swanctl/conf.d"
WG_CONF_DIR = "/etc/wireguard"
BOV_CONF_DIR = os.path.join(BASE_DIR, "pki", "bov")

_tunnel_processes = {}   # tunnel_id -> process
_tunnel_statuses = {}    # tunnel_id -> "Up"|"Down"|"Error"|"Connecting"


# ══════════════════════════════════════════════════════════════════════════════
# StrongSwan 6.x / swanctl (IKEv1 + IKEv2)
# Ubuntu 26.04 uses charon-systemd + swanctl — no legacy ipsec command
# ══════════════════════════════════════════════════════════════════════════════

_DH_MAP = {
    "DH14": "modp2048", "DH15": "modp3072", "DH16": "modp4096",
    "DH19": "ecp256",   "DH20": "ecp384",   "DH21": "ecp521",
}


def _write_swanctl_conf(tunnel):
    """Generate a swanctl.conf snippet for one tunnel."""
    name = tunnel["name"].replace(" ", "_")
    ike_ver = 2 if tunnel.get("ike_version", "IKEv2") == "IKEv2" else 1

    ike_dh  = _DH_MAP.get(tunnel.get("ike_dh", "DH14"), "modp2048")
    pfs_dh  = _DH_MAP.get(tunnel.get("pfs_group", "DH14"), "modp2048")
    ike_c   = tunnel.get("ike_cipher", "aes256").lower()
    ike_h   = tunnel.get("ike_hash",   "sha256").lower()
    esp_c   = tunnel.get("esp_cipher", "aes256").lower()
    esp_h   = tunnel.get("esp_hash",   "sha256").lower()

    ike_proposal = f"{ike_c}-{ike_h}-{ike_dh}"
    esp_proposal = f"{esp_c}-{esp_h}-{pfs_dh}"

    local_ts   = tunnel.get("local_subnets",  "0.0.0.0/0")
    remote_ts  = tunnel.get("remote_subnets", "0.0.0.0/0")
    remote_gw  = tunnel["remote_gateway"]
    psk        = tunnel.get("psk", "")
    start_act  = "start" if tunnel.get("enabled", 1) else "none"
    encap      = "yes" if tunnel.get("nat_traversal", 1) else "no"
    dpd_delay  = tunnel.get("dpd_interval", 30)
    dpd_action = "restart" if tunnel.get("dpd_enabled", 1) else "none"

    return f"""connections {{
    {name} {{
        remote_addrs = {remote_gw}
        encap = {encap}
        dpd_delay = {dpd_delay}s
        local {{
            auth = psk
        }}
        remote {{
            auth = psk
        }}
        children {{
            {name} {{
                local_ts  = {local_ts}
                remote_ts = {remote_ts}
                esp_proposals = {esp_proposal}
                start_action  = {start_act}
                dpd_action    = {dpd_action}
            }}
        }}
        version = {ike_ver}
        proposals = {ike_proposal}
        keyingtries = 0
    }}
}}

secrets {{
    ike-{name} {{
        secret = "{psk}"
    }}
}}
"""


def _vpn_cidr():
    try:
        cfg = database.get_ssl_vpn_config() or {}
        subnet = cfg.get("server_subnet") or "10.8.0.0"
        netmask = cfg.get("server_netmask") or "255.255.255.0"
        bits = sum(bin(int(octet)).count("1") for octet in netmask.split("."))
        return f"{subnet}/{bits}"
    except Exception:
        return "10.8.0.0/24"


def _lan_ip_for_tunnel(tunnel):
    gw = (tunnel.get("local_gateway") or "").strip().split("/")[0]
    if gw:
        return gw
    try:
        from core.ssl_vpn import _get_lan_ip
        return _get_lan_ip()
    except Exception:
        return ""


def _reinsert_nat(rule):
    """Delete then insert at POSTROUTING 1 so the rule stays above MASQUERADE."""
    run(["iptables", "-t", "nat", "-D", "POSTROUTING"] + rule)
    run(["iptables", "-t", "nat", "-I", "POSTROUTING", "1"] + rule)


def pin_ipsec_nat_rules():
    """Keep IPsec LAN and SSL VPN traffic ahead of WAN MASQUERADE.

    If MASQUERADE matches first, packets are SNATed to the WAN IP and xfrm
    selectors (LAN <-> peer LAN) never match. iptables -C is not enough: the
    exception may already exist *below* MASQUERADE. Always re-insert at top.
    SSL VPN (10.8.0.0/24) also has ``ip rule pref 210 lookup main`` which
    sends peer LAN into WireGuard; force table 220 (IPsec) for that dest.
    """
    if not IS_LINUX:
        return
    tunnels = [
        t for t in database.get_bov_tunnels()
        if t.get("enabled", 1) and t.get("type") in ("IKEv2", "IKEv1", "L2TP-IPSec")
    ]
    vpn_net = _vpn_cidr()
    for t in reversed(tunnels):
        local_ts = (t.get("local_subnets") or "").strip()
        remote_ts = (t.get("remote_subnets") or "").strip()
        if not local_ts or not remote_ts:
            continue
        lan_ip = _lan_ip_for_tunnel(t)

        run(["ip", "rule", "del", "from", vpn_net, "to", remote_ts,
             "lookup", "220", "pref", "205"])
        run(["ip", "rule", "add", "from", vpn_net, "to", remote_ts,
             "lookup", "220", "pref", "205"])

        if lan_ip:
            _reinsert_nat([
                "-s", vpn_net, "-d", remote_ts,
                "-j", "SNAT", "--to-source", lan_ip,
            ])
        _reinsert_nat(["-s", local_ts, "-d", remote_ts, "-j", "RETURN"])

        for spec in (
            ["-s", remote_ts, "-d", local_ts, "-j", "ACCEPT"],
            ["-s", local_ts, "-d", remote_ts, "-j", "ACCEPT"],
            ["-i", "tun0", "-d", remote_ts, "-j", "ACCEPT"],
            ["-s", remote_ts, "-o", "tun0", "-j", "ACCEPT"],
        ):
            run(["iptables", "-D", "FORWARD"] + spec)
            run(["iptables", "-I", "FORWARD", "1"] + spec)

        run(["iptables", "-D", "INPUT",
             "-s", remote_ts, "-d", local_ts, "-j", "ACCEPT"])
        run(["iptables", "-I", "INPUT", "1",
             "-s", remote_ts, "-d", local_ts, "-j", "ACCEPT"])

    if tunnels:
        pol = ["-m", "policy", "--dir", "out", "--pol", "ipsec", "-j", "ACCEPT"]
        run(["iptables", "-t", "nat", "-D", "POSTROUTING"] + pol)
        run(["iptables", "-t", "nat", "-I", "POSTROUTING", "1"] + pol)


def apply_ipsec_tunnels():
    """Write swanctl configs and reload charon (auto-installs if missing)."""
    if not IS_LINUX:
        return False, "IPSec management requires Linux"

    ok_swanctl, _, _ = run(["which", "swanctl"])
    if not ok_swanctl:
        database.add_log("INFO", details="IPSec: installing strongswan...")
        run(["apt-get", "install", "-y",
             "strongswan", "strongswan-swanctl", "charon-systemd"], timeout=180)

    tunnels = database.get_bov_tunnels()
    ipsec_tunnels = [t for t in tunnels if t["type"] in ("IKEv2", "IKEv1", "L2TP-IPSec")]
    if not ipsec_tunnels:
        return True, "No IPSec tunnels to apply"

    try:
        os.makedirs(SWANCTL_CONF_DIR, exist_ok=True)
        for t in ipsec_tunnels:
            name = t["name"].replace(" ", "_")
            conf_path = os.path.join(SWANCTL_CONF_DIR, f"fguard-{name}.conf")
            with open(conf_path, "w") as f:
                f.write(_write_swanctl_conf(t))
            os.chmod(conf_path, 0o600)

        run(["systemctl", "restart", "strongswan"])
        ok, out, err = run(["swanctl", "--load-all"])

        pin_ipsec_nat_rules()

        # Open IKE + NAT-T ports for IPSec negotiation on WAN
        for proto_port in [("udp", "500"), ("udp", "4500")]:
            proto, port = proto_port
            chk_p, _, _ = run(["iptables", "-C", "INPUT",
                                "-p", proto, "--dport", port, "-j", "ACCEPT"])
            if not chk_p:
                run(["iptables", "-I", "INPUT", "1",
                     "-p", proto, "--dport", port, "-j", "ACCEPT"])

        return ok, out if ok else err
    except Exception as e:
        return False, str(e)


def connect_ipsec_tunnel(tunnel):
    name = tunnel["name"].replace(" ", "_")
    ok, out, err = run(["swanctl", "--initiate", "--child", name], timeout=30)
    if ok:
        database.update_bov_tunnel(tunnel["id"], status="Up", last_up=datetime.now().isoformat())
        database.add_log("INFO", details=f"BOV IPSec UP: {tunnel['name']}")
    else:
        database.update_bov_tunnel(tunnel["id"], status="Error")
    return ok, out if ok else err


def disconnect_ipsec_tunnel(tunnel):
    name = tunnel["name"].replace(" ", "_")
    ok, out, err = run(["swanctl", "--terminate", "--ike", name], timeout=15)
    database.update_bov_tunnel(tunnel["id"], status="Down")
    database.add_log("INFO", details=f"BOV IPSec DOWN: {tunnel['name']}")
    return ok, out if ok else err


def delete_ipsec_tunnel(tunnel):
    """Terminate SA, delete swanctl conf file, reload swanctl — no orphaned config."""
    name = tunnel["name"].replace(" ", "_")
    run(["swanctl", "--terminate", "--ike", name], timeout=15)
    conf_path = os.path.join(SWANCTL_CONF_DIR, f"fguard-{name}.conf")
    if os.path.isfile(conf_path):
        os.remove(conf_path)
    run(["swanctl", "--load-all"])
    database.update_bov_tunnel(tunnel["id"], status="Down")
    database.add_log("INFO", details=f"BOV IPSec DELETED: {tunnel['name']}")
    return True, "Deleted"


def get_ipsec_status():
    ok, out, _ = run(["swanctl", "--list-sas"])
    return out if ok else "swanctl not available"


# ══════════════════════════════════════════════════════════════════════════════
# WireGuard Site-to-Site (Hub-Spoke)
# ══════════════════════════════════════════════════════════════════════════════

def _write_wireguard_site_config(tunnel):
    """Generate WireGuard .conf for site-to-site tunnel."""
    conf = f"""# FGUARD BOV WireGuard - {tunnel['name']}
[Interface]
PrivateKey = {tunnel.get('wg_private_key','')}
ListenPort = {tunnel.get('wg_port',51820)}
# Add local tunnel IP if needed:
# Address = 10.254.0.1/30

[Peer]
PublicKey = {tunnel.get('wg_peer_pubkey','')}
{'PresharedKey = ' + tunnel.get('wg_preshared_key','') if tunnel.get('wg_preshared_key') else ''}
Endpoint = {tunnel['remote_gateway']}:{tunnel.get('wg_port',51820)}
AllowedIPs = {tunnel.get('remote_subnets','0.0.0.0/0')}
PersistentKeepalive = {tunnel.get('wg_keepalive',25)}
"""
    return conf


def apply_wireguard_tunnel(tunnel):
    """Write WireGuard config and bring up interface."""
    os.makedirs(WG_CONF_DIR, exist_ok=True)
    iface_name = f"wg-bov-{tunnel['id']}"
    conf_path = os.path.join(WG_CONF_DIR, f"{iface_name}.conf")

    conf = _write_wireguard_site_config(tunnel)
    try:
        with open(conf_path, "w") as f:
            f.write(conf)
        os.chmod(conf_path, 0o600)
    except Exception as e:
        return False, str(e)

    if IS_LINUX:
        run(["wg-quick", "down", conf_path])
        ok, out, err = run(["wg-quick", "up", conf_path], timeout=15)
        if ok:
            run(["systemctl", "enable", f"wg-quick@{iface_name}"])
            database.update_bov_tunnel(tunnel["id"], status="Up", last_up=datetime.now().isoformat())
            database.add_log("INFO", details=f"BOV WireGuard UP: {tunnel['name']}")
        return ok, out if ok else err
    return True, f"Config written: {conf_path}"


def disconnect_wireguard_tunnel(tunnel):
    iface_name = f"wg-bov-{tunnel['id']}"
    conf_path = os.path.join(WG_CONF_DIR, f"{iface_name}.conf")
    if IS_LINUX and os.path.isfile(conf_path):
        run(["wg-quick", "down", conf_path])
    database.update_bov_tunnel(tunnel["id"], status="Down")
    return True, "Disconnected"


def delete_wireguard_tunnel(tunnel):
    """Bring down WireGuard, disable systemd unit, delete conf file."""
    iface_name = f"wg-bov-{tunnel['id']}"
    conf_path = os.path.join(WG_CONF_DIR, f"{iface_name}.conf")
    if IS_LINUX:
        if os.path.isfile(conf_path):
            run(["wg-quick", "down", conf_path])
        run(["systemctl", "disable", f"wg-quick@{iface_name}"])
    if os.path.isfile(conf_path):
        os.remove(conf_path)
    database.update_bov_tunnel(tunnel["id"], status="Down")
    database.add_log("INFO", details=f"BOV WireGuard DELETED: {tunnel['name']}")
    return True, "Deleted"


# ══════════════════════════════════════════════════════════════════════════════
# SSL/OpenVPN Site-to-Site
# ══════════════════════════════════════════════════════════════════════════════

def _write_ssl_site_config(tunnel, mode="server"):
    """Generate OpenVPN site-to-site config."""
    is_server = (mode == "server")

    def _block(tag, content):
        return f"<{tag}>\n{content.strip()}\n</{tag}>\n" if content else ""

    conf = f"""# FGUARD BOV SSL - {tunnel['name']} ({mode})
# Generated: {datetime.now().isoformat()}

{'dev tun' if is_server else 'dev tun'}
proto {tunnel.get('ssl_protocol','udp')}
{'port ' + str(tunnel.get('ssl_port',1194)) if is_server else 'remote ' + tunnel['remote_gateway'] + ' ' + str(tunnel.get('ssl_port',1194))}
{'server-bridge' if not is_server else ''}

{_block('ca', tunnel.get('ssl_ca_cert',''))}
{_block('cert', tunnel.get('ssl_cert',''))}
{_block('key', tunnel.get('ssl_key',''))}
{_block('tls-auth', tunnel.get('ssl_ta_key',''))}
key-direction {'0' if is_server else '1'}

cipher {tunnel.get('ssl_cipher','AES-256-GCM')}
auth SHA256
compress lz4-v2

{'ifconfig 10.254.0.1 10.254.0.2' if is_server else 'ifconfig 10.254.0.2 10.254.0.1'}
route {tunnel.get('remote_subnets','').split(',')[0].strip()} 255.255.255.0

keepalive 10 120
persist-key
persist-tun
verb 3
"""
    return conf


def apply_ssl_site_tunnel(tunnel):
    """Start OpenVPN site-to-site tunnel."""
    os.makedirs(BOV_CONF_DIR, exist_ok=True)
    conf_path = os.path.join(BOV_CONF_DIR, f"bov-ssl-{tunnel['id']}.conf")
    conf = _write_ssl_site_config(tunnel, mode="client")

    try:
        with open(conf_path, "w") as f:
            f.write(conf)
    except Exception as e:
        return False, str(e)

    exe = database.get_setting("vpn_openvpn_path", "openvpn")
    try:
        proc = subprocess.Popen([exe, "--config", conf_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _tunnel_processes[tunnel["id"]] = proc
        database.update_bov_tunnel(tunnel["id"], status="Connecting")
        threading.Timer(5, lambda: _check_ssl_up(tunnel, proc)).start()
        return True, f"SSL tunnel connecting (PID {proc.pid})"
    except Exception as e:
        return False, str(e)


def _check_ssl_up(tunnel, proc):
    if proc.poll() is None:
        database.update_bov_tunnel(tunnel["id"], status="Up", last_up=datetime.now().isoformat())
        database.add_log("INFO", details=f"BOV SSL UP: {tunnel['name']}")
    else:
        database.update_bov_tunnel(tunnel["id"], status="Error")


# ══════════════════════════════════════════════════════════════════════════════
# Generic connect/disconnect dispatcher
# ══════════════════════════════════════════════════════════════════════════════

def connect_tunnel(tunnel):
    t = tunnel["type"]
    if t in ("IKEv2", "IKEv1", "L2TP-IPSec"):
        apply_ipsec_tunnels()
        return connect_ipsec_tunnel(tunnel)
    elif t == "WireGuard":
        return apply_wireguard_tunnel(tunnel)
    elif t == "SSL-OpenVPN":
        return apply_ssl_site_tunnel(tunnel)
    return False, f"Protocol {t} not yet implemented"


def disconnect_tunnel(tunnel):
    t = tunnel["type"]
    if t in ("IKEv2", "IKEv1", "L2TP-IPSec"):
        return disconnect_ipsec_tunnel(tunnel)
    elif t == "WireGuard":
        return disconnect_wireguard_tunnel(tunnel)
    elif t == "SSL-OpenVPN":
        proc = _tunnel_processes.pop(tunnel["id"], None)
        if proc and proc.poll() is None:
            proc.terminate()
        database.update_bov_tunnel(tunnel["id"], status="Down")
        return True, "Disconnected"
    return False, f"Protocol {t} not supported"


def delete_tunnel(tunnel):
    """Called on UI delete: disconnect AND remove all config files from disk."""
    t = tunnel["type"]
    if t in ("IKEv2", "IKEv1", "L2TP-IPSec"):
        return delete_ipsec_tunnel(tunnel)
    elif t == "WireGuard":
        return delete_wireguard_tunnel(tunnel)
    elif t == "SSL-OpenVPN":
        proc = _tunnel_processes.pop(tunnel["id"], None)
        if proc and proc.poll() is None:
            proc.terminate()
        conf_path = os.path.join(BOV_CONF_DIR, f"bov-ssl-{tunnel['id']}.conf")
        if os.path.isfile(conf_path):
            os.remove(conf_path)
        database.update_bov_tunnel(tunnel["id"], status="Down")
        return True, "Deleted"
    return False, f"Protocol {t} not supported"


def prefer_ipsec_routes_over_wireguard():
    """Stop wg0 from stealing IPSec remote subnets.

    StrongSwan puts 10.16.0.0/24 in table 220 with src 192.168.0.254.
    If the same prefix is in WireGuard AllowedIPs, main-table uses dead wg0
    and FGUARD itself cannot relay DHCP or resolve AD — LAN clients still
    work because their source already matches the IPSec policy.
    """
    if not IS_LINUX:
        return
    ok, table220, _ = run(["ip", "route", "show", "table", "220"])
    if not ok or not (table220 or "").strip():
        return
    ok, rules, _ = run(["ip", "rule", "list"])
    if ok and "lookup 220" not in (rules or ""):
        for line in table220.splitlines():
            dest = (line.split() or [None])[0]
            if dest and "/" in dest:
                run(["ip", "rule", "add", "to", dest, "lookup", "220", "priority", "220"])
    for line in table220.splitlines():
        dest = (line.split() or [None])[0]
        if dest:
            run(["ip", "route", "del", dest, "dev", "wg0"])
    # Keep wg0 AllowedIPs from reinstalling the stolen route
    ipsec_nets = set()
    for line in table220.splitlines():
        dest = (line.split() or [None])[0]
        if dest:
            ipsec_nets.add(dest)
    ok, ai, _ = run(["wg", "show", "wg0", "allowed-ips"])
    if ok and ai:
        for line in ai.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            peer, nets = parts[0], parts[1:]
            keep = [n for n in nets if n not in ipsec_nets]
            if keep != nets and keep:
                run(["wg", "set", "wg0", "peer", peer, "allowed-ips", ",".join(keep)])


def restore_tunnels_on_boot():
    """Called at app startup: re-apply enabled BOV tunnels after power outage / restart."""
    if not IS_LINUX:
        return

    tunnels = database.get_bov_tunnels()

    # IPSec: ensure conf files exist on disk — StrongSwan auto-connects via start_action=start
    ipsec_tunnels = [t for t in tunnels
                     if t["type"] in ("IKEv2", "IKEv1", "L2TP-IPSec") and t.get("enabled", 1)]
    if ipsec_tunnels:
        os.makedirs(SWANCTL_CONF_DIR, exist_ok=True)
        wrote = False
        for t in ipsec_tunnels:
            name = t["name"].replace(" ", "_")
            conf_path = os.path.join(SWANCTL_CONF_DIR, f"fguard-{name}.conf")
            if not os.path.isfile(conf_path):
                with open(conf_path, "w") as f:
                    f.write(_write_swanctl_conf(t))
                os.chmod(conf_path, 0o600)
                wrote = True
        if wrote:
            run(["swanctl", "--load-all"])
        pin_ipsec_nat_rules()

    # WireGuard BOV: bring up + enable systemd so they survive future reboots
    wg_tunnels = [t for t in tunnels
                  if t["type"] == "WireGuard" and t.get("enabled", 1)]
    for t in wg_tunnels:
        apply_wireguard_tunnel(t)

    prefer_ipsec_routes_over_wireguard()


def get_tunnel_status(tunnel_id):
    proc = _tunnel_processes.get(tunnel_id)
    if proc:
        return "Up" if proc.poll() is None else "Down"
    return None


# ── Config export ─────────────────────────────────────────────────────────────

def export_peer_config(tunnel):
    """Generate the configuration for the REMOTE peer (to paste on the other side)."""
    t = tunnel["type"]
    name = tunnel["name"]

    if t == "WireGuard":
        # Generate reverse config for remote peer
        conf = f"""# FGUARD BOV - Remote peer config for '{name}'
# Paste this on the REMOTE WireGuard device

[Interface]
# Generate your own private key: wg genkey
# PrivateKey = <YOUR_PRIVATE_KEY>
ListenPort = {tunnel.get('wg_port',51820)}

[Peer]
PublicKey = {tunnel.get('wg_public_key','<LOCAL_PUBLIC_KEY>')}
{'PresharedKey = ' + tunnel.get('wg_preshared_key','') if tunnel.get('wg_preshared_key') else ''}
Endpoint = <YOUR_LOCAL_PUBLIC_IP>:{tunnel.get('wg_port',51820)}
AllowedIPs = {tunnel.get('local_subnets','0.0.0.0/0')}
PersistentKeepalive = {tunnel.get('wg_keepalive',25)}
"""
        return conf

    elif t in ("IKEv2", "IKEv1"):
        return f"""# StrongSwan config for REMOTE peer '{name}'
# Add to /etc/ipsec.conf on remote device

conn {name.replace(' ','_')}-remote
    keyexchange={t.lower()}
    left=%defaultroute
    leftsubnet={tunnel.get('remote_subnets','')}
    right=<LOCAL_GATEWAY_IP>
    rightsubnet={tunnel.get('local_subnets','')}
    ike={tunnel.get('ike_cipher','aes256').lower()}-{tunnel.get('ike_hash','sha256').lower()}-{'modp2048'}!
    esp={tunnel.get('esp_cipher','aes256').lower()}-{tunnel.get('esp_hash','sha256').lower()}!
    authby=secret
    auto=start

# /etc/ipsec.secrets on remote:
# %any <LOCAL_GATEWAY_IP> : PSK "{tunnel.get('psk','')}"
"""

    elif t == "SSL-OpenVPN":
        return _write_ssl_site_config(tunnel, mode="server")

    return f"# No peer config template for protocol {t}"
