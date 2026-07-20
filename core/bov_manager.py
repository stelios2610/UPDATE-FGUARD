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
            conf_path = os.path.join(SWANCTL_CONF_DIR, f"aegisguard-{name}.conf")
            with open(conf_path, "w") as f:
                f.write(_write_swanctl_conf(t))
            os.chmod(conf_path, 0o600)

        run(["systemctl", "restart", "strongswan"])
        ok, out, err = run(["swanctl", "--load-all"])

        # Add iptables rules for IPSec traffic
        for t in ipsec_tunnels:
            if not t.get("enabled", 1):
                continue
            local_ts = t.get("local_subnets", "").strip()
            remote_ts = t.get("remote_subnets", "").strip()
            if not local_ts or not remote_ts:
                continue

            # 1. Skip MASQUERADE for IPSec traffic (NAT breaks xfrm matching)
            chk, _, _ = run(["iptables", "-t", "nat", "-C", "POSTROUTING",
                              "-s", local_ts, "-d", remote_ts, "-j", "RETURN"])
            if not chk:
                run(["iptables", "-t", "nat", "-I", "POSTROUTING", "1",
                     "-s", local_ts, "-d", remote_ts, "-j", "RETURN"])

            # 2. Accept decrypted inbound IPSec packets (from remote subnet to us)
            chk2, _, _ = run(["iptables", "-C", "INPUT",
                               "-s", remote_ts, "-d", local_ts, "-j", "ACCEPT"])
            if not chk2:
                run(["iptables", "-I", "INPUT", "1",
                     "-s", remote_ts, "-d", local_ts, "-j", "ACCEPT"])

            # 3. Accept forwarded IPSec packets (remote→local direction)
            chk3, _, _ = run(["iptables", "-C", "FORWARD",
                               "-s", remote_ts, "-d", local_ts, "-j", "ACCEPT"])
            if not chk3:
                run(["iptables", "-I", "FORWARD", "1",
                     "-s", remote_ts, "-d", local_ts, "-j", "ACCEPT"])

        # 4. Open IKE + NAT-T ports for IPSec negotiation on WAN
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
    conf_path = os.path.join(SWANCTL_CONF_DIR, f"aegisguard-{name}.conf")
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
    conf = f"""# FGUARD UTC BOV WireGuard - {tunnel['name']}
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

    conf = f"""# FGUARD UTC BOV SSL - {tunnel['name']} ({mode})
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
            conf_path = os.path.join(SWANCTL_CONF_DIR, f"aegisguard-{name}.conf")
            if not os.path.isfile(conf_path):
                with open(conf_path, "w") as f:
                    f.write(_write_swanctl_conf(t))
                os.chmod(conf_path, 0o600)
                wrote = True
        if wrote:
            run(["swanctl", "--load-all"])

    # WireGuard BOV: bring up + enable systemd so they survive future reboots
    wg_tunnels = [t for t in tunnels
                  if t["type"] == "WireGuard" and t.get("enabled", 1)]
    for t in wg_tunnels:
        apply_wireguard_tunnel(t)


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
        conf = f"""# FGUARD UTC BOV - Remote peer config for '{name}'
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
