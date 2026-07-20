"""SSL VPN (Mobile VPN with SSL) - OpenVPN server management.
Auto-generates PKI, manages users, generates per-user .ovpn configs."""
import os
import subprocess
import threading
import shutil
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run
from core.vpn_keygen import generate_openvpn_pki, generate_openvpn_server_config, generate_openvpn_client_config
from core.mfa import hash_password

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
PKI_DIR = os.path.join(BASE_DIR, "pki", "ssl-vpn")
CONFIGS_DIR = os.path.join(BASE_DIR, "vpn-configs")
SERVER_CONF = os.path.join(BASE_DIR, "ssl-vpn-server.conf")
SYSTEMD_CONF = "/etc/openvpn/server/server.conf"

_server_process = None
_server_status = "Stopped"


# ── PKI Setup ─────────────────────────────────────────────────────────────────

def is_pki_initialized():
    return (os.path.isfile(os.path.join(PKI_DIR, "ca.crt")) and
            os.path.isfile(os.path.join(PKI_DIR, "server.crt")))


def initialize_pki(server_name="aegisguard-ssl", progress_cb=None):
    """Generate CA + server PKI. Called once on first setup."""
    os.makedirs(PKI_DIR, exist_ok=True)
    os.makedirs(CONFIGS_DIR, exist_ok=True)

    if progress_cb:
        progress_cb("Generating PKI (CA + server certificates)...")

    result = generate_openvpn_pki(PKI_DIR, server_name="server", client_name="__template__")

    if not result["success"]:
        failed = [(n, m) for n, ok, m in result["steps"] if not ok]
        return False, f"PKI generation failed: {failed[0][1] if failed else 'Unknown'}"

    # Store cert/key content in DB config
    def _read(path):
        try:
            with open(path) as f:
                return f.read()
        except Exception:
            return ""

    database.save_ssl_vpn_config(
        pki_dir=PKI_DIR,
        ca_cert=_read(os.path.join(PKI_DIR, "ca.crt")),
        server_cert=_read(os.path.join(PKI_DIR, "server.crt")),
        server_key=_read(os.path.join(PKI_DIR, "server.key")),
        dh_params=_read(os.path.join(PKI_DIR, "dh.pem")),
        ta_key=_read(os.path.join(PKI_DIR, "ta.key")),
        status="Ready"
    )

    if progress_cb:
        progress_cb("PKI initialized successfully.")

    database.add_log("INFO", details="SSL VPN PKI initialized")
    return True, "PKI generated successfully"


# ── Server Config ─────────────────────────────────────────────────────────────

def write_server_config():
    """Write OpenVPN server .conf file from DB settings."""
    cfg = database.get_ssl_vpn_config()
    if not cfg:
        return False, "SSL VPN not configured"

    subnet = cfg.get("server_subnet", "10.8.0.0")
    netmask = cfg.get("server_netmask", "255.255.255.0")
    port = cfg.get("port", 1194)
    proto = cfg.get("protocol", "udp")
    cipher = cfg.get("cipher", "AES-256-GCM")
    auth = cfg.get("auth", "SHA256")

    # Write inline certs
    def _block(tag, content):
        return f"<{tag}>\n{content.strip()}\n</{tag}>\n" if content else ""

    _push_redirect = 'push "redirect-gateway def1 bypass-dhcp"\n' if cfg.get("redirect_gateway", 1) else ""
    _routes = database.get_ssl_vpn_routes()
    _push_routes = "".join(
        f'push "route {r["network"]} {r["netmask"]}"\n'
        for r in _routes if r.get("enabled", 1)
    )
    _dns_domain = cfg.get("dns_domain", "").strip()
    _push_domain = f'push "dhcp-option DOMAIN {_dns_domain}"\n' if _dns_domain else ""

    conf = f"""# FGUARD UTC SSL VPN Server
# Generated: {datetime.now().isoformat()}

port {port}
proto {proto}
dev tun

# PKI (inline)
{_block('ca', cfg.get('ca_cert',''))}
{_block('cert', cfg.get('server_cert',''))}
{_block('key', cfg.get('server_key',''))}
{_block('dh', cfg.get('dh_params',''))}
{_block('tls-auth', cfg.get('ta_key',''))}
key-direction 0

# Network
server {subnet} {netmask}
{_push_redirect}{_push_routes}push "dhcp-option DNS {cfg.get('dns1','1.1.1.1')}"
push "dhcp-option DNS {cfg.get('dns2','8.8.8.8')}"
{_push_domain}

# Security
cipher {cipher}
auth {auth}
tls-version-min {cfg.get('tls_version','1.2')}
# User auth via script
script-security 2
auth-user-pass-verify /etc/aegisguard/vpn-auth.sh via-file
username-as-common-name
verify-client-cert optional

# Settings
keepalive 10 120
{'compress lz4-v2' if cfg.get('compress',1) else ''}
{'push "compress lz4-v2"' if cfg.get('compress',1) else ''}
max-clients 100
persist-key
persist-tun
user nobody
group nogroup
status /var/log/aegisguard-ssl-vpn-status.log
log-append /var/log/aegisguard-ssl-vpn.log
verb 3

{cfg.get('extra_opts','') or ''}
"""

    try:
        with open(SERVER_CONF, "w") as f:
            f.write(conf)
        if IS_LINUX:
            os.makedirs(os.path.dirname(SYSTEMD_CONF), exist_ok=True)
            shutil.copy2(SERVER_CONF, SYSTEMD_CONF)
        return True, SERVER_CONF
    except Exception as e:
        return False, str(e)


def reload_systemd_server():
    """Restart the systemd-managed OpenVPN server to apply config changes."""
    if not IS_LINUX:
        return True, "Not Linux"
    try:
        subprocess.run(
            ["systemctl", "restart", "openvpn-server@server"],
            timeout=15, check=True, capture_output=True
        )
        return True, "OpenVPN restarted"
    except Exception as e:
        return False, str(e)


def write_auth_script():
    """Write the OpenVPN user auth script."""
    script = """#!/bin/bash
# FGUARD UTC SSL VPN auth script
# Called by OpenVPN via-file: $1 = temp file with username/password

/usr/bin/python3 /etc/aegisguard/vpn_auth_check.py "$1"
"""
    auth_script = "/etc/aegisguard/vpn-auth.sh"
    auth_check = "/etc/aegisguard/vpn_auth_check.py"

    auth_check_code = """#!/usr/bin/env python3
import sys, sqlite3, hashlib, hmac

DB = '/opt/aegisguard/firewall.db'

try:
    import bcrypt as _bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False

try:
    with open(sys.argv[1]) as f:
        lines = f.read().splitlines()
    username = lines[0] if len(lines) > 0 else ''
    password = lines[1] if len(lines) > 1 else ''

    conn = sqlite3.connect(DB)
    row = conn.execute('SELECT password_hash, enabled FROM vpn_users WHERE username=?', (username,)).fetchone()
    conn.close()
    if not row or not row[1]:
        sys.exit(1)
    phash = row[0]
    if not phash or ':' not in phash:
        sys.exit(1)

    if phash.startswith('bcrypt:'):
        if not _BCRYPT_OK:
            sys.exit(1)
        sys.exit(0 if _bcrypt.checkpw(password.encode(), phash[7:].encode()) else 1)
    else:
        parts = phash.split(':', 2)
        if len(parts) != 3:
            sys.exit(1)
        _, salt, stored = parts
        h = hashlib.sha256(f'{salt}{password}'.encode()).hexdigest()
        sys.exit(0 if hmac.compare_digest(h, stored) else 1)
except Exception:
    sys.exit(1)
"""
    try:
        os.makedirs("/etc/aegisguard", exist_ok=True)
        with open(auth_script, "w") as f:
            f.write(script)
        with open(auth_check, "w") as f:
            f.write(auth_check_code)
        os.chmod(auth_script, 0o755)
        os.chmod(auth_check, 0o755)
        os.chmod("/etc/aegisguard", 0o755)
        return True, "Auth scripts written"
    except Exception as e:
        return False, str(e)


# ── Server Control ────────────────────────────────────────────────────────────

def start_server():
    global _server_process, _server_status
    if _server_process and _server_process.poll() is None:
        return False, "Already running"

    ok, msg = write_server_config()
    if not ok:
        return False, msg

    if IS_LINUX:
        write_auth_script()
        apply_vpn_internet_nat()

    exe_path = database.get_setting("vpn_openvpn_path", "openvpn")
    try:
        _server_process = subprocess.Popen(
            [exe_path, "--config", SERVER_CONF],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _server_status = "Running"
        database.save_ssl_vpn_config(status="Running")
        database.add_log("INFO", details="SSL VPN server started")
        _monitor_server()
        return True, f"SSL VPN started (PID {_server_process.pid})"
    except Exception as e:
        _server_status = "Error"
        return False, str(e)


def stop_server():
    global _server_process, _server_status
    if _server_process and _server_process.poll() is None:
        _server_process.terminate()
        try:
            _server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _server_process.kill()
        _server_process = None
    _server_status = "Stopped"
    database.save_ssl_vpn_config(status="Stopped")
    database.add_log("INFO", details="SSL VPN server stopped")
    return True, "Stopped"


def _monitor_server():
    def _watch():
        global _server_status
        if _server_process:
            _server_process.wait()
            _server_status = "Stopped"
            database.save_ssl_vpn_config(status="Stopped")
    threading.Thread(target=_watch, daemon=True).start()


def get_server_status():
    global _server_status
    if _server_process and _server_process.poll() is None:
        _server_status = "Running"
    elif _server_process and _server_process.poll() is not None:
        _server_status = "Stopped"
    return _server_status


# ── Push Route iptables helpers ───────────────────────────────────────────────

def _netmask_to_cidr(netmask: str) -> int:
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))


def _get_wan_if() -> str:
    """Detect WAN interface via default route."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=3
        )
        parts = result.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def apply_vpn_internet_nat():
    """Ensure VPN clients can reach the internet when redirect-gateway is active.
    Adds FORWARD + MASQUERADE rules for tun0 → WAN. Safe to call multiple times."""
    if not IS_LINUX:
        return
    wan_if = _get_wan_if()
    vpn_net = _vpn_cidr()
    # Remove first (idempotent), then re-add
    run(["iptables", "-D", "FORWARD", "-i", "tun0", "-o", wan_if, "-j", "ACCEPT"])
    run(["iptables", "-D", "FORWARD", "-i", wan_if, "-o", "tun0",
         "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", vpn_net, "-o", wan_if, "-j", "MASQUERADE"])
    run(["iptables", "-I", "FORWARD", "1", "-i", "tun0", "-o", wan_if, "-j", "ACCEPT"])
    run(["iptables", "-I", "FORWARD", "2", "-i", wan_if, "-o", "tun0",
         "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpn_net, "-o", wan_if, "-j", "MASQUERADE"])
    run(["netfilter-persistent", "save"])


def _get_lan_ip() -> str:
    try:
        conn = database.get_connection()
        row = conn.execute("SELECT ip_address FROM vlans WHERE vlan_id=10 LIMIT 1").fetchone()
        if not row:
            row = conn.execute("SELECT ip_address FROM interfaces WHERE role='LAN' LIMIT 1").fetchone()
        conn.close()
        if row and row["ip_address"]:
            return row["ip_address"].split("/")[0]
    except Exception:
        pass
    return "192.168.0.254"


def _vpn_cidr() -> str:
    cfg = database.get_ssl_vpn_config()
    subnet = cfg.get("server_subnet", "10.8.0.0")
    netmask = cfg.get("server_netmask", "255.255.255.0")
    return f"{subnet}/{_netmask_to_cidr(netmask)}"


def apply_push_route_rules(network: str, netmask: str):
    """Add iptables FORWARD + MASQUERADE rules for a new push route."""
    if not IS_LINUX:
        return
    cidr = f"{network}/{_netmask_to_cidr(netmask)}"
    vpn_net = _vpn_cidr()
    run(["iptables", "-I", "FORWARD", "-i", "tun0", "-d", cidr, "-j", "ACCEPT"])
    run(["iptables", "-I", "FORWARD", "-s", cidr, "-o", "tun0", "-j", "ACCEPT"])
    run(["iptables", "-t", "nat", "-I", "POSTROUTING",
         "-s", vpn_net, "-d", cidr, "-j", "MASQUERADE"])
    run(["netfilter-persistent", "save"])


def remove_push_route_rules(network: str, netmask: str):
    """Remove iptables FORWARD + MASQUERADE rules for a deleted push route."""
    if not IS_LINUX:
        return
    cidr = f"{network}/{_netmask_to_cidr(netmask)}"
    vpn_net = _vpn_cidr()
    run(["iptables", "-D", "FORWARD", "-i", "tun0", "-d", cidr, "-j", "ACCEPT"])
    run(["iptables", "-D", "FORWARD", "-s", cidr, "-o", "tun0", "-j", "ACCEPT"])
    run(["iptables", "-t", "nat", "-D", "POSTROUTING",
         "-s", vpn_net, "-d", cidr, "-j", "MASQUERADE"])
    run(["netfilter-persistent", "save"])


def refresh_server_conf():
    """Regenerate server.conf and copy to systemd service path (no restart)."""
    write_server_config()
    if IS_LINUX:
        try:
            os.makedirs("/etc/openvpn/server", exist_ok=True)
            shutil.copy2(SERVER_CONF, "/etc/openvpn/server/server.conf")
        except Exception:
            pass


def get_connected_clients():
    """Read OpenVPN status log for connected clients.
    Supports both status-version 2 (systemd service) and version 1 (direct start)."""
    candidates = [
        "/run/openvpn-server/status-server.log",  # openvpn-server@server.service
        "/var/log/aegisguard-ssl-vpn-status.log",  # FGUARD direct start
    ]
    status_file = next((p for p in candidates if os.path.isfile(p)), None)
    clients = []
    if not status_file:
        return clients
    try:
        with open(status_file) as f:
            content = f.read()

        # status-version 2: rows start with CLIENT_LIST,
        if "CLIENT_LIST," in content:
            for line in content.splitlines():
                if not line.startswith("CLIENT_LIST,"):
                    continue
                parts = line.split(",")
                # HEADER,CLIENT_LIST,... rows have "HEADER" prefix — skip
                if len(parts) < 8:
                    continue
                clients.append({
                    "username": parts[9] if len(parts) > 9 and parts[9] else parts[1],
                    "real_ip": parts[2],
                    "bytes_recv": parts[5],
                    "bytes_sent": parts[6],
                    "connected_since": parts[7],
                })
        else:
            # status-version 1 (legacy)
            in_client_list = False
            for line in content.splitlines():
                if "Common Name" in line and "Real Address" in line:
                    in_client_list = True
                    continue
                if "ROUTING TABLE" in line:
                    in_client_list = False
                if in_client_list and "," in line:
                    parts = line.split(",")
                    if len(parts) >= 4:
                        clients.append({
                            "username": parts[0],
                            "real_ip": parts[1],
                            "bytes_recv": parts[2],
                            "bytes_sent": parts[3],
                            "connected_since": parts[4] if len(parts) > 4 else "",
                        })
    except Exception:
        pass
    return clients


# ── Per-user client config generation ────────────────────────────────────────

def generate_user_config(vpn_user, server_ip="auto"):
    """Generate a .ovpn config for a specific VPN user."""
    cfg = database.get_ssl_vpn_config()
    if not cfg:
        return None, "SSL VPN not configured"

    if server_ip == "auto":
        # Use WAN IP from settings, fallback to detecting public IP
        server_ip = database.get_setting("wan_ip", "")
        if not server_ip:
            try:
                import urllib.request
                server_ip = urllib.request.urlopen(
                    "https://api.ipify.org", timeout=5
                ).read().decode().strip()
            except Exception:
                pass
        if not server_ip:
            # Fallback: use eth0 IP
            try:
                import subprocess
                result = subprocess.run(
                    ["hostname", "-I"], capture_output=True, text=True, timeout=3
                )
                ips = result.stdout.strip().split()
                server_ip = ips[0] if ips else "YOUR_SERVER_IP"
            except Exception:
                server_ip = "YOUR_SERVER_IP"

    port = cfg.get("port", 1194)
    proto = cfg.get("protocol", "udp")
    cipher = cfg.get("cipher", "AES-256-GCM")
    auth_alg = cfg.get("auth", "SHA256")

    def _block(tag, content):
        return f"<{tag}>\n{content.strip()}\n</{tag}>\n" if content else ""

    conf = f"""# FGUARD UTC SSL VPN - Client Config
# User: {vpn_user['username']}
# Server: {server_ip}:{port}
# Generated: {datetime.now().isoformat()}

client
dev tun
proto {proto}
remote {server_ip} {port}
resolv-retry infinite
nobind
persist-key
persist-tun

# Auth — enter username and password when prompted
auth-user-pass

# PKI (inline)
{_block('ca', cfg.get('ca_cert',''))}
{_block('tls-auth', cfg.get('ta_key',''))}
key-direction 1

# Security
cipher {cipher}
auth {auth_alg}
tls-version-min {cfg.get('tls_version','1.2')}
remote-cert-tls server

# Settings
{'compress lz4-v2' if cfg.get('compress',1) else ''}
verb 3
"""

    username = vpn_user["username"]
    os.makedirs(CONFIGS_DIR, exist_ok=True)
    config_path = os.path.join(CONFIGS_DIR, f"{username}.ovpn")

    try:
        with open(config_path, "w") as f:
            f.write(conf)
        database.update_vpn_user(vpn_user["id"], config_path=config_path)
        return config_path, conf
    except Exception as e:
        return None, str(e)


def get_user_config_content(user_id):
    """Get the .ovpn config content for a user."""
    conn = database.get_connection()
    row = conn.execute("SELECT * FROM vpn_users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return None
    user = dict(row)
    if user.get("config_path") and os.path.isfile(user["config_path"]):
        with open(user["config_path"]) as f:
            return f.read()
    _, content = generate_user_config(user)
    return content


# ── Setup wizard ──────────────────────────────────────────────────────────────

def quick_setup(port=1194, proto="udp", server_subnet="10.8.0.0", dns1="1.1.1.1"):
    """One-call setup: init PKI + write config + ready to start."""
    database.save_ssl_vpn_config(
        port=port, protocol=proto,
        server_subnet=server_subnet, dns1=dns1,
        status="Initializing"
    )
    ok, msg = initialize_pki()
    if ok:
        write_server_config()
        database.save_ssl_vpn_config(status="Ready - Not Started")
    return ok, msg
