"""SSL VPN (Mobile VPN with SSL) - OpenVPN server management.
Auto-generates PKI, manages users, generates per-user .ovpn configs."""
import os
import re
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


def initialize_pki(server_name="fguard-ssl", progress_cb=None):
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

    conf = f"""# FGUARD SSL VPN Server
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
auth-user-pass-verify /etc/fguard/vpn-auth.sh via-file
username-as-common-name
verify-client-cert optional

# Settings
keepalive 10 120
max-clients 100
persist-key
persist-tun
user nobody
group nogroup
status /var/log/fguard-ssl-vpn-status.log 5
status-version 2
log-append /var/log/fguard-ssl-vpn.log
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
# FGUARD SSL VPN auth script
# Called by OpenVPN via-file: $1 = temp file with username/password

/usr/bin/python3 /etc/fguard/vpn_auth_check.py "$1"
"""
    auth_script = "/etc/fguard/vpn-auth.sh"
    auth_check = "/etc/fguard/vpn_auth_check.py"

    source = os.path.join(BASE_DIR, "build", "server-configs", "vpn_auth_check.py")
    try:
        with open(source, encoding="utf-8") as handle:
            auth_check_code = handle.read()
    except Exception:
        auth_check_code = ""
    if "mode=ro" not in auth_check_code:
        return False, "Auth check source is missing"
    try:
        os.makedirs("/etc/fguard", exist_ok=True)
        with open(auth_script, "w") as f:
            f.write(script)
        with open(auth_check, "w") as f:
            f.write(auth_check_code)
        _chmod_vpn_db_readable()
        os.chmod(auth_script, 0o755)
        os.chmod(auth_check, 0o755)
        os.chmod("/etc/fguard", 0o755)
        if os.path.isdir("/etc/aegisguard"):
            for src, name in ((auth_script, "vpn-auth.sh"), (auth_check, "vpn_auth_check.py")):
                dst = os.path.join("/etc/aegisguard", name)
                try:
                    shutil.copy2(src, dst)
                    os.chmod(dst, 0o755)
                except Exception:
                    pass
        return True, "Auth scripts written"
    except Exception as e:
        return False, str(e)


# ── Server Control ────────────────────────────────────────────────────────────

def _kill_orphan_openvpn():
    """Kill any direct-launched openvpn process (not managed by systemd)."""
    try:
        subprocess.run(["pkill", "-f", "ssl-vpn-server.conf"], capture_output=True)
    except Exception:
        pass


def start_server():
    global _server_process, _server_status

    if IS_LINUX and is_pki_initialized():
        try:
            ensure_server_eku()
        except Exception:
            pass

    ok, msg = write_server_config()
    if not ok:
        return False, msg

    if IS_LINUX:
        write_auth_script()
        apply_vpn_internet_nat()
        _kill_orphan_openvpn()
        try:
            subprocess.run(
                ["systemctl", "enable", "--now", "openvpn-server@server"],
                timeout=15, check=True, capture_output=True
            )
            _server_status = "Running"
            database.save_ssl_vpn_config(status="Running")
            database.add_log("INFO", details="SSL VPN server started")
            return True, "SSL VPN started (systemd)"
        except Exception as e:
            _server_status = "Error"
            return False, str(e)

    # Non-Linux (dev/Windows)
    if _server_process and _server_process.poll() is None:
        return False, "Already running"
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

    if IS_LINUX:
        try:
            subprocess.run(
                ["systemctl", "stop", "openvpn-server@server"],
                timeout=15, capture_output=True
            )
        except Exception:
            pass
        _kill_orphan_openvpn()
    else:
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
    if IS_LINUX:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "openvpn-server@server"],
                capture_output=True, text=True, timeout=3
            )
            _server_status = "Running" if result.stdout.strip() == "active" else "Stopped"
        except Exception:
            pass
    else:
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
    try:
        from core.bov_manager import pin_ipsec_nat_rules
        pin_ipsec_nat_rules()
    except Exception:
        pass
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
    """Add iptables FORWARD + NAT rules for a new push route.

    IPsec peer LANs must SNAT to the local LAN IP (not MASQUERADE to WAN)
    or xfrm selectors will not match.
    """
    if not IS_LINUX:
        return
    cidr = f"{network}/{_netmask_to_cidr(netmask)}"
    vpn_net = _vpn_cidr()
    run(["iptables", "-I", "FORWARD", "-i", "tun0", "-d", cidr, "-j", "ACCEPT"])
    run(["iptables", "-I", "FORWARD", "-s", cidr, "-o", "tun0", "-j", "ACCEPT"])
    ipsec_peer = False
    try:
        for t in database.get_bov_tunnels():
            if t.get("enabled", 1) and (t.get("remote_subnets") or "").strip() == cidr:
                ipsec_peer = True
                break
    except Exception:
        ipsec_peer = False
    if not ipsec_peer:
        run(["iptables", "-t", "nat", "-I", "POSTROUTING",
             "-s", vpn_net, "-d", cidr, "-j", "MASQUERADE"])
    try:
        from core.bov_manager import pin_ipsec_nat_rules
        pin_ipsec_nat_rules()
    except Exception:
        pass
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
    lan_ip = _get_lan_ip()
    if lan_ip:
        run(["iptables", "-t", "nat", "-D", "POSTROUTING",
             "-s", vpn_net, "-d", cidr, "-j", "SNAT", "--to-source", lan_ip])
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


def _host_only(addr):
    """Drop the UDP/TCP port OpenVPN appends to a client address."""
    addr = (addr or "").strip()
    if addr.startswith("["):
        end = addr.find("]")
        if end > 1:
            return addr[1:end]
    if addr.count(":") == 1:
        host, port = addr.rsplit(":", 1)
        if port.isdigit():
            return host
    return addr


def _client_row(username, real_ip, virtual_ip="", bytes_recv="", bytes_sent="", connected_since=""):
    return {
        "username": username or "",
        "real_ip": _host_only(real_ip),
        "virtual_ip": virtual_ip or "",
        "bytes_recv": bytes_recv or "",
        "bytes_sent": bytes_sent or "",
        "connected_since": connected_since or "",
    }


def _status_candidate_paths():
    paths = [
        "/run/openvpn-server/status-server.log",
        "/run/openvpn/status-server.log",
        "/var/log/fguard-ssl-vpn-status.log",
        "/var/log/aegisguard-ssl-vpn-status.log",
    ]
    for conf in (SYSTEMD_CONF, SERVER_CONF):
        try:
            with open(conf, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.split()
                    if parts and parts[0] == "status" and len(parts) > 1:
                        paths.append(parts[1])
        except Exception:
            continue
    seen = set()
    unique = []
    for path in paths:
        if path and path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def _parse_status_text(content):
    """Parse an OpenVPN status file. Version 2/3 is header-driven; version 1 is the old table."""
    clients = []
    header = None
    for line in content.splitlines():
        if line.startswith("HEADER,CLIENT_LIST,"):
            header = line.split(",")[2:]
            continue
        if not line.startswith("CLIENT_LIST,"):
            continue
        values = line.split(",")[1:]
        if header and len(values) >= len(header):
            row = dict(zip(header, values))
        elif len(values) >= 7:
            # OpenVPN 2.4 status-version 2 has no virtual IPv6 column.
            row = {
                "Common Name": values[0],
                "Real Address": values[1],
                "Virtual Address": values[2],
                "Bytes Received": values[3],
                "Bytes Sent": values[4],
                "Connected Since": values[5],
                "Username": values[7] if len(values) > 7 else values[0],
            }
        else:
            continue
        username = row.get("Username") or row.get("Common Name") or ""
        clients.append(_client_row(
            username,
            row.get("Real Address", ""),
            row.get("Virtual Address", ""),
            row.get("Bytes Received", ""),
            row.get("Bytes Sent", ""),
            row.get("Connected Since", ""),
        ))
    if clients or "CLIENT_LIST," in content:
        return clients

    in_clients = False
    in_routes = False
    routes = {}
    for line in content.splitlines():
        if "ROUTING TABLE" in line or line.startswith("Virtual Address,Common Name"):
            in_clients = False
            in_routes = "Virtual Address" in line or False
            if "ROUTING TABLE" in line and "Virtual Address" not in line:
                in_routes = False
            continue
        if "Common Name" in line and "Real Address" in line and "CLIENT_LIST" not in line:
            in_clients = True
            in_routes = False
            continue
        if in_routes and "," in line:
            parts = line.split(",")
            if len(parts) >= 2:
                routes[parts[1]] = parts[0]
            continue
        if in_clients and "," in line:
            parts = line.split(",")
            if len(parts) >= 4 and not parts[0].startswith("HEADER"):
                clients.append(_client_row(
                    parts[0], parts[1], routes.get(parts[0], ""),
                    parts[2], parts[3], parts[4] if len(parts) > 4 else "",
                ))
    for client in clients:
        if not client["virtual_ip"]:
            client["virtual_ip"] = routes.get(client["username"], "")
    return clients


def _read_tail(path, limit=2_000_000):
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - limit))
        data = handle.read().decode("utf-8", "replace")
    if size > limit:
        cut = data.find("\n")
        if cut >= 0:
            data = data[cut + 1:]
    return data


_LOG_INIT = re.compile(
    r'(udp4|tcp4|udp6|tcp6):([^:\s]+):(\d+) \[([^\]]+)\] Peer Connection Initiated'
)
_LOG_VIP = re.compile(
    r'primary virtual IP for ([^/\s]+)/(udp4|tcp4|udp6|tcp6):([^:\s]+):(\d+): ([0-9a-fA-F.:]+)'
)
_LOG_DEAD = re.compile(
    r'^([^/\s]+)/(udp4|tcp4|udp6|tcp6):([^:\s]+):(\d+)\s+.*'
    r'(SIGTERM|SIGUSR1|client-instance exiting|client-instance restarting|'
    r'Connection reset|Inactivity timeout|Delayed exit|CC-EEN exit)'
)


_LOG_POOL = re.compile(
    r'^([^/\s]+)/(udp4|tcp4|udp6|tcp6):([^:\s]+):(\d+)\s+'
    r'MULTI_sva: pool returned IPv4=([0-9.]+)'
)


def _release_virtual_ip(live, virtual, keep):
    """OpenVPN gives a tunnel address to one client. A later assignment means the previous session is gone."""
    if not virtual:
        return
    for key, row in list(live.items()):
        if key != keep and row.get("virtual_ip") == virtual:
            del live[key]


def _parse_openvpn_log(content):
    """Sessions still up, from the OpenVPN log. The log is written immediately; the status file is not."""
    live = {}
    for line in content.splitlines():
        dead = _LOG_DEAD.search(line)
        if dead:
            live.pop(dead.group(1, 2, 3, 4), None)
            continue
        started = _LOG_INIT.search(line)
        if started:
            proto, ip, port, username = started.groups()
            live[(username, proto, ip, port)] = _client_row(username, ip)
            continue
        pool = _LOG_POOL.search(line)
        if pool:
            username, proto, ip, port, virtual = pool.groups()
            key = (username, proto, ip, port)
            row = live.get(key) or _client_row(username, ip)
            row["virtual_ip"] = virtual
            live[key] = row
            _release_virtual_ip(live, virtual, key)
            continue
        vip = _LOG_VIP.search(line)
        if vip:
            username, proto, ip, port, virtual = vip.groups()
            key = (username, proto, ip, port)
            row = live.get(key) or _client_row(username, ip)
            row["virtual_ip"] = virtual
            live[key] = row
            _release_virtual_ip(live, virtual, key)
    return list(live.values())


def _log_candidate_paths():
    paths = [
        "/var/log/fguard-ssl-vpn.log",
        "/var/log/aegisguard-ssl-vpn.log",
    ]
    for conf in (SYSTEMD_CONF, SERVER_CONF):
        try:
            with open(conf, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.split()
                    if parts and parts[0] in ("log-append", "log") and len(parts) > 1:
                        paths.append(parts[1])
        except Exception:
            continue
    seen = set()
    unique = []
    for path in paths:
        if path and path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def _merge_clients(status_rows, log_rows):
    used = set()
    merged = []
    for log_row in log_rows:
        match = None
        for index, status_row in enumerate(status_rows):
            if index in used:
                continue
            if (status_row["username"] == log_row["username"]
                    and status_row["real_ip"] == log_row["real_ip"]):
                match = index
                break
        if match is None:
            merged.append(log_row)
            continue
        used.add(match)
        status_row = status_rows[match]
        merged.append(_client_row(
            status_row["username"] or log_row["username"],
            status_row["real_ip"] or log_row["real_ip"],
            status_row["virtual_ip"] or log_row["virtual_ip"],
            status_row["bytes_recv"],
            status_row["bytes_sent"],
            status_row["connected_since"],
        ))
    for index, status_row in enumerate(status_rows):
        if index not in used:
            merged.append(status_row)
    return merged


def get_connected_clients():
    """Connected SSL VPN clients. Reads the status file OpenVPN already writes
    and, for a session not flushed there yet, the server log. Does not signal
    or restart OpenVPN."""
    status_rows = []
    status_mtime = -1
    for path in _status_candidate_paths():
        if not os.path.isfile(path):
            continue
        try:
            modified = os.stat(path).st_mtime
        except Exception:
            continue
        if modified < status_mtime:
            continue
        try:
            parsed = _parse_status_text(_read_tail(path))
        except Exception:
            continue
        status_rows = parsed
        status_mtime = modified
    newest_log = None
    log_mtime = -1
    for path in _log_candidate_paths():
        if not os.path.isfile(path):
            continue
        try:
            modified = os.stat(path).st_mtime
        except Exception:
            continue
        if modified >= log_mtime:
            newest_log = path
            log_mtime = modified
    # The status file is rewritten on a timer. A newer log means a session
    # changed after that rewrite, so fold those sessions in. An older log
    # must not bring back clients the status file has already dropped.
    if not newest_log or log_mtime <= status_mtime:
        return status_rows
    try:
        log_rows = _parse_openvpn_log(_read_tail(newest_log))
    except Exception:
        return status_rows
    return _merge_clients(status_rows, log_rows)


# ── Per-user client config generation ────────────────────────────────────────

def build_client_ovpn(username, server_ip="auto"):
    """Client profile text. Does not write a file or change the user row."""
    cfg = database.get_ssl_vpn_config()
    if not cfg:
        return None, "SSL VPN not configured"

    if not server_ip or server_ip == "auto":
        server_ip = database.get_setting("wan_ip", "") or database.get_setting("openvpn_public_ip", "")
        if not server_ip:
            try:
                import urllib.request
                server_ip = urllib.request.urlopen(
                    "https://api.ipify.org", timeout=5
                ).read().decode().strip()
            except Exception:
                pass
        if not server_ip:
            try:
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

    conf = f"""# FGUARD SSL VPN - Client Config
# User: {username}
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
verb 3
"""
    return conf, None


def generate_user_config(vpn_user, server_ip="auto"):
    """Generate a .ovpn config for a specific VPN user."""
    conf, err = build_client_ovpn(vpn_user["username"], server_ip)
    if conf is None:
        return None, err

    username = vpn_user["username"]
    os.makedirs(CONFIGS_DIR, exist_ok=True)
    config_path = os.path.join(CONFIGS_DIR, f"{username}.ovpn")

    try:
        with open(config_path, "w") as f:
            f.write(conf)
        if vpn_user.get("id"):
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
            return _without_compress_push(f.read())
    _, content = generate_user_config(user)
    return _without_compress_push(content)


def _without_compress_push(content):
    """Drop compress lines from a profile. OpenVPN 2.6 rejects a compress push."""
    if not content:
        return content
    skip = {"compress lz4-v2", "compress lz4", 'push "compress lz4-v2"'}
    lines = [line for line in content.splitlines() if line.strip() not in skip]
    return "\n".join(lines) + "\n"


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


def _vpn_db_paths():
    paths = []
    try:
        from db.database import DB_PATH
        paths.append(DB_PATH)
    except Exception:
        pass
    paths.extend(["/opt/fguard/firewall.db", "/opt/aegisguard/firewall.db"])
    unique = []
    for path in paths:
        if path and path not in unique:
            unique.append(path)
    return unique


def _chmod_vpn_db_readable():
    """Let the nobody user read the database. Do not grant write."""
    for path in _vpn_db_paths():
        if not os.path.isfile(path):
            continue
        try:
            os.chmod(path, os.stat(path).st_mode | 0o444)
        except Exception:
            pass


def _read_text(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except Exception:
        return None


def _config_body(text):
    if not text:
        return ""
    lines = [
        line for line in text.splitlines()
        if not line.startswith("# Generated:")
    ]
    return "\n".join(lines).strip()


def _openvpn_state(command):
    try:
        result = subprocess.run(
            ["systemctl", command, "openvpn-server@server"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def ensure_server_eku():
    """Add serverAuth to the current server certificate. Same key, same CA."""
    from core.vpn_keygen import resign_server_certificate

    cert_path = os.path.join(PKI_DIR, "server.crt")
    key_path = os.path.join(PKI_DIR, "server.key")
    ca_path = os.path.join(PKI_DIR, "ca.crt")
    ca_key = os.path.join(PKI_DIR, "ca.key")
    if not all(os.path.isfile(path) for path in (cert_path, key_path, ca_path, ca_key)):
        return False, "PKI files missing"
    ok, message = resign_server_certificate(ca_path, ca_key, key_path, cert_path)
    if not ok:
        return False, message
    with open(cert_path, encoding="utf-8") as handle:
        pem = handle.read()
    cfg = database.get_ssl_vpn_config() or {}
    if (cfg.get("server_cert") or "").strip() != pem.strip():
        database.save_ssl_vpn_config(server_cert=pem)
    return True, message


def _snapshot_openvpn():
    cert_path = os.path.join(PKI_DIR, "server.crt")
    cfg = database.get_ssl_vpn_config() or {}
    cert_bytes = None
    try:
        with open(cert_path, "rb") as handle:
            cert_bytes = handle.read()
    except Exception:
        pass
    return {
        "active": _openvpn_state("is-active") == "active",
        "enabled": _openvpn_state("is-enabled") == "enabled",
        "cert_file": cert_bytes,
        "db_cert": cfg.get("server_cert") or "",
        "systemd": _read_text(SYSTEMD_CONF),
        "local": _read_text(SERVER_CONF),
    }


def _restore_openvpn(snapshot):
    cert_path = os.path.join(PKI_DIR, "server.crt")
    if snapshot.get("cert_file") is not None:
        with open(cert_path, "wb") as handle:
            handle.write(snapshot["cert_file"])
    if snapshot.get("db_cert"):
        database.save_ssl_vpn_config(server_cert=snapshot["db_cert"])
    if snapshot.get("local") is not None:
        with open(SERVER_CONF, "w", encoding="utf-8") as handle:
            handle.write(snapshot["local"])
    if snapshot.get("systemd") is not None:
        os.makedirs(os.path.dirname(SYSTEMD_CONF), exist_ok=True)
        with open(SYSTEMD_CONF, "w", encoding="utf-8") as handle:
            handle.write(snapshot["systemd"])


def _restart_openvpn():
    try:
        subprocess.run(
            ["systemctl", "restart", "openvpn-server@server"],
            timeout=20, check=False, capture_output=True,
        )
    except Exception:
        return False
    return _openvpn_state("is-active") == "active"


def apply_persistent_fix():
    """Put the SSL VPN fix on disk so a hard reboot keeps it.

    DNS, nginx, DHCP, WireGuard and IPsec are not restarted. OpenVPN is
    restarted only when its config actually changed and it was already
    running. If that restart does not come back, the previous certificate
    and config are restored and OpenVPN is started again.
    """
    if not IS_LINUX:
        return True, "Not Linux"

    auth_ok, auth_msg = write_auth_script()
    try:
        from core.geoblock import patch_vpn_boot_script
        patch_vpn_boot_script()
    except Exception:
        pass
    if not is_pki_initialized():
        if not auth_ok:
            return False, auth_msg
        return True, "Auth script updated. PKI not initialized."

    snapshot = _snapshot_openvpn()
    ok, message = ensure_server_eku()
    if not ok:
        _restore_openvpn(snapshot)
        return False, message

    ok, message = write_server_config()
    if not ok:
        _restore_openvpn(snapshot)
        return False, message

    wants_boot = snapshot["active"] or snapshot["enabled"] or (
        (database.get_ssl_vpn_config() or {}).get("status") == "Running"
    )
    if wants_boot:
        try:
            subprocess.run(
                ["systemctl", "enable", "openvpn-server@server"],
                timeout=15, check=False, capture_output=True,
            )
        except Exception:
            pass

    changed = _config_body(snapshot["systemd"]) != _config_body(_read_text(SYSTEMD_CONF))
    # A stopped OpenVPN stays stopped. Reboot brings it back only when the
    # unit is enabled or the database still says it should be running.
    if snapshot["active"] and changed:
        if not _restart_openvpn():
            _restore_openvpn(snapshot)
            _restart_openvpn()
            return False, "OpenVPN kept the previous config because the new one did not start"
        return True, "OpenVPN reloaded with the updated certificate and config"

    if not auth_ok:
        return False, auth_msg
    return True, "SSL VPN files saved for the next boot"
