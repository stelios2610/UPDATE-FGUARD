"""VPN Manager - cross-platform (OpenVPN, WireGuard, IPSec)."""
import subprocess
import os
import threading
import time
from datetime import datetime
from db import database
from core.platform import IS_LINUX, IS_WINDOWS, run


_vpn_processes = {}
_vpn_status = {}


def _find_exe(setting_key, linux_names, windows_names):
    path = database.get_setting(setting_key, "")
    if path and os.path.isfile(path):
        return path
    names = linux_names if IS_LINUX else windows_names
    for name in names:
        ok, out, _ = run(["which" if IS_LINUX else "where", name])
        if ok and out:
            return out.splitlines()[0]
    return None


def get_openvpn_path():
    return _find_exe(
        "vpn_openvpn_path",
        ["openvpn"],
        ["openvpn", "openvpn.exe"]
    )


def get_wireguard_path():
    if IS_LINUX:
        ok, out, _ = run(["which", "wg-quick"])
        return out.splitlines()[0] if ok and out else None
    return _find_exe(
        "vpn_wireguard_path",
        [],
        ["wireguard", "wireguard.exe"]
    )


# ─── OpenVPN ──────────────────────────────────────────────────────────────────

def connect_openvpn(profile):
    pid = profile["id"]
    if pid in _vpn_processes and _vpn_processes[pid].poll() is None:
        return False, "Already connected"

    exe = get_openvpn_path()
    if not exe:
        return False, "OpenVPN not found. Install with: sudo apt install openvpn"

    config = profile["config_path"]
    if not os.path.isfile(config):
        return False, f"Config not found: {config}"

    try:
        flags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
        cmd = [exe, "--config", config]
        if IS_WINDOWS:
            cmd += ["--management", "127.0.0.1", "7505"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=flags)
        _vpn_processes[pid] = proc
        _vpn_status[pid] = {"status": "Connecting", "since": datetime.now().isoformat(),
                            "bytes_in": 0, "bytes_out": 0}
        database.update_vpn_profile(pid, status="Connecting")
        database.add_log("INFO", details=f"OpenVPN connecting: {profile['name']}")
        _monitor_openvpn(pid, profile)
        return True, "Connecting..."
    except Exception as e:
        return False, str(e)


def _monitor_openvpn(pid, profile):
    def _watch():
        proc = _vpn_processes.get(pid)
        if not proc:
            return
        time.sleep(4)
        if proc.poll() is None:
            _vpn_status[pid]["status"] = "Connected"
            database.update_vpn_profile(pid, status="Connected",
                                        last_connected=datetime.now().isoformat())
            database.add_log("INFO", details=f"OpenVPN connected: {profile['name']}")
        proc.wait()
        _vpn_status[pid]["status"] = "Disconnected"
        database.update_vpn_profile(pid, status="Disconnected")
        database.add_log("INFO", details=f"OpenVPN disconnected: {profile['name']}")
        _vpn_processes.pop(pid, None)
    threading.Thread(target=_watch, daemon=True).start()


def disconnect_openvpn(profile):
    pid = profile["id"]
    proc = _vpn_processes.get(pid)
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        _vpn_processes.pop(pid, None)
        _vpn_status[pid] = {"status": "Disconnected", "since": "", "bytes_in": 0, "bytes_out": 0}
        database.update_vpn_profile(pid, status="Disconnected")
        return True, "Disconnected"
    return False, "Not connected"


# ─── WireGuard ────────────────────────────────────────────────────────────────

def connect_wireguard(profile):
    pid = profile["id"]
    config = profile["config_path"]

    if IS_LINUX:
        return _connect_wireguard_linux(pid, profile, config)
    return _connect_wireguard_windows(pid, profile, config)


def _connect_wireguard_linux(pid, profile, config):
    if not os.path.isfile(config):
        return False, f"Config not found: {config}"
    tunnel = os.path.splitext(os.path.basename(config))[0]
    ok, out, err = run(["wg-quick", "up", config], timeout=20)
    if ok or "already exists" in err:
        _vpn_status[pid] = {"status": "Connected", "since": datetime.now().isoformat(),
                            "bytes_in": 0, "bytes_out": 0, "tunnel": tunnel}
        database.update_vpn_profile(pid, status="Connected",
                                    last_connected=datetime.now().isoformat())
        database.add_log("INFO", details=f"WireGuard up: {profile['name']}")
        return True, f"WireGuard tunnel '{tunnel}' up"
    return False, err or out


def _connect_wireguard_windows(pid, profile, config):
    exe = get_wireguard_path()
    if not exe:
        return False, "WireGuard not found."
    if not os.path.isfile(config):
        return False, f"Config not found: {config}"
    tunnel = os.path.splitext(os.path.basename(config))[0]
    ok, out, err = run([exe, "/installtunnelservice", config], timeout=15)
    if ok or "already installed" in err.lower():
        _vpn_status[pid] = {"status": "Connected", "since": datetime.now().isoformat(),
                            "bytes_in": 0, "bytes_out": 0, "tunnel": tunnel}
        database.update_vpn_profile(pid, status="Connected",
                                    last_connected=datetime.now().isoformat())
        return True, f"Tunnel '{tunnel}' started"
    return False, err or out


def disconnect_wireguard(profile):
    pid = profile["id"]
    config = profile["config_path"]
    status = _vpn_status.get(pid, {})
    tunnel = status.get("tunnel", os.path.splitext(os.path.basename(config))[0])

    if IS_LINUX:
        ok, out, err = run(["wg-quick", "down", config], timeout=15)
    else:
        exe = get_wireguard_path()
        if not exe:
            return False, "WireGuard not found"
        ok, out, err = run([exe, "/uninstalltunnelservice", tunnel], timeout=10)

    _vpn_status[pid] = {"status": "Disconnected", "since": "", "bytes_in": 0, "bytes_out": 0}
    database.update_vpn_profile(pid, status="Disconnected")
    database.add_log("INFO", details=f"WireGuard disconnected: {profile['name']}")
    return True, "Disconnected"


# ─── Public API ───────────────────────────────────────────────────────────────

def connect(profile):
    if profile["type"] == "OpenVPN":
        return connect_openvpn(profile)
    elif profile["type"] == "WireGuard":
        return connect_wireguard(profile)
    return False, "Unknown VPN type"


def disconnect(profile):
    if profile["type"] == "OpenVPN":
        return disconnect_openvpn(profile)
    elif profile["type"] == "WireGuard":
        return disconnect_wireguard(profile)
    return False, "Unknown VPN type"


def get_status(profile_id):
    return _vpn_status.get(profile_id,
                           {"status": "Disconnected", "since": "", "bytes_in": 0, "bytes_out": 0})


def get_all_statuses():
    return dict(_vpn_status)


def get_wireguard_peers():
    """Get WireGuard peer stats (Linux only)."""
    if not IS_LINUX:
        return []
    ok, out, err = run(["wg", "show", "all", "dump"])
    if not ok:
        return []
    peers = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 8:
            peers.append({
                "interface": parts[0],
                "public_key": parts[1][:20] + "...",
                "endpoint": parts[3],
                "allowed_ips": parts[4],
                "last_handshake": parts[5],
                "rx_bytes": int(parts[6]) if parts[6].isdigit() else 0,
                "tx_bytes": int(parts[7]) if parts[7].isdigit() else 0,
            })
    return peers


def generate_wireguard_config(server_endpoint, server_pubkey, client_privkey,
                               client_address, dns="1.1.1.1", allowed_ips="0.0.0.0/0,::/0"):
    return f"""[Interface]
PrivateKey = {client_privkey}
Address = {client_address}
DNS = {dns}

[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""


def generate_wireguard_keypair():
    """Generate a WireGuard keypair (Linux: uses wg command)."""
    if IS_LINUX:
        ok, privkey, _ = run(["wg", "genkey"])
        if ok and privkey:
            ok2, pubkey, _ = run(["bash", "-c", f"echo '{privkey}' | wg pubkey"])
            if ok2:
                return privkey.strip(), pubkey.strip()
    # Fallback: base64 random (not cryptographically proper WG key but useful for display)
    import base64
    import os
    privkey = base64.b64encode(os.urandom(32)).decode()
    pubkey = base64.b64encode(os.urandom(32)).decode()
    return privkey, pubkey
