"""High Availability Manager — VRRP via keepalived + config sync.

Architecture:
  - Two FGUARD nodes: MASTER (priority 100) and BACKUP (priority 90)
  - keepalived manages VRRP: Virtual IP floats to active MASTER
  - On failover, BACKUP becomes MASTER and takes the Virtual IP
  - Config sync: MASTER periodically rsyncs its config/DB to BACKUP
"""
import os
import base64
import ipaddress
import subprocess
import threading
import time
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

KEEPALIVED_CONF = "/etc/keepalived/keepalived.conf"
KEEPALIVED_D    = "/etc/keepalived/keepalived.d"
NOTIFY_SCRIPT   = "/etc/keepalived/fguard-notify.sh"
KNOWN_HOSTS     = "/etc/fguard/ha_known_hosts"
HOST_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}
DEFAULT_VRRP_PASSWORD = "AegisHA"


# ═══════════════════════════════════════════════════════════════════════════════
# keepalived config generation
# ═══════════════════════════════════════════════════════════════════════════════

def write_keepalived_config():
    """Generate /etc/keepalived/keepalived.conf from DB settings."""
    cfg = database.get_ha_config()
    if not cfg or not cfg.get("enabled"):
        return False, "HA not enabled"

    role        = cfg.get("role", "MASTER")
    iface       = cfg.get("interface", "eth1")
    vip         = cfg.get("virtual_ip", "")
    vip_mask    = cfg.get("virtual_ip_mask", 24)
    router_id   = cfg.get("router_id", 51)
    priority    = cfg.get("priority", 100)
    advert      = cfg.get("advert_interval", 1)
    auth_pass   = (cfg.get("auth_pass") or "").strip()
    preempt     = "preempt" if cfg.get("preempt", 1) else "nopreempt"

    if not vip:
        return False, "Virtual IP is required"
    if not auth_pass or auth_pass == DEFAULT_VRRP_PASSWORD:
        return False, "Set a VRRP auth password on both nodes before starting HA"

    os.makedirs("/etc/keepalived", exist_ok=True)
    _write_notify_script()

    conf = f"""# FGUARD HA — keepalived config
# Generated: {datetime.now().isoformat()}
# Role: {role}

global_defs {{
    router_id FGUARD_{role}
    script_user root
    enable_script_security
}}

vrrp_script chk_fguard {{
    script "/usr/bin/systemctl is-active fguard"
    interval 2
    weight -20
    fall 2
    rise 2
}}

vrrp_instance AEGIS_HA {{
    state {role}
    interface {iface}
    virtual_router_id {router_id}
    priority {priority}
    advert_int {advert}
    {preempt}

    authentication {{
        auth_type PASS
        auth_pass {auth_pass[:8]}
    }}

    virtual_ipaddress {{
        {vip}/{vip_mask}
    }}

    track_script {{
        chk_fguard
    }}

    notify "{NOTIFY_SCRIPT}"
}}
"""

    try:
        with open(KEEPALIVED_CONF, "w") as f:
            f.write(conf)
        return True, KEEPALIVED_CONF
    except Exception as e:
        return False, str(e)


def _write_notify_script():
    """Write the VRRP state-change notification script."""
    script = """#!/bin/bash
# FGUARD VRRP notify script
# Called by keepalived on state change
# Args: $1=instance $2=state $3=priority

TYPE=$1
NAME=$2
STATE=$3

logger -t fguard-ha "VRRP transition: $NAME -> $STATE"

case "$STATE" in
    MASTER)
        # We became master — ensure firewall is running
        systemctl start fguard 2>/dev/null
        systemctl start dnsmasq 2>/dev/null
        # Re-apply NAT masquerade
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
        python3 -c "
import sys; sys.path.insert(0,'/opt/fguard')
from db import database
from core.bov_manager import pin_ipsec_nat_rules
pin_ipsec_nat_rules()
database.add_log('WARN', details='HA: became MASTER')
" 2>/dev/null
        ;;
    BACKUP)
        python3 -c "
import sys; sys.path.insert(0,'/opt/fguard')
from db import database
database.add_log('INFO', details='HA: became BACKUP')
" 2>/dev/null
        ;;
    FAULT)
        python3 -c "
import sys; sys.path.insert(0,'/opt/fguard')
from db import database
database.add_log('WARN', details='HA: entered FAULT state')
" 2>/dev/null
        ;;
esac
"""
    try:
        with open(NOTIFY_SCRIPT, "w") as f:
            f.write(script)
        os.chmod(NOTIFY_SCRIPT, 0o755)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# keepalived service control
# ═══════════════════════════════════════════════════════════════════════════════

def apply_ha():
    """Write config and reload keepalived (auto-installs if missing)."""
    if not IS_LINUX:
        return False, "HA requires Linux"

    ok, msg = write_keepalived_config()
    if not ok:
        return False, msg

    # Auto-install keepalived if not present
    ok2, _, _ = run(["which", "keepalived"])
    if not ok2:
        database.add_log("INFO", details="HA: installing keepalived...")
        ok_inst, _, err_inst = run(["apt-get", "install", "-y", "keepalived"], timeout=120)
        if not ok_inst:
            return False, f"Failed to install keepalived: {err_inst}"

    run(["systemctl", "enable", "keepalived"])
    ok3, out, err = run(["systemctl", "restart", "keepalived"])
    if ok3:
        database.add_log("INFO", details="HA keepalived started/reloaded")
        _start_session_sync(database.get_ha_config())
        return True, "keepalived restarted"
    return False, err or out


def _start_session_sync(cfg):
    """Keep existing connections across failover. A missing daemon leaves VRRP running."""
    try:
        from core.session_sync import install_session_sync
        from core.platform import run as platform_run
        iface = cfg.get("interface") or "eth1"
        peer = (cfg.get("peer_ip") or cfg.get("sync_peer") or "").strip()
        ok, out, _ = platform_run(["ip", "-4", "-o", "addr", "show", "dev", iface])
        local_ip = ""
        if ok and out:
            local_ip = out.split()[3].split("/")[0]
        sync_ok, sync_msg = install_session_sync(local_ip, peer, iface)
        database.add_log("INFO" if sync_ok else "WARN", details="HA session sync: " + sync_msg)
    except Exception as exc:
        database.add_log("WARN", details="HA session sync: " + str(exc))


def stop_ha():
    """Stop keepalived (removes Virtual IP from this node)."""
    run(["systemctl", "stop", "keepalived"])
    database.add_log("WARN", details="HA keepalived stopped")
    return True, "keepalived stopped"


def get_ha_status():
    """Return current HA/VRRP status."""
    status = {
        "keepalived_active": False,
        "current_role": "unknown",
        "virtual_ip_held": False,
        "peer_reachable": False,
        "peer_latency_ms": 0,
    }

    if not IS_LINUX:
        return status

    ok, out, _ = run(["systemctl", "is-active", "keepalived"])
    status["keepalived_active"] = ok and out.strip() == "active"

    # Check if we hold the VIP
    cfg = database.get_ha_config()
    vip = cfg.get("virtual_ip", "")
    if vip:
        ok2, out2, _ = run(["ip", "addr", "show"])
        status["virtual_ip_held"] = vip in out2

    # Detect current role from keepalived state
    ok3, state_out, _ = run(["bash", "-c",
        "journalctl -u keepalived -n 20 --no-pager 2>/dev/null | grep -oE 'MASTER|BACKUP|FAULT' | tail -1"])
    if ok3 and state_out.strip():
        status["current_role"] = state_out.strip()
    elif status["virtual_ip_held"]:
        status["current_role"] = "MASTER"
    else:
        status["current_role"] = cfg.get("role", "unknown")

    # Ping peer
    peer = cfg.get("peer_ip", "")
    if peer:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", peer],
                capture_output=True, text=True, timeout=4
            )
            status["peer_reachable"] = result.returncode == 0
            if status["peer_reachable"]:
                for line in result.stdout.splitlines():
                    if "time=" in line:
                        status["peer_latency_ms"] = int(float(line.split("time=")[1].split()[0]))
        except Exception:
            pass

    return status


# ═══════════════════════════════════════════════════════════════════════════════
# Config sync (MASTER → BACKUP)
# ═══════════════════════════════════════════════════════════════════════════════

_sync_thread = None
_sync_running = False


def start_sync():
    """Start background config sync thread (MASTER only, and only when HA is on)."""
    global _sync_thread, _sync_running
    cfg = database.get_ha_config()
    if not cfg.get("enabled") or not cfg.get("sync_enabled") or cfg.get("role") != "MASTER":
        return
    if not (cfg.get("sync_peer") or cfg.get("peer_ip")):
        return
    if _sync_running:
        return
    _sync_running = True
    _sync_thread = threading.Thread(target=_sync_loop, daemon=True)
    _sync_thread.start()


def stop_sync():
    global _sync_running
    _sync_running = False


def sync_now():
    """Perform immediate config sync to peer."""
    cfg = database.get_ha_config()
    peer = cfg.get("sync_peer", "")
    if not peer:
        return False, "No sync peer configured"
    return _do_sync(peer)


def parse_host_key(text):
    """Accept 'ssh-ed25519 AAAA...' or a full ssh-keyscan line."""
    parts = (text or "").strip().split()
    if len(parts) >= 3 and parts[1] in HOST_KEY_TYPES:
        parts = parts[1:3]
    if len(parts) != 2 or parts[0] not in HOST_KEY_TYPES:
        raise ValueError("Peer host key must be one line: ssh-ed25519 AAAA...")
    keytype, blob = parts
    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception as exc:
        raise ValueError("Peer host key is not valid base64") from exc
    if len(raw) < 16:
        raise ValueError("Peer host key is too short")
    return keytype, blob


def known_hosts_line(host, host_key):
    peer = (host or "").strip()
    try:
        ipaddress.ip_address(peer)
    except ValueError as exc:
        raise ValueError("HA peer must be an IP address") from exc
    keytype, blob = parse_host_key(host_key)
    return "%s %s %s\n" % (peer, keytype, blob)


def rsync_rsh(known_hosts=KNOWN_HOSTS):
    """ssh command rsync runs. Host keys are checked against a pinned file."""
    return (
        "ssh -o StrictHostKeyChecking=yes "
        "-o UserKnownHostsFile=%s "
        "-o CheckHostIP=yes -o ConnectTimeout=5 -o BatchMode=yes"
        % known_hosts
    )


def write_known_hosts(peer_ip, host_key, path=None):
    path = path or KNOWN_HOSTS
    line = known_hosts_line(peer_ip, host_key)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as handle:
        handle.write(line)
    return line


def _do_sync(peer_ip):
    """Rsync FGUARD config and database to the peer.

    Copies the directory this process is running from. Live boxes use
    /opt/aegisguard. --delete is not used, so a peer is never wiped.
    The peer SSH host key must already be saved. Sync refuses any other key.
    """
    if not IS_LINUX:
        return False, "Sync requires Linux"
    try:
        ipaddress.ip_address((peer_ip or "").strip())
    except ValueError:
        return False, "HA peer must be an IP address"
    cfg = database.get_ha_config()
    host_key = (cfg.get("peer_hostkey") or "").strip()
    if not host_key:
        return False, "Set the peer SSH host key before sync. On the peer run: ssh-keyscan -t ed25519 %s" % peer_ip
    try:
        write_known_hosts(peer_ip, host_key)
    except ValueError as exc:
        return False, str(exc)
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    from core.parity import export_policy, full_policy_enabled, rsync_excludes
    full_policy = full_policy_enabled()
    if full_policy:
        export_policy(base)
    if not base.endswith("/"):
        base += "/"
    remote = "root@%s:%s" % (peer_ip.strip(), base)
    command = ["rsync", "-az"]
    for name in rsync_excludes(full_policy):
        command.append("--exclude=%s" % name)
    command += ["-e", rsync_rsh(), base, remote]
    ok, _, err = run(command, timeout=60)

    if ok:
        run(ssh_reload_command(peer_ip), timeout=10)
        database.add_log("INFO", details=f"HA sync completed to {peer_ip}")
        return True, f"Synced to {peer_ip}"
    return False, err


def ssh_reload_command(peer_ip):
    return [
        "ssh",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=%s" % KNOWN_HOSTS,
        "-o", "CheckHostIP=yes",
        "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes",
        "root@%s" % peer_ip.strip(),
        "systemctl reload fguard",
    ]


def _sync_loop():
    while _sync_running:
        cfg = database.get_ha_config()
        interval = cfg.get("sync_interval", 30)
        peer = cfg.get("sync_peer", "")
        if peer and cfg.get("sync_enabled"):
            try:
                _do_sync(peer)
            except Exception:
                pass
        time.sleep(interval)
