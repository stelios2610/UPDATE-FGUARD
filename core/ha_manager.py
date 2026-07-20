"""High Availability Manager — VRRP via keepalived + config sync.

Architecture:
  - Two FGUARD UTC nodes: MASTER (priority 100) and BACKUP (priority 90)
  - keepalived manages VRRP: Virtual IP floats to active MASTER
  - On failover, BACKUP becomes MASTER and takes the Virtual IP
  - Config sync: MASTER periodically rsyncs its config/DB to BACKUP
"""
import os
import subprocess
import threading
import time
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

KEEPALIVED_CONF = "/etc/keepalived/keepalived.conf"
KEEPALIVED_D    = "/etc/keepalived/keepalived.d"
NOTIFY_SCRIPT   = "/etc/keepalived/aegisguard-notify.sh"


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
    auth_pass   = cfg.get("auth_pass", "AegisHA")
    preempt     = "preempt" if cfg.get("preempt", 1) else "nopreempt"

    if not vip:
        return False, "Virtual IP is required"

    os.makedirs("/etc/keepalived", exist_ok=True)
    _write_notify_script()

    conf = f"""# FGUARD UTC HA — keepalived config
# Generated: {datetime.now().isoformat()}
# Role: {role}

global_defs {{
    router_id AEGISGUARD_{role}
    script_user root
    enable_script_security
}}

vrrp_script chk_aegisguard {{
    script "/usr/bin/systemctl is-active aegisguard"
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
        chk_aegisguard
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
# FGUARD UTC VRRP notify script
# Called by keepalived on state change
# Args: $1=instance $2=state $3=priority

TYPE=$1
NAME=$2
STATE=$3

logger -t aegisguard-ha "VRRP transition: $NAME -> $STATE"

case "$STATE" in
    MASTER)
        # We became master — ensure firewall is running
        systemctl start aegisguard 2>/dev/null
        systemctl start dnsmasq 2>/dev/null
        # Re-apply NAT masquerade
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
        python3 -c "
import sys; sys.path.insert(0,'/opt/aegisguard')
from db import database
database.add_log('WARN', details='HA: became MASTER')
" 2>/dev/null
        ;;
    BACKUP)
        python3 -c "
import sys; sys.path.insert(0,'/opt/aegisguard')
from db import database
database.add_log('INFO', details='HA: became BACKUP')
" 2>/dev/null
        ;;
    FAULT)
        python3 -c "
import sys; sys.path.insert(0,'/opt/aegisguard')
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
        return True, "keepalived restarted"
    return False, err or out


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
    """Start background config sync thread (MASTER only)."""
    global _sync_thread, _sync_running
    cfg = database.get_ha_config()
    if not cfg.get("sync_enabled") or cfg.get("role") != "MASTER":
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


def _do_sync(peer_ip):
    """Rsync FGUARD UTC config and database to peer."""
    if not IS_LINUX:
        return False, "Sync requires Linux"

    ok, _, err = run([
        "rsync", "-az", "--delete",
        "--exclude=*.pyc", "--exclude=__pycache__",
        "--exclude=build/iso-work", "--exclude=build/*.iso",
        "-e", "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5",
        "/opt/aegisguard/",
        f"root@{peer_ip}:/opt/aegisguard/"
    ], timeout=60)

    if ok:
        # Reload peer's aegisguard service
        run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             f"root@{peer_ip}", "systemctl reload aegisguard"], timeout=10)
        database.add_log("INFO", details=f"HA sync completed to {peer_ip}")
        return True, f"Synced to {peer_ip}"
    return False, err


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
