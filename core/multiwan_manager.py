"""Multi-WAN Manager — failover + load balancing via Linux policy routing.

Architecture:
  - Each WAN link gets a dedicated routing table (100 + link_id)
  - ip rule: traffic FROM that WAN's IP uses that table (reply routing)
  - Main table: ECMP nexthops for load-balance, or single for failover
  - Health checks: periodic ping via each interface; on failure remove from main table
"""
import threading
import time
import subprocess
import socket
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

# Routing table base (table 100+id for each WAN link)
RT_BASE = 100

_lock = threading.Lock()
_health_thread = None
_running = False

# Runtime state: link_id -> {"up": bool, "latency": int, "failures": int}
_link_state = {}


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

def start():
    """Start background health-check thread."""
    global _health_thread, _running
    if _running:
        return
    _running = True
    _health_thread = threading.Thread(target=_health_loop, daemon=True)
    _health_thread.start()


def stop():
    global _running
    _running = False


def get_status():
    """Return live status for all WAN links."""
    links = database.get_wan_links()
    result = []
    for link in links:
        state = _link_state.get(link["id"], {})
        result.append({
            **link,
            "up":       state.get("up", None),
            "latency":  state.get("latency", 0),
            "failures": state.get("failures", 0),
        })
    return result


def apply_routing():
    """Apply full Multi-WAN routing to the system (call after config change)."""
    if not IS_LINUX:
        return False, "Multi-WAN requires Linux"
    links = [l for l in database.get_wan_links() if l["enabled"]]
    if not links:
        return True, "No WAN links configured"

    _setup_rt_tables(links)
    _setup_policy_rules(links)
    _apply_main_routes(links)
    database.add_log("INFO", details=f"Multi-WAN routing applied: {len(links)} links")
    return True, f"Applied {len(links)} WAN link(s)"


def failover_to(link_id):
    """Force failover — remove all routes except the specified link."""
    if not IS_LINUX:
        return False, "Linux only"
    links = database.get_wan_links()
    target = next((l for l in links if l["id"] == link_id), None)
    if not target:
        return False, "Link not found"
    _flush_default_routes()
    run(["ip", "route", "add", "default",
         "via", target["gateway"], "dev", target["interface"]])
    database.add_log("WARN", details=f"Manual failover to WAN: {target['name']}")
    return True, f"Forced failover to {target['name']}"


# ═══════════════════════════════════════════════════════════════════════════════
# Routing setup
# ═══════════════════════════════════════════════════════════════════════════════

def _setup_rt_tables(links):
    """Ensure /etc/iproute2/rt_tables has entries for each WAN link."""
    try:
        with open("/etc/iproute2/rt_tables", "r") as f:
            existing = f.read()
        additions = []
        for link in links:
            table_id = RT_BASE + link["id"]
            table_name = f"wan_{link['id']}"
            if str(table_id) not in existing:
                additions.append(f"{table_id}\t{table_name}")
        if additions:
            with open("/etc/iproute2/rt_tables", "a") as f:
                f.write("\n" + "\n".join(additions) + "\n")
    except Exception:
        pass


def _setup_policy_rules(links):
    """Add ip rules for reply routing (each WAN replies on same interface)."""
    for link in links:
        table_id = RT_BASE + link["id"]
        iface = link["interface"]

        # Get IP of the interface
        ok, out, _ = run(["ip", "addr", "show", iface])
        ip = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "/" in line:
                ip = line.split()[1].split("/")[0]
                break
        if not ip:
            continue

        # Route table for this WAN: default via its gateway
        run(["ip", "route", "flush", "table", str(table_id)])
        run(["ip", "route", "add", "default", "via", link["gateway"],
             "dev", iface, "table", str(table_id)])

        # Rule: traffic FROM this WAN's IP uses its table
        run(["ip", "rule", "del", "from", ip, "lookup", str(table_id)])
        run(["ip", "rule", "add", "from", ip, "lookup", str(table_id)])

        # Per-interface MASQUERADE
        from core.rules_engine import _ipt
        _ipt(["-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
        _ipt(["-A", "FORWARD", "-i", iface, "-j", "ACCEPT"])
        _ipt(["-A", "FORWARD", "-o", iface, "-j", "ACCEPT"])


def _apply_main_routes(links):
    """Set main table default route: ECMP for load-balance, single for failover."""
    enabled_up = [l for l in links if l["enabled"] and _link_state.get(l["id"], {}).get("up", True)]
    if not enabled_up:
        enabled_up = [l for l in links if l["enabled"]]
    if not enabled_up:
        return

    mode = enabled_up[0]["mode"]
    _flush_default_routes()

    if mode == "loadbalance" and len(enabled_up) > 1:
        # ECMP: all links in one route with weights
        args = ["ip", "route", "add", "default"]
        for link in enabled_up:
            args += ["nexthop", "via", link["gateway"],
                     "dev", link["interface"],
                     "weight", str(max(1, link["weight"]))]
        run(args)
    else:
        # Failover: use highest priority (lowest number) link
        best = sorted(enabled_up, key=lambda l: l["priority"])[0]
        run(["ip", "route", "add", "default",
             "via", best["gateway"], "dev", best["interface"]])


def _flush_default_routes():
    """Remove all default routes from main table."""
    while True:
        ok, out, _ = run(["ip", "route", "show", "default"])
        if not ok or not out.strip():
            break
        run(["ip", "route", "del", "default"])


# ═══════════════════════════════════════════════════════════════════════════════
# Health checks
# ═══════════════════════════════════════════════════════════════════════════════

def _ping_via(interface, target_ip, timeout=3):
    """Ping target_ip via a specific interface. Returns (reachable, latency_ms)."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), "-I", interface, target_ip],
            capture_output=True, text=True, timeout=timeout + 2
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "time=" in line:
                    ms = float(line.split("time=")[1].split()[0])
                    return True, int(ms)
            return True, 0
        return False, 0
    except Exception:
        return False, 0


def _health_loop():
    """Background thread: check all WAN links periodically."""
    while _running:
        links = database.get_wan_links()
        changed = False

        for link in links:
            if not link["enabled"]:
                continue

            lid = link["id"]
            prev = _link_state.get(lid, {"up": None, "latency": 0, "failures": 0})

            reachable, latency = _ping_via(
                link["interface"], link["check_ip"], link["check_timeout"]
            )

            if reachable:
                failures = 0
                is_up = True
            else:
                failures = prev["failures"] + 1
                is_up = failures < link["check_failures"]

            state_changed = (prev.get("up") != is_up)
            with _lock:
                _link_state[lid] = {"up": is_up, "latency": latency, "failures": failures}

            # Persist status to DB
            database.update_wan_link(lid,
                status="up" if is_up else "down",
                latency_ms=latency,
                last_check=datetime.now().isoformat())

            if state_changed:
                changed = True
                status_str = "UP" if is_up else "DOWN"
                database.add_log(
                    "WARN" if not is_up else "INFO",
                    details=f"WAN link '{link['name']}' ({link['interface']}) went {status_str}"
                )

        # Re-apply routes if any link changed state
        if changed and IS_LINUX:
            try:
                _apply_main_routes([l for l in links if l["enabled"]])
            except Exception:
                pass

        # Sleep until next check (use shortest interval of all links)
        intervals = [l["check_interval"] for l in links if l["enabled"]] or [10]
        time.sleep(min(intervals))
