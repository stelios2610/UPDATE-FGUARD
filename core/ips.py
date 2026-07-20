"""Intrusion Prevention System - signature-based detection + auto-block."""
import re
import threading
import time
import ipaddress
import psutil
from collections import defaultdict, deque
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

_lock = threading.Lock()
_blocked_ips = {}        # ip -> unblock Timer
_threat_callbacks = []

# Block duration per severity (seconds)
_BLOCK_DURATION = {"CRITICAL": 3600, "HIGH": 600, "MEDIUM": 0, "LOW": 0}

# Never block these (LAN, loopback, private)
_SAFE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
]

SIGNATURES = [
    {
        "id": "PORT_SCAN",
        "name": "Port Scan Detected",
        "description": "Remote IP connecting to many ports in short time",
        "severity": "HIGH",
        "threshold_ports": 15,
        "window_seconds": 60,
    },
    {
        "id": "SYN_FLOOD",
        "name": "SYN Flood",
        "description": "High rate of SYN connections from single IP",
        "severity": "CRITICAL",
        "threshold_conns": 50,
        "window_seconds": 10,
    },
    {
        "id": "BRUTE_FORCE_SSH",
        "name": "SSH Brute Force",
        "description": "Multiple connection attempts to port 22",
        "severity": "HIGH",
        "threshold_conns": 10,
        "window_seconds": 30,
        "port": 22,
    },
    {
        "id": "BRUTE_FORCE_RDP",
        "name": "RDP Brute Force",
        "description": "Multiple connection attempts to port 3389",
        "severity": "HIGH",
        "threshold_conns": 10,
        "window_seconds": 30,
        "port": 3389,
    },
    {
        "id": "BRUTE_FORCE_SMB",
        "name": "SMB Attack",
        "description": "Multiple connection attempts to SMB port 445",
        "severity": "HIGH",
        "threshold_conns": 8,
        "window_seconds": 30,
        "port": 445,
    },
    {
        "id": "HTTP_FLOOD",
        "name": "HTTP Flood",
        "description": "High rate of connections to port 80/443/8080",
        "severity": "HIGH",
        "threshold_conns": 80,
        "window_seconds": 10,
        "ports": [80, 443, 8080, 8888],
    },
]

_enabled_signatures = {sig["id"]: True for sig in SIGNATURES}
_ip_port_history  = defaultdict(lambda: defaultdict(list))
_ip_conn_history  = defaultdict(list)
_running = False
_monitor_thread = None
_alerts = deque(maxlen=1000)


def register_callback(fn):
    _threat_callbacks.append(fn)


def _fire_alert(alert):
    _alerts.appendleft(alert)
    for fn in _threat_callbacks:
        try:
            fn(alert)
        except Exception:
            pass


def _is_safe_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _SAFE_NETS)
    except ValueError:
        return False


def _block_ip(ip, duration):
    if not IS_LINUX or duration <= 0 or _is_safe_ip(ip):
        return
    with _lock:
        if ip in _blocked_ips:
            return
        run(["iptables", "-I", "INPUT", "1", "-s", ip,
             "-m", "comment", "--comment", f"ips_block_{ip}",
             "-j", "DROP"])
        t = threading.Timer(duration, _unblock_ip, args=[ip])
        t.daemon = True
        t.start()
        _blocked_ips[ip] = t
    database.add_log("BLOCK", src_ip=ip, rule_name="IPS Auto-Block",
                     details=f"IPS blocked {ip} for {duration}s")


def _unblock_ip(ip):
    with _lock:
        _blocked_ips.pop(ip, None)
    if IS_LINUX:
        run(["iptables", "-D", "INPUT", "-s", ip,
             "-m", "comment", "--comment", f"ips_block_{ip}",
             "-j", "DROP"])


def _check_signatures(conns):
    now = time.time()
    alerts = []

    for c in conns:
        if not c.get("remote_ip") or c["remote_ip"] in ("", "0.0.0.0", "::"):
            continue
        rip   = c["remote_ip"]
        rport = c.get("local_port", 0)

        _ip_port_history[rip][rport].append(now)
        _ip_port_history[rip][rport] = [t for t in _ip_port_history[rip][rport] if now - t < 120]

        _ip_conn_history[rip].append(now)
        _ip_conn_history[rip] = [t for t in _ip_conn_history[rip] if now - t < 120]

    for sig in SIGNATURES:
        if not _enabled_signatures.get(sig["id"], True):
            continue

        if sig["id"] == "PORT_SCAN":
            for rip, port_map in list(_ip_port_history.items()):
                recent_ports = sum(
                    1 for port, times in port_map.items()
                    if any(now - t < sig["window_seconds"] for t in times)
                )
                if recent_ports >= sig["threshold_ports"]:
                    alert = _make_alert(sig, rip, f"{recent_ports} ports in {sig['window_seconds']}s")
                    if alert:
                        alerts.append(alert)

        elif sig["id"] == "SYN_FLOOD":
            for rip, times in list(_ip_conn_history.items()):
                recent = sum(1 for t in times if now - t < sig["window_seconds"])
                if recent >= sig["threshold_conns"]:
                    alert = _make_alert(sig, rip, f"{recent} connections in {sig['window_seconds']}s")
                    if alert:
                        alerts.append(alert)

        elif "BRUTE_FORCE" in sig["id"]:
            port = sig.get("port")
            for rip, port_map in list(_ip_port_history.items()):
                times = port_map.get(port, [])
                recent = sum(1 for t in times if now - t < sig["window_seconds"])
                if recent >= sig["threshold_conns"]:
                    alert = _make_alert(sig, rip, f"{recent} attempts to port {port}")
                    if alert:
                        alerts.append(alert)

        elif sig["id"] == "HTTP_FLOOD":
            ports = sig.get("ports", [])
            for rip, port_map in list(_ip_port_history.items()):
                recent = sum(
                    1 for p in ports
                    for t in port_map.get(p, [])
                    if now - t < sig["window_seconds"]
                )
                if recent >= sig["threshold_conns"]:
                    alert = _make_alert(sig, rip, f"{recent} HTTP requests in {sig['window_seconds']}s")
                    if alert:
                        alerts.append(alert)

    return alerts


_alerted_ips = {}


def _make_alert(sig, remote_ip, detail):
    key = f"{sig['id']}-{remote_ip}"
    now = time.time()
    if _alerted_ips.get(key, 0) > now - 60:
        return None
    _alerted_ips[key] = now

    alert = {
        "id":        sig["id"],
        "name":      sig["name"],
        "severity":  sig["severity"],
        "remote_ip": remote_ip,
        "detail":    detail,
        "timestamp": datetime.now().isoformat(),
        "blocked":   False,
    }

    # Auto-block HIGH and CRITICAL threats
    duration = _BLOCK_DURATION.get(sig["severity"], 0)
    if duration > 0 and database.get_setting("ips_auto_block", "1") == "1":
        _block_ip(remote_ip, duration)
        alert["blocked"] = True

    database.add_log("THREAT", src_ip=remote_ip,
                     rule_name=sig["name"],
                     details=f"[{sig['severity']}] {detail}" + (" — BLOCKED" if alert["blocked"] else ""))
    return alert


def _monitor_loop():
    global _running
    while _running:
        try:
            raw = psutil.net_connections(kind="inet")
            conns = []
            for c in raw:
                if c.raddr and not _is_safe_ip(c.raddr.ip):
                    conns.append({
                        "remote_ip":  c.raddr.ip,
                        "local_port": c.laddr.port if c.laddr else 0,
                        "proto":      "TCP" if c.type == 1 else "UDP",
                    })
            alerts = _check_signatures(conns)
            for alert in alerts:
                _fire_alert(alert)
        except Exception:
            pass
        time.sleep(2)


def start():
    global _running, _monitor_thread
    if _running:
        return
    _running = True
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    _monitor_thread.start()


def stop():
    global _running
    _running = False


def get_alerts(limit=100):
    return list(_alerts)[:limit]


def get_signatures():
    return [{"enabled": _enabled_signatures.get(s["id"], True), **s} for s in SIGNATURES]


def set_signature_enabled(sig_id, enabled):
    _enabled_signatures[sig_id] = enabled


def clear_alerts():
    _alerts.clear()


def get_blocked_ips():
    return list(_blocked_ips.keys())


def unblock_ip(ip):
    t = _blocked_ips.pop(ip, None)
    if t:
        t.cancel()
    _unblock_ip(ip)
