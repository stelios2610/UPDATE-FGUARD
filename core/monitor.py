"""Network traffic monitor using psutil."""
import psutil
import socket
from datetime import datetime


STATUS_MAP = {
    "ESTABLISHED": "Established",
    "LISTEN": "Listening",
    "TIME_WAIT": "Time Wait",
    "CLOSE_WAIT": "Close Wait",
    "SYN_SENT": "SYN Sent",
    "SYN_RECV": "SYN Recv",
    "NONE": "",
}


def _get_proc_name(pid):
    if pid is None:
        return "System"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"PID {pid}"


def get_connections():
    connections = []
    try:
        raw = psutil.net_connections(kind="inet")
        for c in raw:
            laddr = c.laddr
            raddr = c.raddr
            entry = {
                "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "local_ip": laddr.ip if laddr else "",
                "local_port": laddr.port if laddr else 0,
                "remote_ip": raddr.ip if raddr else "",
                "remote_port": raddr.port if raddr else 0,
                "status": STATUS_MAP.get(c.status, c.status),
                "pid": c.pid,
                "process": _get_proc_name(c.pid),
            }
            connections.append(entry)
    except psutil.AccessDenied:
        pass
    return connections


def get_network_stats():
    from db import database
    stats = psutil.net_io_counters()
    b_sent, b_recv = database.get_traffic_baseline()
    return {
        "bytes_sent":    max(0, stats.bytes_sent    - b_sent),
        "bytes_recv":    max(0, stats.bytes_recv    - b_recv),
        "packets_sent":  stats.packets_sent,
        "packets_recv":  stats.packets_recv,
    }


def get_per_interface_stats():
    result = {}
    per_nic = psutil.net_io_counters(pernic=True)
    for name, s in per_nic.items():
        result[name] = {
            "bytes_sent": s.bytes_sent,
            "bytes_recv": s.bytes_recv,
        }
    return result


def format_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def get_blocked_activity(limit=100):
    """Aggregate currently blocked and recently logged blocked IPs for Monitor."""
    from db import database
    from core import ips, reputation

    entries = {}

    def upsert(ip, source, reason, last_seen="", active=False, hits=1):
        ip = (ip or "").strip()
        if not ip or ip in ("0.0.0.0", "::", "-"):
            return
        cur = entries.get(ip)
        if not cur:
            entries[ip] = {
                "ip": ip,
                "source": source,
                "reason": reason or "",
                "last_seen": last_seen or "",
                "hits": hits,
                "active": active,
            }
            return
        cur["hits"] += hits
        if active:
            cur["active"] = True
            if cur["source"] in ("Log", "") or source != "Log":
                cur["source"] = source
            if reason:
                cur["reason"] = reason
        elif not cur["reason"] and reason:
            cur["reason"] = reason
        if last_seen and last_seen > (cur["last_seen"] or ""):
            cur["last_seen"] = last_seen

    for ip in ips.get_blocked_ips():
        upsert(ip, "IPS", "IPS auto-block", active=True)

    for ip in reputation.get_ddos_stats().get("blocked_ips", []):
        upsert(ip, "DDoS", "Anti-DDoS", active=True)

    for rule in database.get_rules():
        if not rule.get("enabled"):
            continue
        name = rule.get("name") or ""
        if name.startswith("Block-IP:") or (
            rule.get("action") == "BLOCK" and rule.get("remote_ip")
        ):
            ip = (rule.get("remote_ip") or "").strip() or name.replace("Block-IP:", "", 1)
            upsert(ip, "Manual", name or "Blocked Sites", active=True)

    for log in database.get_logs(limit=500):
        if log.get("action") not in ("BLOCK", "DROP", "THREAT"):
            continue
        upsert(
            log.get("src_ip") or "",
            "Log",
            log.get("rule_name") or log.get("details") or log.get("action"),
            last_seen=log.get("timestamp") or "",
            hits=1,
        )

    items = list(entries.values())
    items.sort(key=lambda x: (1 if x["active"] else 0, x["last_seen"] or ""), reverse=True)
    return {"count": len(items), "ips": items[:limit]}
