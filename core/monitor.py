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
    stats = psutil.net_io_counters()
    return {
        "bytes_sent": stats.bytes_sent,
        "bytes_recv": stats.bytes_recv,
        "packets_sent": stats.packets_sent,
        "packets_recv": stats.packets_recv,
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
