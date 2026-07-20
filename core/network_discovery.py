"""Network Discovery - Nmap integration (WatchGuard Network Discovery equivalent)."""
import subprocess
import threading
import json
import os
import re
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

_scan_running = False
_last_scan_results = []
_scan_callbacks = []


def register_callback(fn):
    _scan_callbacks.append(fn)


def _fire(results):
    for fn in _scan_callbacks:
        try:
            fn(results)
        except Exception:
            pass


def is_nmap_available():
    ok, _, _ = run(["nmap", "--version"])
    return ok


def scan_network(subnet, scan_type="quick", callback=None):
    """
    Scan network for devices.
    scan_type: quick (ping scan), port (common ports), full (all ports), os (OS detection)
    """
    global _scan_running, _last_scan_results
    if _scan_running:
        return False, "Scan already running"

    flags = {
        "quick":    ["-sn", "-T4"],                    # Ping sweep only
        "port":     ["-sS", "-T4", "--top-ports", "100"],  # Top 100 ports
        "full":     ["-sS", "-T3", "-p-"],             # All 65535 ports
        "os":       ["-sS", "-O", "-T4", "--top-ports", "100"],  # OS detection
        "vuln":     ["-sV", "--script=vuln", "-T4"],   # Vulnerability scan
        "service":  ["-sV", "-T4", "--top-ports", "200"],  # Service versions
    }

    nmap_flags = flags.get(scan_type, flags["quick"])

    def _run():
        global _scan_running, _last_scan_results
        _scan_running = True
        database.add_log("INFO", details=f"Network scan started: {subnet} ({scan_type})")
        try:
            cmd = ["nmap", "-oX", "-"] + nmap_flags + [subnet]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            hosts = _parse_nmap_xml(result.stdout)
            _last_scan_results = hosts
            database.add_log("INFO", details=f"Network scan complete: {len(hosts)} hosts found")
            _fire(hosts)
            if callback:
                callback(hosts)
        except subprocess.TimeoutExpired:
            database.add_log("WARN", details="Network scan timed out")
        except Exception as e:
            database.add_log("WARN", details=f"Network scan error: {e}")
        finally:
            _scan_running = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return True, "Scan started"


def _parse_nmap_xml(xml_output):
    """Parse nmap XML output to host list."""
    hosts = []
    # Simple regex-based parsing (avoids xml dependency)
    host_blocks = re.findall(r"<host[^>]*>(.*?)</host>", xml_output, re.DOTALL)
    for block in host_blocks:
        host = {}
        # State
        state_m = re.search(r'<status[^>]+state="([^"]+)"', block)
        if not state_m or state_m.group(1) != "up":
            continue
        # IP
        ip_m = re.search(r'<address[^>]+addrtype="ipv4"[^>]+addr="([^"]+)"', block)
        if not ip_m:
            ip_m = re.search(r'<address[^>]+addr="([^"]+)"', block)
        host["ip"] = ip_m.group(1) if ip_m else "unknown"
        # MAC
        mac_m = re.search(r'<address[^>]+addrtype="mac"[^>]+addr="([^"]+)"', block)
        host["mac"] = mac_m.group(1) if mac_m else ""
        vendor_m = re.search(r'<address[^>]+addrtype="mac"[^>]+vendor="([^"]+)"', block)
        host["vendor"] = vendor_m.group(1) if vendor_m else ""
        # Hostname
        name_m = re.search(r'<hostname[^>]+name="([^"]+)"', block)
        host["hostname"] = name_m.group(1) if name_m else ""
        # OS
        os_m = re.search(r'<osmatch[^>]+name="([^"]+)"', block)
        host["os"] = os_m.group(1) if os_m else ""
        # Open ports
        ports = []
        for port_m in re.finditer(
                r'<port[^>]+portid="(\d+)"[^>]+protocol="([^"]+)"[^>]*>.*?<state[^>]+state="([^"]+)".*?(?:<service[^>]+name="([^"]*)"[^>]*(?:product="([^"]*)"[^>]*)?)?',
                block, re.DOTALL):
            if port_m.group(3) == "open":
                ports.append({
                    "port": int(port_m.group(1)),
                    "protocol": port_m.group(2),
                    "service": port_m.group(4) or "",
                    "product": port_m.group(5) or "",
                })
        host["ports"] = ports
        host["port_count"] = len(ports)
        host["discovered_at"] = datetime.now().isoformat()
        hosts.append(host)
    return hosts


def get_scan_results():
    return _last_scan_results


def is_scanning():
    return _scan_running


def stop_scan():
    global _scan_running
    _scan_running = False


def _validate_host(host: str) -> bool:
    """Allow only valid IPv4/IPv6 addresses or simple hostnames."""
    import ipaddress
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Allow simple hostnames/FQDNs (letters, digits, hyphens, dots only)
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$', host))


def ping_host(ip, count=4):
    """Quick ping test."""
    if not _validate_host(ip):
        return False, None
    flag = "-c" if IS_LINUX else "-n"
    ok, out, err = run(["ping", flag, str(count), ip], timeout=10)
    if ok:
        m = re.search(r"avg.*?=.*?/([\d.]+)/", out)
        rtt = float(m.group(1)) if m else None
        return True, rtt
    return False, None


def traceroute(ip):
    """Run traceroute to a host."""
    if not _validate_host(ip):
        return "Invalid host address"
    cmd = ["traceroute", ip] if IS_LINUX else ["tracert", ip]
    ok, out, err = run(cmd, timeout=60)
    return out if ok else err


def get_arp_table():
    """Get ARP table."""
    ok, out, err = run(["arp", "-a"])
    entries = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            ip_m = re.search(r"\(?([\d.]+)\)?", parts[0] if "(" in line else "")
            if not ip_m and len(parts) > 1:
                ip_m = re.search(r"[\d.]+", parts[1])
            mac_m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
            if ip_m and mac_m:
                entries.append({"ip": ip_m.group(), "mac": mac_m.group()})
    return entries
