"""Connection tracking sync so an HA failover keeps existing sessions."""
import os

from core.platform import IS_LINUX, run

CONF_PATH = "/etc/conntrackd/conntrackd.conf"


def render_conntrackd_conf(local_ip, peer_ip, interface):
    local_ip = (local_ip or "").strip()
    peer_ip = (peer_ip or "").strip()
    interface = (interface or "eth1").strip()
    if not local_ip or not peer_ip:
        raise ValueError("Session sync needs this node's IP and the peer IP")
    return """Sync {
    Mode FTFW {
        DisableExternalCache Off
    }
    UDP {
        IPv4_address %s
        IPv4_Destination_Address %s
        Port 3780
        Interface %s
        Checksum on
    }
}
General {
    Nice -20
    HashSize 32768
    HashLimit 131072
    LogFile /var/log/conntrackd.log
    LockFile /var/lock/conntrack.lock
    UNIX {
        Path /var/run/conntrackd.ctl
    }
    Filter From Userspace {
        Protocol Accept {
            TCP
            UDP
            ICMP
        }
        Address Ignore {
            IPv4_address 127.0.0.1
        }
    }
}
""" % (local_ip, peer_ip, interface)


def install_session_sync(local_ip, peer_ip, interface):
    """Write conntrackd.conf and start it. Missing conntrackd does not remove the virtual IP."""
    try:
        text = render_conntrackd_conf(local_ip, peer_ip, interface)
    except ValueError as exc:
        return False, str(exc)
    if not IS_LINUX:
        return False, "Session sync requires Linux"
    ok, _, _ = run(["which", "conntrackd"])
    if not ok:
        return False, "conntrackd is not installed"
    os.makedirs(os.path.dirname(CONF_PATH), exist_ok=True)
    with open(CONF_PATH, "w", encoding="utf-8") as handle:
        handle.write(text)
    run(["systemctl", "enable", "conntrackd"])
    ok, _, err = run(["systemctl", "restart", "conntrackd"], timeout=20)
    if not ok:
        return False, err or "conntrackd did not start"
    return True, "conntrackd restarted"
