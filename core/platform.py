"""Platform detection and abstraction layer."""
import sys
import os

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform == "win32"


def run(args, timeout=15):
    import subprocess
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return False, "", str(e)


def is_root():
    if IS_LINUX:
        return os.geteuid() == 0
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False


def get_interfaces():
    import psutil
    return list(psutil.net_if_addrs().keys())
