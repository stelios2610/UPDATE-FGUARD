"""FGUARD UTC Update Manager — checks UPDATE-FGUARD repo daily, downloads and applies updates."""
import os
import json
import shutil
import zipfile
import threading
import subprocess
import urllib.request
from datetime import datetime, date

from core.license_manager import is_licensed

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
LOCAL_VERSION_FILE = os.path.join(BASE_DIR, "version.json")
UPDATES_DIR = os.path.join(BASE_DIR, "updates")
PENDING_DIR = os.path.join(UPDATES_DIR, "pending")

UPDATE_REPO_RAW = "https://raw.githubusercontent.com/stelios2610/UPDATE-FGUARD/main"
UPDATE_REPO_ZIP = "https://github.com/stelios2610/UPDATE-FGUARD/archive/refs/heads/main.zip"
VERSION_URL = f"{UPDATE_REPO_RAW}/version.json"

# Files/dirs that must never be overwritten by an update
PROTECTED = {
    "firewall.db",
    "pki",
    "vpn-configs",
    "ssl-vpn-server.conf",
    "version.json",
    "updates",
    "__pycache__",
}

_status_lock = threading.Lock()
_status = {
    "last_check": None,
    "available": False,
    "version": None,
    "date": None,
    "changelog": [],
    "downloaded": False,
    "error": None,
}


def get_local_version():
    try:
        with open(LOCAL_VERSION_FILE) as f:
            return json.load(f).get("version", "0.0.0")
    except Exception:
        return "0.0.0"


def get_status():
    with _status_lock:
        return dict(_status)


def _version_tuple(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except Exception:
        return (0, 0, 0)


def check_for_update():
    """Fetch remote version.json and compare with local. Returns status dict."""
    if not is_licensed():
        with _status_lock:
            _status["error"] = "No valid license"
            _status["last_check"] = datetime.now().isoformat()
        return get_status()

    try:
        req = urllib.request.Request(VERSION_URL, headers={"Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=15) as r:
            remote = json.loads(r.read().decode())

        remote_ver = remote.get("version", "0.0.0")
        local_ver = get_local_version()
        available = _version_tuple(remote_ver) > _version_tuple(local_ver)
        downloaded = _is_downloaded(remote_ver)

        with _status_lock:
            _status.update({
                "last_check": datetime.now().isoformat(),
                "available": available,
                "version": remote_ver,
                "date": remote.get("date", ""),
                "changelog": remote.get("changelog", []),
                "downloaded": downloaded,
                "error": None,
            })
    except Exception as e:
        with _status_lock:
            _status["last_check"] = datetime.now().isoformat()
            _status["error"] = str(e)

    return get_status()


def _is_downloaded(version):
    marker = os.path.join(PENDING_DIR, f"version_{version}.marker")
    return os.path.isfile(marker)


def download_update():
    """Download the update zip to PENDING_DIR. Returns (ok, message)."""
    if not is_licensed():
        return False, "No valid license"

    st = get_status()
    if not st.get("available"):
        return False, "No update available"

    version = st.get("version")
    if _is_downloaded(version):
        return True, f"Already downloaded (v{version})"

    try:
        os.makedirs(PENDING_DIR, exist_ok=True)
        zip_path = os.path.join(PENDING_DIR, "update.zip")

        req = urllib.request.Request(UPDATE_REPO_ZIP, headers={"Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=60) as r, open(zip_path, "wb") as f:
            shutil.copyfileobj(r, f)

        # Verify it's a valid zip
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.testzip()

        # Write marker
        marker = os.path.join(PENDING_DIR, f"version_{version}.marker")
        with open(marker, "w") as f:
            f.write(datetime.now().isoformat())

        with _status_lock:
            _status["downloaded"] = True

        return True, f"Downloaded v{version}"
    except Exception as e:
        return False, str(e)


def apply_update():
    """Extract and apply the downloaded update. Returns (ok, message)."""
    if not is_licensed():
        return False, "No valid license"

    zip_path = os.path.join(PENDING_DIR, "update.zip")
    if not os.path.isfile(zip_path):
        return False, "No downloaded update found"

    try:
        extract_dir = os.path.join(PENDING_DIR, "extracted")
        if os.path.isdir(extract_dir):
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)

        # The zip extracts to UPDATE-FGUARD-main/
        contents = os.listdir(extract_dir)
        if not contents:
            return False, "Empty update archive"
        src_root = os.path.join(extract_dir, contents[0])

        # Copy files, skipping protected paths
        copied = 0
        for item in os.listdir(src_root):
            if item in PROTECTED:
                continue
            src = os.path.join(src_root, item)
            dst = os.path.join(BASE_DIR, item)
            if os.path.isdir(src):
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
            copied += 1

        # Update local version
        remote_version_src = os.path.join(src_root, "version.json")
        if os.path.isfile(remote_version_src):
            shutil.copy2(remote_version_src, LOCAL_VERSION_FILE)

        # Clean up pending
        shutil.rmtree(PENDING_DIR, ignore_errors=True)

        with _status_lock:
            _status["available"] = False
            _status["downloaded"] = False

        # Restart service in background
        threading.Thread(target=_restart_service, daemon=True).start()

        return True, f"Update applied — {copied} components updated. Restarting..."
    except Exception as e:
        return False, str(e)


def _restart_service():
    import time
    time.sleep(2)
    try:
        subprocess.run(["systemctl", "restart", "aegisguard"], timeout=30)
    except Exception:
        pass


# ── Daily background checker ───────────────────────────────────────────────────

_last_check_date = None


def _daily_loop():
    global _last_check_date
    import time
    # Wait 60s after startup before first check
    time.sleep(60)
    while True:
        today = date.today().isoformat()
        if _last_check_date != today:
            _last_check_date = today
            try:
                st = check_for_update()
                if st.get("available") and not st.get("downloaded"):
                    download_update()
            except Exception:
                pass
        time.sleep(3600)  # re-check every hour to catch midnight rollover


def start_daily_check():
    t = threading.Thread(target=_daily_loop, daemon=True)
    t.start()
