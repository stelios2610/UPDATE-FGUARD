"""FGUARD Update Manager — checks UPDATE-FGUARD repo daily, downloads and applies updates."""
import os
import json
import shutil
import threading
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, date

from core.license_manager import is_licensed
from core.update_trust import (
    manifest_trusted, parse_signature, safe_extract, sha256_file, verify_archive,
)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
LOCAL_VERSION_FILE = os.path.join(BASE_DIR, "version.json")
UPDATES_DIR = os.path.join(BASE_DIR, "updates")
PENDING_DIR = os.path.join(UPDATES_DIR, "pending")

UPDATE_REPO_RAW = "https://raw.githubusercontent.com/stelios2610/UPDATE-FGUARD/main"
VERSION_URL = f"{UPDATE_REPO_RAW}/version.json"
VERSION_SIG_URL = VERSION_URL + ".sig"
MANIFEST_NAME = "update.manifest.json"
SIGNATURE_NAME = "update.manifest.sig"
ARCHIVE_NAME = "update.zip"

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


def _fetch(url):
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError("update request failed (%s) for %s" % (exc.code, url)) from exc


def fetch_trusted_manifest():
    """Download version.json and version.json.sig. Refuse an unsigned manifest."""
    document = _fetch(VERSION_URL)
    try:
        signature_bytes = _fetch(VERSION_SIG_URL)
    except RuntimeError as exc:
        raise RuntimeError(
            "Refusing unsigned update. Publish version.json.sig next to version.json."
        ) from exc
    signature = parse_signature(signature_bytes)
    return manifest_trusted(document, signature), document, signature


def check_for_update():
    """Fetch the signed remote manifest and compare it with the local version."""
    if not is_licensed():
        with _status_lock:
            _status["error"] = "No valid license"
            _status["last_check"] = datetime.now().isoformat()
        return get_status()

    try:
        remote, _document, _signature = fetch_trusted_manifest()
        remote_ver = remote.get("version", "0.0.0")
        local_ver = get_local_version()
        available = _version_tuple(remote_ver) > _version_tuple(local_ver)
        downloaded = _is_downloaded(remote_ver) and _pending_matches(remote)

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
            _status["available"] = False
            _status["downloaded"] = False
            _status["error"] = str(e)

    return get_status()


def _pending_paths():
    return (
        os.path.join(PENDING_DIR, ARCHIVE_NAME),
        os.path.join(PENDING_DIR, MANIFEST_NAME),
        os.path.join(PENDING_DIR, SIGNATURE_NAME),
    )


def _is_downloaded(version):
    archive, manifest_path, _signature = _pending_paths()
    if not (os.path.isfile(archive) and os.path.isfile(manifest_path)):
        return False
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception:
        return False
    return manifest.get("version") == version


def _pending_matches(manifest):
    archive, manifest_path, signature_path = _pending_paths()
    if not (os.path.isfile(archive) and os.path.isfile(manifest_path) and os.path.isfile(signature_path)):
        return False
    try:
        with open(manifest_path, "rb") as handle:
            document = handle.read()
        with open(signature_path, "rb") as handle:
            signature = parse_signature(handle.read())
        trusted = verify_archive(archive, document, signature)
    except Exception:
        return False
    return trusted.get("sha256") == manifest.get("sha256") and trusted.get("version") == manifest.get("version")


def _store_pending(archive_bytes, document, signature):
    os.makedirs(PENDING_DIR, exist_ok=True)
    archive, manifest_path, signature_path = _pending_paths()
    partial = archive + ".partial"
    with open(partial, "wb") as handle:
        handle.write(archive_bytes)
    os.replace(partial, archive)
    with open(manifest_path, "wb") as handle:
        handle.write(document if isinstance(document, bytes) else json.dumps(document).encode())
    with open(signature_path, "wb") as handle:
        handle.write(signature if isinstance(signature, bytes) else str(signature).encode())


def download_update():
    """Download the signed archive. Returns (ok, message)."""
    if not is_licensed():
        return False, "No valid license"

    try:
        remote, document, signature = fetch_trusted_manifest()
    except Exception as exc:
        return False, str(exc)

    remote_ver = remote.get("version", "0.0.0")
    if _version_tuple(remote_ver) <= _version_tuple(get_local_version()):
        return False, "No update available"
    if _is_downloaded(remote_ver) and _pending_matches(remote):
        with _status_lock:
            _status["downloaded"] = True
        return True, "Already downloaded (v%s)" % remote_ver

    try:
        os.makedirs(PENDING_DIR, exist_ok=True)
        archive_bytes = _fetch(remote["url"])
        _store_pending(archive_bytes, document, base64_signature(signature))
        archive, _manifest_path, _signature_path = _pending_paths()
        verify_archive(archive, document, signature)
        with _status_lock:
            _status["downloaded"] = True
            _status["available"] = True
            _status["version"] = remote_ver
            _status["error"] = None
        return True, "Downloaded v%s" % remote_ver
    except Exception as exc:
        _discard_pending()
        return False, str(exc)


def base64_signature(signature):
    import base64
    if isinstance(signature, bytes) and len(signature) == 64:
        return base64.b64encode(signature)
    return signature


def _discard_pending():
    if os.path.isdir(PENDING_DIR):
        shutil.rmtree(PENDING_DIR, ignore_errors=True)


def _load_pending_trust():
    archive, manifest_path, signature_path = _pending_paths()
    if not (os.path.isfile(archive) and os.path.isfile(manifest_path) and os.path.isfile(signature_path)):
        raise ValueError("No signed update is waiting to be applied")
    with open(manifest_path, "rb") as handle:
        document = handle.read()
    with open(signature_path, "rb") as handle:
        signature = parse_signature(handle.read())
    trusted = verify_archive(archive, document, signature)
    if sha256_file(archive) != trusted["sha256"]:
        raise ValueError("update archive does not match the signed checksum")
    return archive, trusted


def _copy_verified_tree(src_root):
    """Copy a verified archive tree. Skip protected paths and refuse symlinks."""
    copied = 0
    for item in os.listdir(src_root):
        if item in PROTECTED:
            continue
        src = os.path.join(src_root, item)
        dst = os.path.join(BASE_DIR, item)
        if os.path.islink(src):
            raise ValueError("refusing to install a symlink from the update")
        if os.path.isdir(src):
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst, symlinks=False, ignore=shutil.ignore_patterns(*PROTECTED))
        else:
            shutil.copy2(src, dst)
        copied += 1
    return copied


def apply_update():
    """Verify the signed archive again, then install it. Returns (ok, message)."""
    if not is_licensed():
        return False, "No valid license"

    try:
        archive, trusted = _load_pending_trust()
        extract_dir = os.path.join(PENDING_DIR, "extracted")
        if os.path.isdir(extract_dir):
            shutil.rmtree(extract_dir)
        safe_extract(archive, extract_dir)

        contents = [name for name in os.listdir(extract_dir) if name not in (".", "..")]
        if len(contents) != 1:
            return False, "Update archive must contain one top-level directory"
        src_root = os.path.realpath(os.path.join(extract_dir, contents[0]))
        extract_root = os.path.realpath(extract_dir)
        if not src_root.startswith(extract_root + os.sep) or not os.path.isdir(src_root):
            return False, "Update archive layout is not safe"
        if os.path.islink(os.path.join(extract_dir, contents[0])):
            return False, "Update archive layout is not safe"

        copied = _copy_verified_tree(src_root)

        installed = {}
        remote_version_src = os.path.join(src_root, "version.json")
        if os.path.isfile(remote_version_src) and not os.path.islink(remote_version_src):
            try:
                with open(remote_version_src, "r", encoding="utf-8") as handle:
                    installed = json.load(handle)
            except Exception:
                installed = {}
        with open(LOCAL_VERSION_FILE, "w", encoding="utf-8") as handle:
            json.dump({
                "version": trusted["version"],
                "date": trusted.get("date") or installed.get("date", ""),
                "product": installed.get("product", "FGUARD"),
                "changelog": trusted.get("changelog") or installed.get("changelog") or [],
            }, handle, indent=2)
            handle.write("\n")

        shutil.rmtree(PENDING_DIR, ignore_errors=True)
        with _status_lock:
            _status["available"] = False
            _status["downloaded"] = False

        post_update = os.path.join(BASE_DIR, "build", "post-update.sh")
        if os.path.isfile(post_update):
            try:
                os.chmod(post_update, 0o755)
                subprocess.run(["bash", post_update], timeout=90, check=False)
            except Exception:
                pass

        threading.Thread(target=_restart_service, daemon=True).start()
        return True, "Update applied — %s components updated. Restarting..." % copied
    except Exception as exc:
        return False, str(exc)


def _restart_service():
    import time
    time.sleep(2)
    # Never run aegisguard and fguard together — both bind 127.0.0.1:8888.
    keep = "aegisguard"
    try:
        r = subprocess.run(
            ["systemctl", "is-enabled", "aegisguard"],
            timeout=10, capture_output=True, text=True,
        )
        if r.returncode != 0:
            keep = "fguard"
    except Exception:
        pass
    other = "fguard" if keep == "aegisguard" else "aegisguard"
    subprocess.run(["systemctl", "stop", other], timeout=30, check=False)
    # Do not systemctl stop the unit we are running in — that kills this
    # process before start runs and leaves nginx 502. systemd-run lives
    # outside our cgroup so start still happens after we exit.
    try:
        subprocess.run(["systemctl", "reset-failed", keep], timeout=10, check=False)
        subprocess.run(
            ["systemd-run", "--collect", "--on-active=2s",
             f"/bin/systemctl", "restart", keep],
            timeout=15, check=False,
        )
    except Exception:
        subprocess.run(["systemctl", "restart", keep], timeout=30, check=False)


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
