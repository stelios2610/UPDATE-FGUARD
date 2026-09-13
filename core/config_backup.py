"""FortiGate-style configuration backup / restore for another appliance."""
import io
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime

from db import database

MAGIC = "FGUARD-UTC-CONFIG"
FORMAT_VERSION = 1
MAX_BYTES = 64 * 1024 * 1024
SKIP_TABLES = ("logs", "dhcp_leases", "file_filter_submissions")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTRA_PATHS = (
    os.path.join("pki"),
    os.path.join("vpn-configs"),
    "ssl-vpn-server.conf",
)


def _version():
    try:
        with open(os.path.join(BASE_DIR, "version.json"), encoding="utf-8") as f:
            return json.load(f).get("version", "0")
    except Exception:
        return "0"


def _safe_rel(name):
    name = (name or "").replace("\\", "/").lstrip("/")
    if not name or name.startswith("..") or "/../" in f"/{name}/":
        return None
    return name


def _copy_config_db(dest_path):
    src = sqlite3.connect(database.DB_PATH)
    dst = sqlite3.connect(dest_path)
    try:
        src.backup(dst)
        dst.commit()
        names = [
            r[0]
            for r in dst.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        ]
        for table in SKIP_TABLES:
            if table in names:
                dst.execute(f"DELETE FROM {table}")
        if "settings" in names:
            dst.execute("DELETE FROM settings WHERE key LIKE 'session:%'")
        dst.commit()
        dst.execute("VACUUM")
    finally:
        src.close()
        dst.close()


def _add_tree(zf, rel):
    full = os.path.join(BASE_DIR, rel)
    if os.path.isfile(full):
        zf.write(full, arcname=f"files/{rel.replace(os.sep, '/')}")
        return
    if not os.path.isdir(full):
        return
    for root, _dirs, files in os.walk(full):
        for fn in files:
            path = os.path.join(root, fn)
            rel_file = os.path.relpath(path, BASE_DIR).replace(os.sep, "/")
            zf.write(path, arcname=f"files/{rel_file}")


def build_backup():
    """Return (filename, zip_bytes)."""
    hostname = database.get_setting("hostname", "fguard") or "fguard"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"fguard-utc-{hostname}-{stamp}.conf"
    manifest = {
        "magic": MAGIC,
        "format": FORMAT_VERSION,
        "product": "FGUARD UTC",
        "version": _version(),
        "hostname": hostname,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "includes": ["sqlite", "pki", "vpn-configs"],
        "excludes": list(SKIP_TABLES) + ["sessions", "license.key"],
        "note": "Restore on replacement hardware. NIC names may differ; license is per-device.",
    }
    buf = io.BytesIO()
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        _copy_config_db(tmp.name)
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.comment = MAGIC.encode("ascii")
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))
            zf.write(tmp.name, arcname="firewall.db")
            for rel in EXTRA_PATHS:
                _add_tree(zf, rel)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return filename, buf.getvalue()


def _read_manifest(zf):
    try:
        raw = zf.read("manifest.json")
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ValueError("Not an FGUARD UTC configuration file (missing manifest)")
    if data.get("magic") != MAGIC:
        raise ValueError("Not an FGUARD UTC configuration file")
    fmt = int(data.get("format") or 0)
    if fmt < 1 or fmt > FORMAT_VERSION:
        raise ValueError(f"Unsupported config format version {fmt}")
    if "firewall.db" not in zf.namelist():
        raise ValueError("Configuration file is missing the database")
    return data


def restore_backup(data: bytes):
    """Replace local configuration from an uploaded .conf backup."""
    if not data:
        raise ValueError("Empty file")
    if len(data) > MAX_BYTES:
        raise ValueError(f"File larger than {MAX_BYTES // (1024 * 1024)} MB")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("Not a valid FGUARD UTC .conf backup")
    with zf:
        manifest = _read_manifest(zf)
        db_bytes = zf.read("firewall.db")
        file_members = []
        for info in zf.infolist():
            if info.is_dir() or not info.filename.startswith("files/"):
                continue
            rel = _safe_rel(info.filename[len("files/"):])
            if not rel:
                continue
            file_members.append((rel, zf.read(info.filename)))

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    try:
        tmp.write(db_bytes)
        tmp.close()
        probe = sqlite3.connect(tmp.name)
        try:
            probe.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
        finally:
            probe.close()

        bak = database.DB_PATH + ".pre-restore"
        if os.path.isfile(database.DB_PATH):
            try:
                shutil.copy2(database.DB_PATH, bak)
            except Exception:
                pass

        src = sqlite3.connect(tmp.name)
        dst = sqlite3.connect(database.DB_PATH)
        try:
            src.backup(dst)
            dst.commit()
            try:
                dst.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
        finally:
            src.close()
            dst.close()
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    for rel, content in file_members:
        dest = os.path.abspath(os.path.join(BASE_DIR, rel))
        if not dest.startswith(os.path.abspath(BASE_DIR) + os.sep) and dest != os.path.abspath(BASE_DIR):
            continue
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(content)

    database.initialize()
    database.add_log(
        "INFO",
        rule_name="Config Restore",
        details=f"Restored backup from {manifest.get('hostname', '?')} "
                f"({manifest.get('created_at', '')}, v{manifest.get('version', '')})",
    )
    return {
        "status": "ok",
        "from_hostname": manifest.get("hostname"),
        "from_version": manifest.get("version"),
        "created_at": manifest.get("created_at"),
        "message": "Configuration restored. Restart FGUARD UTC so VPN/network services pick up the new settings. License stays on this device.",
    }
