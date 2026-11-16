#!/usr/bin/env python3
import os
import sys
import sqlite3
import hashlib
import hmac

CANDIDATES = (
    "/opt/fguard/firewall.db",
    "/opt/aegisguard/firewall.db",
)

try:
    import bcrypt as _bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False


def _open_db():
    """Read-only. OpenVPN runs this as nobody and must not need a write lock."""
    last_error = None
    for path in CANDIDATES:
        if not os.path.isfile(path):
            continue
        try:
            return sqlite3.connect("file:" + path + "?mode=ro", uri=True)
        except Exception as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise FileNotFoundError("vpn database")


try:
    with open(sys.argv[1]) as handle:
        lines = handle.read().splitlines()
    username = lines[0] if len(lines) > 0 else ""
    password = lines[1] if len(lines) > 1 else ""

    conn = _open_db()
    row = conn.execute(
        "SELECT password_hash, enabled FROM vpn_users WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()
    if not row or not row[1]:
        sys.exit(1)
    phash = row[0]
    if not phash or ":" not in phash:
        sys.exit(1)

    if phash.startswith("bcrypt:"):
        if not _BCRYPT_OK:
            sys.exit(1)
        sys.exit(0 if _bcrypt.checkpw(password.encode(), phash[7:].encode()) else 1)

    parts = phash.split(":", 2)
    if len(parts) != 3:
        sys.exit(1)
    _, salt, stored = parts
    digest = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    sys.exit(0 if hmac.compare_digest(digest, stored) else 1)
except Exception:
    sys.exit(1)
