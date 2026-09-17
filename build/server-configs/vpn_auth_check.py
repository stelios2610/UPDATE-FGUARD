#!/usr/bin/env python3
import os
import sys, sqlite3, hashlib, hmac

DB = next((p for p in (
    "/opt/fguard/firewall.db",
    "/opt/aegisguard/firewall.db",
) if os.path.isfile(p)), "/opt/aegisguard/firewall.db")

try:
    import bcrypt as _bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False

try:
    with open(sys.argv[1]) as f:
        lines = f.read().splitlines()
    username = lines[0] if len(lines) > 0 else ''
    password = lines[1] if len(lines) > 1 else ''

    conn = sqlite3.connect(DB)
    row = conn.execute('SELECT password_hash, enabled FROM vpn_users WHERE username=?', (username,)).fetchone()
    conn.close()
    if not row or not row[1]:
        sys.exit(1)
    phash = row[0]
    if not phash or ':' not in phash:
        sys.exit(1)

    if phash.startswith('bcrypt:'):
        if not _BCRYPT_OK:
            sys.exit(1)
        sys.exit(0 if _bcrypt.checkpw(password.encode(), phash[7:].encode()) else 1)
    else:
        parts = phash.split(':', 2)
        if len(parts) != 3:
            sys.exit(1)
        _, salt, stored = parts
        h = hashlib.sha256(f'{salt}{password}'.encode()).hexdigest()
        sys.exit(0 if hmac.compare_digest(h, stored) else 1)
except Exception:
    sys.exit(1)
