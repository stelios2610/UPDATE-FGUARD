"""FGUARD UTC License Manager — validates license key on the deployed appliance."""
import hashlib
import json
import base64
import subprocess
from datetime import datetime

LICENSE_FILE = "/etc/aegisguard/license.key"
# Must match the SECRET_KEY in generate_license.py — keep private, never commit the real value
SECRET_KEY = "3a6e515a424558f4fae7173cf9b250ef2443d2783d8ea277b9e106b8cea15998"

_cache = {"status": None, "info": None, "ts": 0}


def _get_all_macs():
    macs = set()
    try:
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "link/ether" in line:
                mac = line.strip().split()[1].upper()
                macs.add(mac)
    except Exception:
        pass
    return macs


def validate_license(force=False):
    """
    Returns (status, info) where status is one of:
      'valid'    — OK, > 30 days left
      'expiring' — OK, <= 30 days left
      'expired'  — file exists but date passed
      'invalid'  — tampered / wrong MAC / bad format
      'missing'  — no license file found
    info = {days_remaining, customer, expires, issued}
    """
    import time
    now_ts = time.time()
    if not force and _cache["status"] and (now_ts - _cache["ts"]) < 300:
        return _cache["status"], _cache["info"]

    def _set(status, info):
        _cache["status"] = status
        _cache["info"] = info
        _cache["ts"] = now_ts
        return status, info

    empty = {"days_remaining": 0, "customer": "", "expires": "", "issued": ""}

    try:
        with open(LICENSE_FILE, "r") as f:
            license_key = f.read().strip()
    except FileNotFoundError:
        return _set("missing", empty)
    except Exception:
        return _set("invalid", empty)

    try:
        data = json.loads(base64.b64decode(license_key).decode())
    except Exception:
        return _set("invalid", empty)

    try:
        signature = data.pop("signature", None)
        if not signature:
            return _set("invalid", empty)

        # Rebuild payload with same sort/separators as generate_license.py
        payload = json.dumps(data, separators=(',', ':'), sort_keys=True)
        expected = hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()
        if signature != expected:
            return _set("invalid", empty)

        license_mac = data.get("mac", "").upper()
        if license_mac not in _get_all_macs():
            return _set("invalid", {**empty, "customer": data.get("customer", "")})

        expires_str = data.get("expires", "")

        # Lifetime license: expires == "9999-12-31"
        if expires_str == "9999-12-31":
            info = {
                "days_remaining": 99999,
                "customer": data.get("customer", ""),
                "expires": "Lifetime",
                "issued": data.get("issued", ""),
            }
            return _set("valid", info)

        expires_dt = datetime.strptime(expires_str, "%Y-%m-%d")
        days_remaining = (expires_dt - datetime.now()).days

        info = {
            "days_remaining": days_remaining,
            "customer": data.get("customer", ""),
            "expires": expires_str,
            "issued": data.get("issued", ""),
        }

        if days_remaining < 0:
            return _set("expired", info)
        elif days_remaining <= 30:
            return _set("expiring", info)
        else:
            return _set("valid", info)

    except Exception:
        return _set("invalid", empty)


def is_licensed():
    """True if license is valid or still within grace period (expiring)."""
    status, _ = validate_license()
    return status in ("valid", "expiring")
