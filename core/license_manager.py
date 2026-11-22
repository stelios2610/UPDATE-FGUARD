"""FGUARD License Manager — validates license key on the deployed appliance.

The appliance holds only the public key. Licenses are signed with an Ed25519
private key that stays on the machine that issues them.
"""
import json
import base64
import os
import subprocess
import tempfile
from datetime import datetime

LICENSE_FILE = "/etc/fguard/license.key"
LICENSE_FILE_LEGACY = "/etc/aegisguard/license.key"

# Public key only. The matching private key is not in this repository.
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAf8x766A9pxVirD8SODpUAnFJJDEmZPdy0kt+LrSnNbg=
-----END PUBLIC KEY-----
"""

_cache = {"status": None, "info": None, "ts": 0}


def canonical_payload(data):
    """Bytes that were signed. Field set and encoding must match the generator."""
    body = {
        "customer": str(data.get("customer", "")).strip(),
        "expires": str(data.get("expires", "")),
        "issued": str(data.get("issued", "")),
        "mac": str(data.get("mac", "")).upper().strip(),
        "v": 2,
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


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


def _signature_ok(payload, signature):
    """True when signature is an Ed25519 signature of payload by our private key."""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    try:
        with tempfile.TemporaryDirectory() as tmp:
            pub = os.path.join(tmp, "pub.pem")
            msg = os.path.join(tmp, "msg.bin")
            sig = os.path.join(tmp, "sig.bin")
            with open(pub, "w", newline="\n") as handle:
                handle.write(PUBLIC_KEY_PEM.strip() + "\n")
            with open(msg, "wb") as handle:
                handle.write(payload)
            with open(sig, "wb") as handle:
                handle.write(bytes(signature))
            result = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub,
                    "-rawin", "-in", msg, "-sigfile", sig,
                ],
                capture_output=True,
            )
            return result.returncode == 0
    except Exception:
        return False


def inspect_key(license_key, macs):
    """Validate one license blob against an explicit set of MAC addresses."""
    empty = {"days_remaining": 0, "customer": "", "expires": "", "issued": ""}
    try:
        data = json.loads(base64.b64decode(license_key).decode())
    except Exception:
        return "invalid", empty

    try:
        if data.get("v") != 2:
            return "invalid", empty
        signature_b64 = data.get("signature")
        if not signature_b64:
            return "invalid", empty
        signature = base64.b64decode(signature_b64, validate=True)
        if not _signature_ok(canonical_payload(data), signature):
            return "invalid", empty

        license_mac = str(data.get("mac", "")).upper()
        if license_mac not in macs:
            return "invalid", {**empty, "customer": data.get("customer", "")}

        expires_str = data.get("expires", "")
        if expires_str == "9999-12-31":
            info = {
                "days_remaining": 99999,
                "customer": data.get("customer", ""),
                "expires": "Lifetime",
                "issued": data.get("issued", ""),
            }
            return "valid", info

        expires_dt = datetime.strptime(expires_str, "%Y-%m-%d")
        days_remaining = (expires_dt - datetime.now()).days
        info = {
            "days_remaining": days_remaining,
            "customer": data.get("customer", ""),
            "expires": expires_str,
            "issued": data.get("issued", ""),
        }
        if days_remaining < 0:
            return "expired", info
        if days_remaining <= 30:
            return "expiring", info
        return "valid", info
    except Exception:
        return "invalid", empty


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
    license_key = ""
    for path in (LICENSE_FILE, LICENSE_FILE_LEGACY):
        try:
            with open(path, "r") as handle:
                license_key = handle.read().strip()
            if license_key:
                break
        except FileNotFoundError:
            continue
        except Exception:
            return _set("invalid", empty)
    if not license_key:
        return _set("missing", empty)

    status, info = inspect_key(license_key, _get_all_macs())
    return _set(status, info)


def is_licensed():
    """True if license is valid or still within grace period (expiring)."""
    status, _ = validate_license()
    return status in ("valid", "expiring")
