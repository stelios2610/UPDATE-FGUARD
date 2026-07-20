"""Multi-Factor Authentication - TOTP (WatchGuard AuthPoint equivalent).
Compatible with Google Authenticator, Authy, etc."""
import os
import time
import hmac
import hashlib
import struct
import base64
import secrets
import qrcode
import io
from db import database


def generate_secret():
    """Generate a new TOTP secret key."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8")


def get_totp_code(secret, timestamp=None):
    """Generate current TOTP code."""
    secret = secret.upper().replace(" ", "")
    key = base64.b32decode(secret, casefold=True)
    ts = int((timestamp or time.time()) / 30)
    msg = struct.pack(">Q", ts)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0xF
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)


def verify_totp(secret, user_code, window=1):
    """Verify TOTP code with ±window time steps tolerance."""
    now = int(time.time() / 30)
    for ts_offset in range(-window, window + 1):
        expected = get_totp_code(secret, (now + ts_offset) * 30)
        if hmac.compare_digest(expected, str(user_code).zfill(6)):
            return True
    return False


def get_qr_code_bytes(username, secret, issuer="FGUARD UTC"):
    """Generate QR code image bytes for authenticator app setup."""
    uri = f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def get_qr_code_uri(username, secret, issuer="FGUARD UTC"):
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def enable_mfa_for_user(user_id):
    """Generate and store MFA secret for user."""
    secret = generate_secret()
    database.update_user(user_id, password_hash=f"mfa:{secret}")
    return secret


def is_mfa_required():
    return database.get_setting("mfa_required", "0") == "1"


def hash_password(password):
    """Hash a password with SHA-256 + salt."""
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"sha256:{salt}:{h}"


def verify_password(password, password_hash):
    """Verify a password against stored hash."""
    if not password_hash or ":" not in password_hash:
        return False
    if password_hash.startswith("sha256:"):
        _, salt, stored = password_hash.split(":", 2)
        h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
        return hmac.compare_digest(h, stored)
    return False
