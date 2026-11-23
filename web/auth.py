"""FGUARD session-based authentication (no extra dependencies)."""
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from db import database

try:
    import bcrypt as _bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False

# In-memory session store: {token: {"user": str, "expires": datetime}}
_sessions: dict = {}

COOKIE_NAME = "fguard_session"
SESSION_HOURS = 8
MUST_CHANGE_KEY = "admin_must_change_password"
FACTORY_PASSWORDS = {"admin", "FGUARD" + "2024!", "FGuard" + "2024!"}

# Routes that don't require login
PUBLIC_ROUTES = {"/login", "/favicon.ico"}
# Reachable while the factory password is still in place.
SETUP_ROUTES = {"/account/password", "/logout", "/api/settings/change-password"}
SENSITIVE_SETTINGS = {
    "admin_password_hash",
    "admin_must_change_password",
    "admin_mfa_secret",
    "admin_mfa_pending",
    "fleet_token",
}

# Only the admin (settings-based) can log in — multi-user auth_users table
# entries are stored but cannot log in through the standard login flow.
# This enforces single-admin control over all GUI operations.

# ── Login rate limiting ───────────────────────────────────────────────────────
_login_attempts: dict = {}   # {ip: [datetime, ...]}
_LOGIN_MAX = 10
_LOGIN_WINDOW = 60           # seconds


def is_rate_limited(ip: str) -> bool:
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=_LOGIN_WINDOW)
    attempts = [t for t in _login_attempts.get(ip, []) if t > cutoff]
    attempts.append(now)
    _login_attempts[ip] = attempts
    return len(attempts) > _LOGIN_MAX


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    if _BCRYPT_OK:
        hashed = _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12))
        return f"bcrypt:{hashed.decode()}"
    # Fallback to sha256 if bcrypt not available
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"sha256:{salt}:{h}"


def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False
    try:
        if stored_hash.startswith("bcrypt:"):
            if not _BCRYPT_OK:
                return False
            stored = stored_hash[7:].encode()
            return _bcrypt.checkpw(password.encode(), stored)
        # Legacy sha256 format
        algo, salt, h = stored_hash.split(":", 2)
        return hmac.compare_digest(
            hashlib.sha256(f"{salt}{password}".encode()).hexdigest(), h
        )
    except Exception:
        return False


def ensure_default_admin():
    """Create default admin if no password is set. The UI stays locked until it changes."""
    current = database.get_setting("admin_password_hash", "")
    if not current:
        database.set_setting("admin_password_hash", hash_password("admin"))
        database.set_setting("admin_username", "admin")
        database.set_setting(MUST_CHANGE_KEY, "1")


def password_change_required():
    """True until the factory admin password has been replaced."""
    flag = database.get_setting(MUST_CHANGE_KEY, "")
    if flag == "1":
        return True
    if flag == "0":
        return False
    stored = database.get_setting("admin_password_hash", "")
    required = verify_password("admin", stored)
    database.set_setting(MUST_CHANGE_KEY, "1" if required else "0")
    return required


def change_admin_password(current, new):
    """Replace the admin password. Returns (ok, message)."""
    if not new or len(new) < 8:
        return False, "Password must be at least 8 characters"
    if new in FACTORY_PASSWORDS or new.lower() == "admin":
        return False, "Choose a password that is not the factory password"
    stored_hash = database.get_setting("admin_password_hash", "")
    if not verify_password(current, stored_hash):
        return False, "Current password is incorrect"
    database.set_setting("admin_password_hash", hash_password(new))
    database.set_setting(MUST_CHANGE_KEY, "0")
    return True, "ok"


def sensitive_setting(key):
    text = str(key)
    return text in SENSITIVE_SETTINGS or text.startswith("session:")


def filter_settings_update(data):
    """Drop keys that would bypass the password gate or steal a session."""
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if not sensitive_setting(key)}


# ── Session management ────────────────────────────────────────────────────────

def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(hours=SESSION_HOURS)
    # Memory store
    _sessions[token] = {"user": username, "expires": expires}
    # DB store — persists across restarts
    try:
        database.set_setting(f"session:{token}", f"{username}|{expires.isoformat()}")
    except Exception:
        pass
    _cleanup_sessions()
    return token


def _load_session_from_db(token: str) -> Optional[dict]:
    try:
        val = database.get_setting(f"session:{token}", "")
        if not val or "|" not in val:
            return None
        user, exp_str = val.split("|", 1)
        exp = datetime.fromisoformat(exp_str)
        if datetime.utcnow() > exp:
            database.set_setting(f"session:{token}", "")
            return None
        return {"user": user, "expires": exp}
    except Exception:
        return None


def get_session_user(request: Request) -> Optional[str]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    # Check memory first
    session = _sessions.get(token)
    if not session:
        # Try DB (e.g. after service restart)
        session = _load_session_from_db(token)
        if session:
            _sessions[token] = session
    if not session:
        return None
    if datetime.utcnow() > session["expires"]:
        _sessions.pop(token, None)
        return None
    return session["user"]


def delete_session(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        _sessions.pop(token, None)
        try:
            database.set_setting(f"session:{token}", "")
        except Exception:
            pass


def _cleanup_sessions():
    now = datetime.utcnow()
    expired = [t for t, s in _sessions.items() if now > s["expires"]]
    for t in expired:
        _sessions.pop(t, None)


# ── Auth check (use as dependency or middleware) ──────────────────────────────

def require_auth(request: Request):
    """Returns redirect or 401 JSON if not authenticated, else None."""
    from fastapi.responses import JSONResponse
    path = request.url.path
    if path in PUBLIC_ROUTES or path.startswith("/static") or path in ("/api/fleet/health", "/api/fleet/policy"):
        return None
    if get_session_user(request) is None:
        # API calls get 401 JSON — so JS can detect and redirect
        if path.startswith("/api/"):
            return JSONResponse({"detail": "Session expired"}, status_code=401)
        safe_next = path if path.startswith("/") and not path.startswith("//") else "/"
        return RedirectResponse(url=f"/login?next={safe_next}", status_code=302)
    if password_change_required() and path not in SETUP_ROUTES:
        if path.startswith("/api/"):
            return JSONResponse(
                {"detail": "Change the factory password before using the firewall."},
                status_code=403,
            )
        return RedirectResponse(url="/account/password", status_code=302)
    if path == "/account/password" and not password_change_required():
        return RedirectResponse(url="/settings", status_code=302)
    return None


# ── Login / logout logic ──────────────────────────────────────────────────────

def attempt_login(username: str, password: str, otp: str = "") -> bool:
    stored_user = database.get_setting("admin_username", "admin")
    stored_hash = database.get_setting("admin_password_hash", "")
    if username != stored_user:
        return False
    if not verify_password(password, stored_hash):
        return False
    secret = database.get_setting("admin_mfa_secret", "") or ""
    if not secret:
        return True
    from core.mfa import verify_totp
    return verify_totp(secret, otp or "")
