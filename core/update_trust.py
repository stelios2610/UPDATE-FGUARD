"""Verify an OTA manifest before any update bytes are kept.

The appliance trusts one Ed25519 public key, the same key that signs licenses.
The private key stays on the machine that publishes updates. A manifest is the
canonical JSON of version, date, changelog, https URL, and the archive sha256.
"""
import hashlib
import json
import os
import base64
import stat
import zipfile

from core.license_manager import PUBLIC_KEY_PEM, verify_ed25519


def canonical_manifest(data):
    """Bytes that were signed. Field set and encoding must match sign_update.py."""
    changelog = data.get("changelog") or []
    if not isinstance(changelog, list):
        raise ValueError("update changelog must be a list")
    body = {
        "changelog": [str(item) for item in changelog],
        "date": str(data.get("date", "")),
        "sha256": str(data.get("sha256", "")).lower(),
        "url": str(data.get("url", "")),
        "version": str(data.get("version", "")),
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def parse_signature(text):
    """Decode a one-line base64 Ed25519 signature."""
    if isinstance(text, bytes):
        text = text.decode("ascii", errors="replace")
    raw = "".join(str(text).split())
    try:
        signature = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError("update signature is not valid base64") from exc
    if len(signature) != 64:
        raise ValueError("update signature has an unexpected length")
    return signature


def manifest_trusted(document, signature, public_key_pem=None):
    """Return the manifest dict when the signature matches the canonical bytes."""
    if isinstance(document, bytes):
        data = json.loads(document.decode())
    else:
        data = document
    if not isinstance(data, dict):
        raise ValueError("update manifest must be a JSON object")
    payload = canonical_manifest(data)
    if not verify_ed25519(payload, signature, public_key_pem or PUBLIC_KEY_PEM):
        raise ValueError("update signature is not valid")
    trusted = json.loads(payload.decode())
    sha = trusted["sha256"]
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise ValueError("signed update manifest has no sha256")
    if not trusted["url"].startswith("https://"):
        raise ValueError("signed update URL must be https")
    if not trusted["version"]:
        raise ValueError("signed update manifest has no version")
    return trusted


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archive(zip_path, manifest, signature, public_key_pem=None):
    """Raise ValueError unless the zip matches a trusted manifest."""
    trusted = manifest_trusted(manifest, signature, public_key_pem)
    actual = sha256_file(zip_path)
    if actual != trusted["sha256"]:
        raise ValueError("update archive does not match the signed checksum")
    return trusted


def unsafe_archive_name(name):
    normalized = str(name).replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        return True
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    return any(part == ".." for part in parts)


def assert_archive_safe(archive):
    """Reject path traversal and symlinks before extract."""
    for info in archive.infolist():
        if unsafe_archive_name(info.filename):
            raise ValueError("update archive contains an unsafe path")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError("update archive contains a symlink")


def safe_extract(zip_path, dest):
    """Extract zip_path into dest. Refuse to leave that directory."""
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path, "r") as archive:
        assert_archive_safe(archive)
        archive.extractall(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                raise ValueError("update archive extracted a symlink")
            real = os.path.realpath(path)
            if real != root and not real.startswith(root + os.sep):
                raise ValueError("update archive escaped its directory")
