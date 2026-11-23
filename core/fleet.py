"""Read-only view of other FGUARD nodes. This does not push policy."""
import hmac
import urllib.parse
import urllib.request


def normalize_base_url(url):
    parsed = urllib.parse.urlparse((url or "").strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Node URL must start with http:// or https://")
    if parsed.username or parsed.password:
        raise ValueError("Node URL must not contain a password")
    host = parsed.hostname
    if not host or host == "169.254.169.254":
        raise ValueError("Node URL host is not allowed")
    port = parsed.port
    netloc = host if port is None else "%s:%s" % (host, port)
    return "%s://%s" % (parsed.scheme, netloc)


def token_matches(presented, expected):
    if not presented or not expected:
        return False
    return hmac.compare_digest(str(presented), str(expected))


def health_url(base_url):
    return normalize_base_url(base_url) + "/api/fleet/health"


def fetch_health(base_url, token, timeout=3):
    request = urllib.request.Request(
        health_url(base_url),
        headers={"X-FGUARD-Fleet": token, "User-Agent": "FGUARD"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        import json
        return json.loads(response.read().decode("utf-8", errors="replace"))
