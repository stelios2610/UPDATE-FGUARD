"""Commercial inspection pieces. Every switch stays off until an administrator enables it.

These are not a FortiGuard feed, a certified throughput number, or a full
management server. They add a signature file, application names, HTTPS
category matches, scanning of decrypted files, safer TLS exceptions, and a
policy push of the traffic switches.
"""
import io
import tarfile

APP_IDENTIFY = (
    ("Zoom", ("zoom.us", "zoom.com")),
    ("Microsoft365", ("office.com", "office365.com", "sharepoint.com")),
    ("Outlook", ("outlook.com", "outlook.office.com")),
    ("Teams", ("teams.microsoft.com", "teams.live.com")),
    ("OneDrive", ("onedrive.com", "1drv.com")),
    ("GoogleMeet", ("meet.google.com",)),
    ("Gmail", ("mail.google.com", "gmail.com")),
    ("GoogleDrive", ("drive.google.com", "docs.google.com")),
    ("WhatsApp", ("whatsapp.com", "whatsapp.net")),
    ("Telegram", ("telegram.org", "t.me")),
    ("Discord", ("discord.com", "discordapp.com")),
    ("Slack", ("slack.com", "slack-edge.com")),
    ("Dropbox", ("dropbox.com", "dropboxusercontent.com")),
    ("Adobe", ("adobe.com", "adobecc.com")),
    ("GitHub", ("github.com", "githubusercontent.com")),
    ("GitLab", ("gitlab.com",)),
    ("Amazon", ("amazon.com", "amazonaws.com")),
    ("AWS", ("aws.amazon.com",)),
    ("Azure", ("azure.com", "azureedge.net")),
    ("Cloudflare", ("cloudflare.com",)),
    ("TikTok", ("tiktok.com", "tiktokv.com")),
    ("Twitter", ("twitter.com", "x.com", "twimg.com")),
    ("Pinterest", ("pinterest.com",)),
    ("Wikipedia", ("wikipedia.org", "wikimedia.org")),
    ("ChatGPT", ("openai.com", "chatgpt.com")),
    ("Claude", ("claude.ai", "anthropic.com")),
    ("iCloud", ("icloud.com",)),
    ("iTunes", ("itunes.apple.com", "mzstatic.com")),
    ("PlayStation", ("playstation.com", "sonyentertainmentnetwork.com")),
    ("Xbox", ("xbox.com", "xboxlive.com")),
    ("EA", ("ea.com", "origin.com")),
    ("Epic", ("epicgames.com", "unrealengine.com")),
    ("Roblox", ("roblox.com",)),
    ("Snapchat", ("snapchat.com",)),
    ("Viber", ("viber.com",)),
    ("Webex", ("webex.com",)),
    ("AnyDesk", ("anydesk.com",)),
    ("TeamViewer", ("teamviewer.com",)),
    ("ZoomGov", ("zoomgov.com",)),
    ("Salesforce", ("salesforce.com", "force.com")),
)

POLICY_KEYS = (
    "traffic_ips_enabled",
    "traffic_categories_enabled",
    "traffic_av_enabled",
    "traffic_signatures_enabled",
    "traffic_appid_enabled",
    "traffic_https_categories_enabled",
    "traffic_av_decrypt_enabled",
)


def quic_rules(lan_ifaces):
    """Drop HTTP/3 so browsers fall back to TLS that inspection can see."""
    rules = []
    for lan in lan_ifaces or []:
        lan = (lan or "").strip()
        if not lan:
            continue
        rules.append([
            "-i", lan, "-p", "udp", "--dport", "443",
            "-m", "comment", "--comment", "fguard_quic", "-j", "DROP",
        ])
    return rules


def render_appid_rules(catalog=None):
    """Alert, do not drop, when a known application name is seen."""
    lines = ["# FGUARD application identification. Generated. Do not edit."]
    sid = 9300001
    for name, domains in (catalog or APP_IDENTIFY):
        label = str(name).replace('"', "")
        for domain in domains:
            domain = str(domain).strip().lower().rstrip(".")
            if len(domain) < 7 or "." not in domain or '"' in domain:
                continue
            lines.append(
                'alert tls any any -> any any (msg:"FGUARD app %s"; tls.sni; content:"%s"; '
                "nocase; sid:%d; rev:1;)" % (label, domain, sid)
            )
            sid += 1
    lines.append("")
    return "\n".join(lines)


def render_https_category_rules(domains, limit=8000):
    """Match category domains on the TLS name. Used only when HTTPS categories are enabled."""
    lines = ["# FGUARD HTTPS category matches. Generated. Do not edit."]
    sid = 9400001
    kept = 0
    for domain in domains or []:
        domain = str(domain).strip().lower().rstrip(".")
        if len(domain) < 7 or "." not in domain or '"' in domain:
            continue
        lines.append(
            'drop tls any any -> any any (msg:"FGUARD category %s"; tls.sni; content:"%s"; '
            "nocase; sid:%d; rev:1;)" % (domain, domain, sid)
        )
        sid += 1
        kept += 1
        if kept >= limit:
            break
    lines.append("")
    return "\n".join(lines)


def rule_file_list(signatures=False, appid=False, https_categories=False, protocols=False):
    names = ["fguard-apps.rules"]
    if appid:
        names.append("fguard-appid.rules")
    if protocols:
        names.append("fguard-proto.rules")
    if https_categories:
        names.append("fguard-https-categories.rules")
    if signatures:
        names.append("fguard-signatures.rules")
    return names


def extract_rules_from_tar(blob, max_bytes=8_000_000):
    """Pull .rules members out of an Emerging Threats archive. Skip unsafe paths."""
    pieces = []
    total = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    except Exception as exc:
        raise ValueError("signature archive is not a readable tar.gz") from exc
    with archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            name = str(member.name).replace("\\", "/")
            parts = [part for part in name.split("/") if part not in ("", ".")]
            if not parts or any(part == ".." for part in parts) or name.startswith("/"):
                continue
            if not parts[-1].endswith(".rules"):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            data = handle.read(max_bytes - total + 1)
            if not data:
                continue
            if total + len(data) > max_bytes:
                data = data[:max_bytes - total]
            total += len(data)
            pieces.append(data.decode("utf-8", errors="ignore"))
            if total >= max_bytes:
                break
    if not pieces:
        raise ValueError("signature archive contained no rules")
    return "\n".join(pieces)


def policy_snapshot(getter, app_names):
    body = {key: "1" if getter(key, "0") == "1" else "0" for key in POLICY_KEYS}
    apps = {}
    for name in app_names:
        apps[name] = "1" if getter("appblock_%s" % name, "0") == "1" else "0"
    body["apps"] = apps
    return body


def filter_policy(data, app_names):
    """Keep only traffic switches and known application blocks. HTTPS inspection cannot be turned on from here."""
    if not isinstance(data, dict):
        raise ValueError("policy must be an object")
    cleaned = {}
    for key in POLICY_KEYS:
        value = data.get(key, "0")
        if str(value) not in ("0", "1"):
            raise ValueError("policy values must be 0 or 1")
        cleaned[key] = "0" if key == "tls_inspect_enabled" and str(value) == "1" else str(value)
    allowed = set(app_names)
    apps = {}
    raw_apps = data.get("apps") or {}
    if not isinstance(raw_apps, dict):
        raise ValueError("policy apps must be an object")
    for name, value in raw_apps.items():
        if name not in allowed:
            continue
        if str(value) not in ("0", "1"):
            raise ValueError("policy values must be 0 or 1")
        apps[name] = str(value)
    cleaned["apps"] = apps
    if str(data.get("tls_inspect_enabled", "0")) == "1":
        cleaned["tls_refused"] = "1"
    return cleaned
