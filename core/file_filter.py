"""FortiGate-style File Filter — inspect uploaded/downloaded files by type.

Policies live in the DB. On-demand submit scans a file (type + ClamAV + DLP)
the way FortiGate File Filter / FortiSandbox file upload works. Inline HTTPS
body inspection is not done here (needs SSL bump / proxy).
"""
import os
from db import database
from core import gateway_av, dlp

MAX_BYTES = 32 * 1024 * 1024

KNOWN_TYPES = [
    "exe", "dll", "sys", "scr", "com", "bat", "cmd", "msi", "ps1",
    "js", "vbs", "wsf", "hta", "jar",
    "zip", "rar", "7z", "gz", "iso",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "elf", "apk",
]

_MAGIC = [
    (b"MZ", "exe"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\x7fELF", "elf"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
]


def _ext(name):
    base = os.path.basename(name or "").rsplit(".", 1)
    if len(base) == 2:
        return base[1].lower().strip()
    return ""


def _magic_type(data: bytes):
    if not data:
        return ""
    head = data[:16]
    for sig, kind in _MAGIC:
        if head.startswith(sig):
            return kind
    return ""


def _rule_types(rule):
    raw = (rule.get("file_types") or "").replace(";", ",").lower()
    return {t.strip().lstrip(".") for t in raw.split(",") if t.strip()}


def match_file(filename, data=b"", direction="upload"):
    """Return the first matching enabled File Filter rule, or None."""
    if database.get_setting("file_filter_enabled", "1") != "1":
        return None
    ext = _ext(filename)
    mag = _magic_type(data)
    kinds = {k for k in (ext, mag) if k}
    if mag == "ole":
        kinds.update({"doc", "xls", "ppt"})
    if mag == "zip":
        kinds.update({"zip", "docx", "xlsx", "pptx", "jar", "apk"})
    if mag == "exe":
        kinds.update({"exe", "dll", "sys", "scr", "com"})
    direction = (direction or "upload").lower()
    for rule in database.get_file_filter_rules():
        if not rule.get("enabled"):
            continue
        rdir = (rule.get("direction") or "both").lower()
        if rdir not in ("both", "any", direction):
            continue
        types = _rule_types(rule)
        if types & kinds:
            return rule
    return None


def inspect(filename, data, direction="upload"):
    """Full inspect: file filter + ClamAV + DLP. Never raises."""
    name = filename or "upload"
    size = len(data or b"")
    ext = _ext(name)
    mag = _magic_type(data or b"")
    result = {
        "filename": name,
        "size": size,
        "extension": ext,
        "detected_type": mag or ext or "unknown",
        "direction": direction,
        "action": "allow",
        "blocked": False,
        "reasons": [],
        "rule": None,
        "av_clean": True,
        "av_threat": "",
        "dlp": [],
    }
    if size > MAX_BYTES:
        result["blocked"] = True
        result["action"] = "block"
        result["reasons"].append(f"File larger than {MAX_BYTES // (1024 * 1024)} MB")
        return result

    rule = match_file(name, data or b"", direction)
    if rule and (rule.get("action") or "block").lower() == "block":
        result["blocked"] = True
        result["action"] = "block"
        result["rule"] = rule.get("name")
        result["reasons"].append(
            f"File Filter '{rule.get('name')}' blocks type {result['detected_type']}"
        )
    elif rule:
        result["rule"] = rule.get("name")
        result["reasons"].append(f"File Filter '{rule.get('name')}' matched (log)")

    try:
        clean, threat = gateway_av.scan_bytes(data or b"", name)
        result["av_clean"] = bool(clean)
        result["av_threat"] = threat or ""
        if not clean:
            result["blocked"] = True
            result["action"] = "block"
            result["reasons"].append(f"AntiVirus: {threat}")
    except Exception:
        pass

    text_like = ext in ("txt", "csv", "log", "json", "xml", "html", "htm", "eml", "md")
    if text_like and mag not in ("exe", "elf", "zip", "7z", "rar"):
        try:
            sample = (data or b"")[:200000].decode("utf-8", errors="ignore")
            if sample.strip():
                findings = dlp.scan_content(sample, source="file-filter")
                result["dlp"] = findings or []
                if findings:
                    result["reasons"].append("DLP pattern matched")
        except Exception:
            pass

    database.add_file_filter_submission(
        filename=name,
        size=size,
        detected_type=result["detected_type"],
        action=result["action"],
        details="; ".join(result["reasons"]) or "clean",
    )
    if result["blocked"]:
        database.add_log(
            "BLOCK",
            rule_name="File Filter",
            details=f"{name}: {result['reasons']}",
        )
    return result


def seed_defaults():
    if database.get_file_filter_rules():
        return
    database.add_file_filter_rule(
        name="Block Windows executables (upload)",
        direction="upload",
        action="block",
        file_types="exe,dll,sys,scr,com,bat,cmd,msi,ps1",
        protocols="HTTP,HTTPS,FTP",
        enabled=1,
    )
    database.add_file_filter_rule(
        name="Block script droppers (upload)",
        direction="upload",
        action="block",
        file_types="js,vbs,wsf,hta,jar",
        protocols="HTTP,HTTPS,FTP",
        enabled=1,
    )
