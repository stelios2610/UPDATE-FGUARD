"""Data Loss Prevention (DLP) — custom patterns persisted in DB."""
import re
from datetime import datetime
from db import database

# ── Built-in sensitive data patterns ─────────────────────────────────────────
PATTERNS = {
    "Credit Card (Visa)":       (r"\b4[0-9]{12}(?:[0-9]{3})?\b",             "HIGH"),
    "Credit Card (MasterCard)": (r"\b5[1-5][0-9]{14}\b",                      "HIGH"),
    "Credit Card (Amex)":       (r"\b3[47][0-9]{13}\b",                       "HIGH"),
    "Social Security Number":   (r"\b\d{3}-\d{2}-\d{4}\b",                    "CRITICAL"),
    "IBAN":                     (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}[A-Z0-9]{0,16}\b", "HIGH"),
    "Email Address":            (r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "LOW"),
    "Phone Number (GR)":        (r"\b(?:69|2[0-9])\d{8}\b",                   "MEDIUM"),
    "Phone Number (Intl)":      (r"\+\d{1,3}[\s-]?\d{6,14}\b",               "LOW"),
    "IPv4 Address":             (r"\b(?:\d{1,3}\.){3}\d{1,3}\b",              "INFO"),
    "Password in URL":          (r"(?i)password=\S+",                          "HIGH"),
    "AWS Key":                  (r"AKIA[0-9A-Z]{16}",                          "CRITICAL"),
    "Private Key":              (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",  "CRITICAL"),
    "JWT Token":                (r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "HIGH"),
    "Greek AMKA":               (r"\b\d{11}\b",                                "HIGH"),
    "Greek AFM":                (r"\b\d{9}\b",                                 "MEDIUM"),
}

_enabled_patterns = set(PATTERNS.keys())


def scan_content(content, source="unknown"):
    """Scan text content for sensitive data patterns."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="ignore")

    findings = []
    for name, (pattern, severity) in PATTERNS.items():
        if name not in _enabled_patterns:
            continue
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                "pattern": name,
                "severity": severity,
                "count": len(matches),
                "samples": [_redact(m) for m in matches[:3]],
            })

    for cp in database.get_dlp_patterns():
        if not cp.get("enabled", 1):
            continue
        try:
            matches = re.findall(cp["pattern"], content)
            if matches:
                findings.append({
                    "pattern": cp["name"],
                    "severity": cp.get("severity", "MEDIUM"),
                    "count": len(matches),
                    "samples": [_redact(m) for m in matches[:3]],
                })
        except re.error:
            pass

    if findings:
        total = sum(f["count"] for f in findings)
        high  = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
        database.add_log(
            "BLOCK" if high else "WARN",
            src_ip=source, rule_name="DLP",
            details=f"DLP: {len(findings)} pattern types, {total} matches in {source}"
        )

    return findings


def _redact(match):
    s = str(match)
    if len(s) <= 4:
        return "****"
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


def add_custom_pattern(name, pattern, severity="MEDIUM", enabled=True):
    database.add_dlp_pattern(name, pattern, severity, 1 if enabled else 0)


def get_patterns():
    built_in = [{"name": k, "pattern": v[0], "severity": v[1],
                 "enabled": k in _enabled_patterns, "builtin": True}
                for k, v in PATTERNS.items()]
    custom = [{"builtin": False, **p} for p in database.get_dlp_patterns()]
    return built_in + custom


def set_pattern_enabled(name, enabled):
    if enabled:
        _enabled_patterns.add(name)
    else:
        _enabled_patterns.discard(name)


def scan_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return scan_content(content, source=path)
    except Exception:
        return []
