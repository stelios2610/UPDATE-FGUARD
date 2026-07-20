"""spamBlocker - Email spam detection (WatchGuard spamBlocker equivalent).
Uses SpamAssassin on Linux if available, else improved heuristic engine."""
import re
import subprocess
import os
import tempfile
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run

SPAM_THRESHOLD     = 5.0
SPAM_TAG_THRESHOLD = 3.0


def is_spamassassin_available():
    ok, _, _ = run(["spamc", "--version"])
    return ok


def ensure_spamassassin():
    """Install and start SpamAssassin if not present (Linux only)."""
    if not IS_LINUX:
        return False
    if is_spamassassin_available():
        return True
    database.add_log("INFO", details="SpamFilter: installing spamassassin...")
    run(["apt-get", "install", "-y", "spamassassin", "spamc"], timeout=120)
    run(["systemctl", "enable", "spamassassin"])
    run(["systemctl", "start",  "spamassassin"])
    return is_spamassassin_available()


def check_email_spamassassin(email_content: bytes) -> dict:
    """Check email via SpamAssassin spamc."""
    try:
        result = subprocess.run(
            ["spamc", "-E", "--max-size=2000000"],
            input=email_content, capture_output=True, timeout=30
        )
        output = result.stdout.decode("utf-8", errors="ignore")
        score  = _parse_score(output)
        is_spam = score >= SPAM_THRESHOLD
        if is_spam:
            database.add_log("BLOCK", details=f"SpamAssassin: score={score:.1f}")
        return {
            "is_spam":  is_spam,
            "score":    score,
            "threshold": SPAM_THRESHOLD,
            "engine":   "spamassassin",
            "report":   output[:500],
        }
    except Exception as e:
        return {"is_spam": False, "score": 0, "error": str(e), "engine": "spamassassin"}


def _parse_score(output):
    for line in output.splitlines():
        if "score=" in line.lower():
            m = re.search(r"score=([+-]?\d+\.?\d*)", line, re.IGNORECASE)
            if m:
                return float(m.group(1))
    return 0.0


# ── Heuristic spam scoring ────────────────────────────────────────────────────

SPAM_PATTERNS = [
    # Pharmaceutical
    (r"(?i)\bviagra\b",              2.0, "Pharmaceutical spam"),
    (r"(?i)\bcialis\b",              2.0, "Pharmaceutical spam"),
    (r"(?i)\bpharma\b",              1.5, "Pharmaceutical spam"),
    # Lottery / scam
    (r"(?i)\blottery\b",             2.5, "Lottery scam"),
    (r"(?i)\byou.?ve won\b",         3.0, "Lottery scam"),
    (r"(?i)\bcongratulations.*prize", 3.0, "Lottery scam"),
    (r"(?i)\bnigerian\b",            2.5, "419 scam"),
    (r"(?i)\badvance.?fee\b",        3.0, "419 scam"),
    (r"(?i)\binheritance\b",         2.0, "419 scam"),
    # Phishing
    (r"(?i)\bclick here\b",          1.0, "Phishing"),
    (r"(?i)\bverify your account\b", 2.5, "Phishing"),
    (r"(?i)\bsuspended\b.*\baccount\b", 2.5, "Account phishing"),
    (r"(?i)\bupdate your (password|billing|payment)\b", 2.5, "Phishing"),
    (r"(?i)\bconfirm your (identity|account|details)\b", 2.0, "Phishing"),
    (r"(?i)\bsecurity alert\b",      1.5, "Phishing"),
    # Financial scam
    (r"(?i)\bfree money\b",          3.0, "Scam"),
    (r"(?i)\bmake money fast\b",     3.0, "Scam"),
    (r"(?i)\b100% free\b",           1.5, "Spam"),
    (r"(?i)\bcash bonus\b",          2.0, "Scam"),
    (r"(?i)\bno risk\b",             1.5, "Scam"),
    (r"(?i)\bguaranteed (income|profit|return)\b", 2.5, "Financial scam"),
    (r"(?i)\bdouble your (money|income)\b", 3.0, "Financial scam"),
    # Job scam
    (r"(?i)\bwork from home\b",      1.5, "Job scam"),
    (r"(?i)\bearn \$\d+.*day\b",     2.5, "Job scam"),
    # Generic spam
    (r"(?i)\bact now\b",             1.0, "Urgency spam"),
    (r"(?i)\blimited time (offer|only)\b", 1.0, "Urgency spam"),
    (r"(?i)\bunsubscribe\b",         0.3, "Marketing"),
    (r"(?i)(\$\$\$|\b\d+%\s*off\b)", 1.0, "Commercial spam"),
    (r"(?i)\bspecial offer\b",       0.5, "Commercial spam"),
]


def check_email_heuristic(email_content: str) -> dict:
    """Improved heuristic-based spam scoring."""
    score   = 0.0
    matches = []

    for pattern, weight, label in SPAM_PATTERNS:
        if re.search(pattern, email_content):
            score  += weight
            matches.append(label)

    # Structural checks
    if email_content.count("!") > 5:
        score += 1.0; matches.append("Excessive exclamation marks")
    if re.search(r"[A-Z]{5,}", email_content):
        score += 0.5; matches.append("Excessive capitals")
    caps_ratio = sum(1 for c in email_content if c.isupper()) / max(len(email_content), 1)
    if caps_ratio > 0.3:
        score += 1.0; matches.append("High caps ratio")
    # Many URLs
    url_count = len(re.findall(r"https?://", email_content))
    if url_count > 5:
        score += 1.0; matches.append(f"Many URLs ({url_count})")
    # HTML with hidden text
    if re.search(r"(?i)font-size:\s*0|color:\s*white|display:\s*none", email_content):
        score += 2.0; matches.append("Hidden text (CSS)")
    # All caps subject
    subject_m = re.search(r"(?i)^subject:\s*(.+)$", email_content, re.MULTILINE)
    if subject_m and subject_m.group(1) == subject_m.group(1).upper() and len(subject_m.group(1)) > 5:
        score += 1.0; matches.append("All-caps subject")

    is_spam = score >= SPAM_THRESHOLD
    if is_spam:
        database.add_log("BLOCK", details=f"Spam heuristic: score={score:.1f}, matches={matches}")

    return {
        "is_spam":   is_spam,
        "score":     round(score, 1),
        "threshold": SPAM_THRESHOLD,
        "engine":    "heuristic",
        "matches":   matches,
    }


def check_email(email_content) -> dict:
    """Check email using SpamAssassin if available, else heuristic."""
    if isinstance(email_content, str):
        email_bytes = email_content.encode("utf-8", errors="ignore")
        email_str   = email_content
    else:
        email_bytes = email_content
        email_str   = email_content.decode("utf-8", errors="ignore")

    if is_spamassassin_available():
        return check_email_spamassassin(email_bytes)
    return check_email_heuristic(email_str)


def update_spamassassin():
    """Update SpamAssassin rules."""
    ensure_spamassassin()
    ok, out, err = run(["sa-update"], timeout=60)
    return ok, out if ok else err
