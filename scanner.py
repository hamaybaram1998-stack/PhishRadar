"""Offline, heuristic phishing URL risk scanner."""
from urllib.parse import urlsplit
import ipaddress
import re

SUSPICIOUS_TERMS = {"verify", "password", "secure", "account", "update", "login", "wallet", "urgent"}

def scan_url(url: str) -> dict:
    """Return an explainable risk score (0-100) for URL *text* only."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("A nonempty URL is required")
    url = url.strip()
    parsed = urlsplit(url if "://" in url else "https://" + url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Provide a valid HTTP(S) URL")
    host = parsed.hostname.lower()
    score, reasons = 0, []
    def flag(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(reason)
    if parsed.scheme.lower() == "http":
        flag(20, "Uses unencrypted HTTP")
    try:
        ipaddress.ip_address(host)
        flag(30, "Host is an IP address rather than a domain")
    except ValueError:
        pass
    if "xn--" in host:
        flag(25, "Internationalized (punycode) hostname")
    if host.count(".") >= 3:
        flag(15, "Many hostname subdomains")
    if "@" in parsed.netloc:
        flag(35, "URL contains an @ sign that can disguise the destination")
    if len(url) > 100:
        flag(15, "Unusually long URL")
    if re.search(r"\b(" + "|".join(sorted(SUSPICIOUS_TERMS)) + r")\b", (parsed.path + " " + parsed.query).lower()):
        flag(10, "Contains common account or urgency keywords")
    score = min(score, 100)
    level = "high" if score >= 60 else "medium" if score >= 30 else "low"
    return {"url": url, "hostname": host, "risk_score": score, "risk_level": level, "reasons": reasons, "note": "Heuristic assessment only; low risk does not guarantee safety."}
