# ciphersweep/analysis/grading.py

from __future__ import annotations
from datetime import datetime
from typing import List

# helper weights
# weights are negative; start at 100.
W = {
    # protocol support
    "SSLv3": -100,  # automatic F
    "TLSv1.0": -30,
    "TLSv1.1": -20,
    "TLSv1.3 missing": -5,
    # cipher weaknesses
    "RC4": -40,
    "3DES/DES": -20,
    "NULL": -40,
    "EXPORT": -40,
    "CBC-Lucky13": -10,
    "Logjam": -25,
    # certificate
    "expired cert": -100,  # automatic F
    "expires soon": -10,
    "SHA1": -20,
    # BREACH
    "breach": -10,
}

# grade table
THRESH = (
    (100, "A+"),
    (95, "A"),
    (90, "A-"),
    (80, "B"),
    (65, "C"),
    (50, "D"),
    (0, "F"),
)


# public API
def grade_site(
    vulns: List[str],
    supported: dict,
    certificate: dict | None,
) -> str:
    score = 100

    # Protocol penalties
    if supported.get("SSLv3", {}).get("ok"):
        score += W["SSLv3"]  # F outright
    if supported.get("TLSv1", {}).get("ok"):
        score += W["TLSv1.0"]
    if supported.get("TLSv1.1", {}).get("ok"):
        score += W["TLSv1.1"]
    if "TLSv1.3" not in supported or not supported["TLSv1.3"].get("ok"):
        score += W["TLSv1.3 missing"]

    # Cipher vulnerabilities
    for v in vulns:
        if "RC4" in v:
            score += W["RC4"]
        elif "3DES" in v or "DES cipher" in v:
            score += W["3DES/DES"]
        elif "NULL cipher" in v:
            score += W["NULL"]
        elif "Export-grade" in v:
            score += W["EXPORT"]
        elif "Lucky13" in v:
            score += W["CBC-Lucky13"]
        elif "Logjam" in v:
            score += W["Logjam"]

    # Certificate penalties
    if certificate:
        if certificate.get("expired"):
            score += W["expired cert"]
        else:
            # "expires soon" if <30 d
            try:
                exp = datetime.strptime(certificate["expires"], "%Y-%m-%d")
                if (exp - datetime.utcnow()).days < 30:
                    score += W["expires soon"]
            except Exception:
                pass

        if certificate.get("sig_alg", "").lower().startswith("sha1"):
            score += W["SHA1"]

    # BREACH
    if any("BREACH" in v for v in vulns):
        score += W["breach"]

    # clamp
    score = max(0, score)

    # map to letter
    for threshold, letter in THRESH:
        if score >= threshold:
            return letter

    # fall-through never reached
    return "F"
