# ciphersweep/analysis/vulnerabilities.py

from __future__ import annotations

from datetime import datetime
from typing import List


# helpers
def _contains(cipher_list: list[str], *needles: str) -> bool:
    return any(n in c for c in cipher_list for n in needles)


def _cbc_cipher(name: str) -> bool:
    n = name.upper()
    # AEAD & stream suites are fine
    return all(x not in n for x in ("GCM", "POLY1305", "CCM", "RC4", "CHACHA"))


# main API
def analyse(
    supported_ciphers: dict,
    certificate: dict | None,
    http_compression: bool | None,
) -> List[str]:
    vulns: list[str] = []
    seen: set[str] = set()  # avoid duplicates

    def add(msg: str):
        if msg not in seen:
            seen.add(msg)
            vulns.append(msg)

    # protocol level
    if supported_ciphers.get("SSLv2", {}).get("ok"):
        add("SSLv2 supported (insecure)")
    if supported_ciphers.get("SSLv3", {}).get("ok"):
        add("SSLv3 supported (POODLE, insecure)")
    if supported_ciphers.get("TLSv1", {}).get("ok"):
        add("TLSv1.0 supported (deprecated, BEAST/CVE-2011-3389)")
    if supported_ciphers.get("TLSv1.1", {}).get("ok"):
        add("TLSv1.1 supported (deprecated)")
    if "TLSv1.3" not in supported_ciphers or not supported_ciphers["TLSv1.3"].get("ok"):
        add("TLSv1.3 not offered")

    # cipher-suite findings (per TLS version)
    for ver, buckets in supported_ciphers.items():
        ok = buckets.get("ok", [])
        if _contains(ok, "RC4-"):
            add("RC4 cipher offered (barred by RFC 7465)")
        if _contains(ok, "3DES", "DES-CBC3") or _contains(ok, "DES-"):
            add("3DES/DES cipher offered (SWEET32 / obsolete)")
        if _contains(ok, "NULL-"):
            add("NULL cipher offered (no encryption)")
        if _contains(ok, "-EXP-") or _contains(ok, "EXPORT"):
            add("Export-grade cipher offered")
        # Logjam: plain-DH (not ECDHE) in DH_* or DHE_* except those that start with E
        if any(
            c.startswith(("DH-", "DHE-")) and not c.startswith("DHE-RSA") for c in ok
        ):
            add("Potential Logjam – non-ECDHE DH cipher offered")

        # CBC-only suites prior to TLS 1.2 → Lucky13
        if ver in ("TLSv1.0", "TLSv1.1", "TLSv1.2") and any(_cbc_cipher(c) for c in ok):
            add("CBC suites on {} (Lucky13 risk)".format(ver))

    # certificate checks
    if certificate:
        if certificate.get("expired"):
            add("Certificate expired")
        # allow optional SHA-1 detection if caller provided sig_alg
        if certificate.get("sig_alg", "").lower().startswith("sha1"):
            add("Certificate signed with SHA-1 (weak)")

        # warn if cert expires soon (<30 days)
        try:
            exp = datetime.strptime(certificate["expires"], "%Y-%m-%d")
            if exp < datetime.utcnow():
                pass  # already flagged as expired
            elif (exp - datetime.utcnow()).days < 30:
                add("Certificate expires within 30 days")
        except Exception:
            pass  # ignore parse issues

    # HTTP compression (BREACH)
    if http_compression is True:
        add("HTTP compression enabled (BREACH)")

    return vulns
