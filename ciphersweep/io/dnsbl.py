# ciphersweep/io/dnsbl.py

from __future__ import annotations

import ipaddress
import logging
import socket
from functools import lru_cache
from typing import Final, Optional

LOG = logging.getLogger(__name__)

DNSBL_ZONE: Final[str] = "zen.spamhaus.org"
DNS_TIMEOUT: Final[int] = 2  # seconds


def _reverse_ipv4(ip: ipaddress.IPv4Address) -> str:
    return ".".join(reversed(ip.exploded.split(".")))


def _reverse_ipv6(ip: ipaddress.IPv6Address) -> str:
    # Expand, drop colons, and reverse nybbles as per RFC 5782.
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".ip6.arpa"


@lru_cache(maxsize=2048)
def _query(bl_lookup: str) -> Optional[bool]:
    try:
        # `gethostbyname` raises `socket.gaierror` if NXDOMAIN,
        # which we map to False (“not listed”).
        socket.gethostbyname(bl_lookup)
        return True
    except socket.gaierror:
        return False
    except Exception as exc:
        LOG.debug("DNSBL lookup failed for %s – %s", bl_lookup, exc)
        return None


def listed(ip: str, zone: str = DNSBL_ZONE) -> Optional[bool]:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        LOG.debug("dnsbl.listed: %s is not a valid IP address", ip)
        return None

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        # Silently skip non-global addresses.
        return None

    if isinstance(ip_obj, ipaddress.IPv4Address):
        lookup = f"{_reverse_ipv4(ip_obj)}.{zone}"
    else:  # IPv6
        lookup = f"{_reverse_ipv6(ip_obj)}.{zone}"

    return _query(lookup)
