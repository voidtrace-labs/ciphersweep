# ciphersweep/io/network.py

import socket, ssl, asyncio, ipaddress, logging
from datetime import datetime, timezone
from ciphersweep.constants import CONNECTION_TIMEOUT
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

LOG = logging.getLogger(__name__)


def resolve_public_ip(host: str) -> str | None:
    try:
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_global:  # `is_global` excludes private, loopback, etc.
            return ip
        LOG.warning("%s resolved to non-public IP (%s) – skipping", host, ip)
    except Exception as exc:
        LOG.debug("DNS error for %s: %s", host, exc)
    return None


def get_certificate(host: str, port: int) -> dict | None:
    ctx = ssl._create_unverified_context()

    try:
        with socket.create_connection((host, port), timeout=CONNECTION_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der, default_backend())

        expires_dt = getattr(cert, "not_valid_after_utc", cert.not_valid_after)

        info = {
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "expires": expires_dt.strftime("%Y-%m-%d"),
            "expired": expires_dt < datetime.now(timezone.utc),
        }
        return info

    except Exception as exc:
        LOG.debug("cert fetch error for %s:%s – %s", host, port, exc)
        return None


async def breach_enabled(host: str, port: int) -> bool | None:
    sslctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.open_connection(
            host, port, ssl=sslctx, server_hostname=host
        )
        req = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            f"Accept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(1024), timeout=CONNECTION_TIMEOUT)
        writer.close()
        await writer.wait_closed()
        headers = raw.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
        return any("content-encoding:" in h.lower() for h in headers.split("\r\n"))
    except Exception as exc:
        LOG.debug("BREACH check error on %s:%s – %s", host, port, exc)
        return None
