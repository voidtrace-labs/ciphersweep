# ciphersweep/scan/host_scan.py

import asyncio, logging
from pathlib import Path
from ciphersweep.io import network, dnsbl as dnsbl_io
from ciphersweep.scan.cipher_scan import probe_version
from ciphersweep.analysis.vulnerabilities import analyse
from ciphersweep.analysis.grading import grade_site
from ciphersweep.models import HostScan

LOG = logging.getLogger(__name__)


async def scan_host(
    host: str,
    port: int,
    openssl_prefix: Path,
    dnsbl: bool,
    breach: bool,
) -> HostScan | None:

    LOG.info("→ starting scan for %s:%s", host, port)
    ip = network.resolve_public_ip(host)
    if not ip:
        return None

    task_map: dict[str, asyncio.Future] = {
        ver: probe_version(host, port, ver, openssl_prefix)
        for ver in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
    }

    task_map["cert"] = asyncio.to_thread(network.get_certificate, host, port)

    if breach:
        task_map["breach"] = network.breach_enabled(host, port)

    if dnsbl:
        task_map["dnsbl"] = asyncio.to_thread(dnsbl_io.listed, ip)

    done = await asyncio.gather(*task_map.values(), return_exceptions=False)
    results = dict(zip(task_map.keys(), done))

    supported = {
        ver: results[ver] for ver in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
    }

    vulns = analyse(supported, results["cert"], results.get("breach"))

    letter = grade_site(vulns, supported, results["cert"])

    scan = HostScan(
        host=host,
        ip=ip,
        port=port,
        dnsbl_listed=results.get("dnsbl"),
        certificate=results["cert"],
        http_compression=results.get("breach"),
        supported_ciphers=supported,
        vulnerabilities=vulns,
        grade=letter,
    )

    LOG.info("← finished %s:%s – %d vulns", host, port, len(scan.vulnerabilities))
    return scan
