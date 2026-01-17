# ciphersweep/scan/cipher_scan.py

import asyncio, logging
from pathlib import Path
from ciphersweep.constants import TLS_FLAGS, load_cipher_matrix
from ciphersweep.io.openssl import run_openssl
from ciphersweep.models import CipherResult

LOG = logging.getLogger(__name__)
CIPHER_MATRIX = load_cipher_matrix()


async def probe_version(
    host: str,
    port: int,
    version: str,
    openssl_prefix: Path,
) -> dict[str, list[str]]:

    tls_flag = TLS_FLAGS[version]
    use_cs = version == "TLSv1.3"

    results_by_status: dict[str, list[str]] = {
        "ok": [],
        "fail": [],
        "unsupported": [],
        "timeout": [],
        "error": [],
    }

    tasks: list[asyncio.Task[CipherResult]] = []
    for cipher, builds in CIPHER_MATRIX[version].items():
        if not builds:
            results_by_status["unsupported"].append(cipher)
            continue

        openssl_bin = openssl_prefix / builds[0] / "bin" / "openssl"
        tasks.append(
            asyncio.create_task(
                run_openssl(
                    host,
                    port,
                    tls_flag,
                    cipher,
                    openssl_bin=openssl_bin,
                    use_ciphersuites=use_cs,
                )
            )
        )

    if tasks:
        for res in await asyncio.gather(*tasks, return_exceptions=False):
            results_by_status[res.status].append(res.cipher)

    return results_by_status
