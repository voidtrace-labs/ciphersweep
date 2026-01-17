# ciphersweep/scan/runner.py

import asyncio, logging
from tqdm.asyncio import tqdm_asyncio

from pathlib import Path
from typing import List, Tuple

from tqdm import tqdm

from ciphersweep.scan.host_scan import scan_host

LOG = logging.getLogger(__name__)


async def run_all(
    targets: List[Tuple[str, int]],
    *,
    host_concurrency: int,
    openssl_prefix: Path,
    dnsbl: bool = False,
    breach: bool = False,
):

    sem = asyncio.Semaphore(host_concurrency)

    async def limited(host: str, port: int):
        async with sem:
            return await scan_host(host, port, openssl_prefix, dnsbl, breach)

    coros = [limited(h, p) for h, p in targets]

    results = []
    with tqdm(total=len(coros), desc="Scanning Hosts") as bar:
        for fut in asyncio.as_completed(coros):
            try:
                res = await fut
                if res:
                    results.append(res)
            finally:
                bar.update(1)

    return results
