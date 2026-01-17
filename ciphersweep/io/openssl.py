# ciphersweep/io/openssl.py

import asyncio, os, signal, time, logging, contextlib
from pathlib import Path
from ciphersweep.models import CipherResult
from ciphersweep.constants import CONNECTION_TIMEOUT

LOG = logging.getLogger(__name__)


# global limit (defaults to 32 – can be resized from the CLI via
# ciphersweep.io.openssl.set_openssl_limit)
_OPENSSL_SEM = asyncio.Semaphore(32)


def set_openssl_limit(max_parallel: int) -> None:
    """Resize the global semaphore that guards openssl subprocesses."""
    global _OPENSSL_SEM
    _OPENSSL_SEM = asyncio.Semaphore(max_parallel)


# Max bytes to keep per stream (stdout/stderr). We still DRAIN beyond this cap
# to prevent backpressure, but we DISCARD extra bytes to avoid RAM blowups.
_OUTPUT_CAP = 1_000_000  # 1 MB; tune as you like
_READ_CHUNK = 16_384  # 16 KiB


async def run_openssl(
    host: str,
    port: int,
    tls_flag: str,
    cipher: str,
    *,
    openssl_bin: Path,
    use_ciphersuites: bool,
) -> CipherResult:
    args = [
        str(openssl_bin),
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        tls_flag,
        "-ciphersuites" if use_ciphersuites else "-cipher",
        cipher,
    ]

    async with _OPENSSL_SEM:
        start = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        stdout_buf = bytearray()
        stderr_buf = bytearray()

        async def drain(reader: asyncio.StreamReader, buf: bytearray, label: str):
            try:
                while True:
                    chunk = await reader.read(_READ_CHUNK)
                    if not chunk:
                        break
                    if len(buf) < _OUTPUT_CAP:
                        take = min(_OUTPUT_CAP - len(buf), len(chunk))
                        if take:
                            buf.extend(chunk[:take])
            except Exception as e:
                LOG.debug("drain(%s) ended: %r", label, e)

        drain_out = asyncio.create_task(drain(proc.stdout, stdout_buf, "stdout"))
        drain_err = asyncio.create_task(drain(proc.stderr, stderr_buf, "stderr"))

        try:
            await asyncio.wait_for(proc.wait(), timeout=CONNECTION_TIMEOUT)

            await asyncio.gather(drain_out, drain_err, return_exceptions=True)

            out = stdout_buf.decode(errors="ignore")
            err = stderr_buf.decode(errors="ignore")
            duration = time.perf_counter() - start

            if "no cipher match" in err.lower():
                status = "unsupported"
            else:
                status = "ok" if cipher_supported(out) else "fail"

        except asyncio.TimeoutError:
            try:
                if proc.pid is not None:
                    with contextlib.suppress(Exception):
                        os.killpg(proc.pid, signal.SIGKILL)
                with contextlib.suppress(Exception):
                    proc.kill()
            finally:
                with contextlib.suppress(Exception):
                    await proc.communicate()
                for t in (drain_out, drain_err):
                    t.cancel()
                await asyncio.gather(drain_out, drain_err, return_exceptions=True)

            out = err = ""
            status = "timeout"
            duration = None

        except asyncio.CancelledError:
            try:
                if proc.pid is not None:
                    with contextlib.suppress(Exception):
                        os.killpg(proc.pid, signal.SIGKILL)
                with contextlib.suppress(Exception):
                    proc.kill()
            finally:
                with contextlib.suppress(Exception):
                    await proc.communicate()
                for t in (drain_out, drain_err):
                    t.cancel()
                await asyncio.gather(drain_out, drain_err, return_exceptions=True)
            raise

        except Exception as exc:
            try:
                if proc.returncode is None:
                    if proc.pid is not None:
                        with contextlib.suppress(Exception):
                            os.killpg(proc.pid, signal.SIGKILL)
                    with contextlib.suppress(Exception):
                        proc.kill()
            finally:
                with contextlib.suppress(Exception):
                    await proc.communicate()
                for t in (drain_out, drain_err):
                    t.cancel()
                await asyncio.gather(drain_out, drain_err, return_exceptions=True)

            out = ""
            err = str(exc)
            status = "error"
            duration = None

        LOG.debug(
            "%s:%s %s %s %s (kept %d/%d bytes out/err)",
            host,
            port,
            tls_flag,
            cipher,
            status,
            len(stdout_buf),
            len(stderr_buf),
        )

        return CipherResult(cipher, status, tls_flag, out, err, duration=duration)


# Pure helper
import re


def cipher_supported(output: str) -> bool:
    if "SSL-Session:" in output:
        return bool(re.search(r"Cipher\s*:\s*(?!0000)\S+", output))
    if "New, TLSv1.3, Cipher is" in output:
        return bool(re.search(r"New,\s*TLSv1\.3,\s*Cipher is\s+(\S+)", output))
    return False
