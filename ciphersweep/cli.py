# ciphersweep/cli.py

import typer, json, logging, asyncio
from tqdm import tqdm
from contextlib import nullcontext
from tqdm.contrib.logging import logging_redirect_tqdm
from pathlib import Path
from ciphersweep.scan.runner import run_all
from ciphersweep.io.openssl import set_openssl_limit
from ciphersweep.constants import DEFAULT_PORT

app = typer.Typer(add_completion=False)


class TqdmLoggingHandler(logging.Handler):

    def emit(self, record):
        try:
            tqdm.write(self.format(record))
        except Exception:
            self.handleError(record)


def parse_target(line: str) -> tuple[str, int] | None:

    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "://" in line:  # URL
        from urllib.parse import urlparse

        p = urlparse(line)
        if p.hostname:
            return p.hostname, p.port or DEFAULT_PORT
        return None

    if ":" in line:  # host:port
        host, port_str = line.rsplit(":", 1)
        if port_str.isdigit():
            return host, int(port_str)
        return None

    return line, DEFAULT_PORT


@app.command()
def scan(
    input: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Argument(...),
    *,
    openssl_prefix: Path = Path("./openssl-builds/build"),
    hosts: int = typer.Option(20, help="Max concurrent hosts (default: 20)"),
    procs: int = typer.Option(
        32, help="Max concurrent openssl processes (default: 32)"
    ),
    dnsbl: bool = typer.Option(False, help="Query Spamhaus zen.dnsbl.org"),
    breach: bool = typer.Option(False, help="Check HTTP compression (BREACH)"),
    debug: bool = typer.Option(False, help="Verbose logging"),
):

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    root.handlers.clear()
    h = TqdmLoggingHandler()
    h.setFormatter(
        logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s", "%H:%M:%S")
    )
    root.addHandler(h)

    targets: list[tuple[str, int]] = []
    for ln in input.read_text().splitlines():
        parsed = parse_target(ln)
        if parsed:
            targets.append(parsed)
        else:
            typer.echo(f"Skipping unparseable line: {ln}", err=True)

    if not targets:
        typer.secho("No valid targets found – exiting.", fg="red")
        raise typer.Exit(code=1)

    set_openssl_limit(procs)

    results = asyncio.run(
        run_all(
            targets,
            host_concurrency=hosts,
            openssl_prefix=openssl_prefix,
            dnsbl=dnsbl,
            breach=breach,
        )
    )

    output.write_text(json.dumps([r.__dict__ for r in results], indent=2))
    typer.secho(f"Wrote {len(results)} result(s) to {output}", fg="green")


if __name__ == "__main__":
    app()
