# ciphersweep/constants.py

from pathlib import Path
import yaml

# runtime knobs
DEFAULT_PORT = 443
CONNECTION_TIMEOUT = 5
DNSBL_ZONE = "zen.spamhaus.org"

TLS_FLAGS = {
    "TLSv1": "-tls1",
    "TLSv1.1": "-tls1_1",
    "TLSv1.2": "-tls1_2",
    "TLSv1.3": "-tls1_3",
}


def load_cipher_matrix(file: Path | None = None) -> dict:
    file = file or Path(__file__).with_name("openssl_map.yaml")
    with file.open() as fh:
        return yaml.safe_load(fh)
