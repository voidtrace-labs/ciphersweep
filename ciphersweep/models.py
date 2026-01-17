from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, List
import json


@dataclass
class CipherResult:
    cipher: str
    status: str  # ok / fail / timeout / unsupported / error
    tls_flag: str
    out: str
    err: str
    duration: Optional[float] = None


@dataclass
class HostScan:
    host: str
    ip: str
    port: int
    dnsbl_listed: Optional[bool]
    certificate: Optional[dict]
    http_compression: Optional[bool]
    supported_ciphers: Dict[str, Dict[str, List[str]]]
    vulnerabilities: List[str]
    grade: str

    # handy helpers
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def is_vulnerable(self) -> bool:
        return bool(self.vulnerabilities)
