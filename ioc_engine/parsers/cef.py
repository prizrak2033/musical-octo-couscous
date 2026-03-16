"""CEF (ArcSight Common Event Format) log parser.

CEF header format:
  CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension

Extension is a space-separated list of ``key=value`` pairs.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, Iterator, Optional

from ..models import LogEntry
from .base import BaseLogParser, extract_observables

_RE_CEF = re.compile(
    r"^(?:.*?)?CEF:(?P<version>\d+)"
    r"\|(?P<vendor>[^|]*)"
    r"\|(?P<product>[^|]*)"
    r"\|(?P<dev_version>[^|]*)"
    r"\|(?P<sig_id>[^|]*)"
    r"\|(?P<name>[^|]*)"
    r"\|(?P<severity>[^|]*)"
    r"\|(?P<ext>.*)$",
    re.IGNORECASE,
)

# Parse extension key=value pairs (values may be quoted or multi-word up to next key=)
_RE_EXT_PAIR = re.compile(r"(\w+)=((?:(?![\w]+=).)+)")

_TS_KEYS = {"rt", "start", "end", "deviceReceiptTime"}
_SRC_IP_KEYS = {"src", "sourceAddress"}
_DST_IP_KEYS = {"dst", "destinationAddress"}
_SRC_PORT_KEYS = {"spt", "sourcePort"}
_DST_PORT_KEYS = {"dpt", "destinationPort"}
_URL_KEYS = {"request", "requestURL"}
_USER_KEYS = {"suser", "sourceUserName", "duser", "destinationUserName"}
_DOMAIN_KEYS = {"shost", "sourceHostName", "dhost", "destinationHostName"}


def _parse_ext(ext_str: str) -> Dict[str, str]:
    return {m.group(1): m.group(2).strip() for m in _RE_EXT_PAIR.finditer(ext_str)}


def _parse_ts(ext: Dict[str, str]) -> Optional[datetime]:
    for key in _TS_KEYS:
        raw = ext.get(key)
        if raw:
            # Epoch milliseconds
            if raw.isdigit():
                try:
                    return datetime.fromtimestamp(int(raw) / 1000, tz=timezone.utc)
                except (ValueError, OSError):
                    pass
            # ISO-ish
            try:
                return datetime.fromisoformat(raw)
            except ValueError:
                pass
    return None


class CEFLogParser(BaseLogParser):
    """Parse ArcSight CEF log lines."""

    name = "cef"

    def parse_file(self, path: str) -> Iterator[LogEntry]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = self.parse_line(line.rstrip("\n"))
                if entry is not None:
                    yield entry

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        m = _RE_CEF.match(line)
        if not m:
            return None

        ext = _parse_ext(m.group("ext"))
        ts = _parse_ts(ext)

        src_ip = next((ext[k] for k in _SRC_IP_KEYS if k in ext), None)
        dst_ip = next((ext[k] for k in _DST_IP_KEYS if k in ext), None)
        url = next((ext[k] for k in _URL_KEYS if k in ext), None)
        username = next((ext[k] for k in _USER_KEYS if k in ext), None)
        domain = next((ext[k] for k in _DOMAIN_KEYS if k in ext), None)

        obs = extract_observables(m.group("ext"))
        extra_ips = [ip for ip in obs["ips"] if ip not in (src_ip, dst_ip)]
        extra_domains = [d for d in obs["domains"] if d != domain]

        hashes: list = []
        for key in ("fileHash", "oldFileHash", "cs6"):
            v = ext.get(key)
            if v:
                hashes.append(v)
        if not hashes:
            hashes = obs["hashes"]

        return LogEntry(
            raw=line,
            timestamp=ts,
            source_ip=src_ip,
            dest_ip=dst_ip,
            domain=domain,
            url=url,
            username=username,
            hashes=hashes,
            emails=obs["emails"],
            extra_ips=extra_ips,
            extra_domains=extra_domains,
            log_source=self.name,
            metadata={
                "vendor": m.group("vendor"),
                "product": m.group("product"),
                "sig_id": m.group("sig_id"),
                "name": m.group("name"),
                "severity": m.group("severity"),
                **ext,
            },
        )
