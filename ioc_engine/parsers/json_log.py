"""JSON-lines log parser.

Accepts files where each line is a JSON object (JSON-lines / NDJSON) **or**
a single JSON array of objects.

Field mapping (tries common key names, falls back to observable extraction):
  - timestamp : ts, time, timestamp, @timestamp, date
  - source IP  : src, src_ip, sourceip, source_ip, clientip, remote_addr
  - dest IP    : dst, dst_ip, dest_ip, destip, serverip
  - domain     : domain, hostname, host, fqdn
  - URL        : url, uri, request_url
  - user agent : user_agent, useragent, ua
  - username   : user, username, account
  - hashes     : hash, md5, sha1, sha256, file_hash
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from ..models import LogEntry
from .base import BaseLogParser, extract_observables

logger = logging.getLogger(__name__)

_TS_KEYS = ("ts", "time", "timestamp", "@timestamp", "date", "datetime")
_SRC_IP_KEYS = ("src", "src_ip", "sourceip", "source_ip", "clientip", "remote_addr", "client_ip")
_DST_IP_KEYS = ("dst", "dst_ip", "dest_ip", "destip", "serverip", "server_ip")
_DOMAIN_KEYS = ("domain", "hostname", "host", "fqdn", "server_name")
_URL_KEYS = ("url", "uri", "request_url", "http_url", "request")
_UA_KEYS = ("user_agent", "useragent", "ua", "http_user_agent", "agent")
_USER_KEYS = ("user", "username", "account", "login", "user_name")
_HASH_KEYS = ("hash", "md5", "sha1", "sha256", "file_hash", "filehash")


def _first(d: Dict[str, Any], keys) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if v:
            return str(v)
    return None


def _parse_ts(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # ISO fromisoformat fallback (Python 3.7+)
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


class JSONLogParser(BaseLogParser):
    """Parse JSON-lines or JSON-array log files."""

    name = "json"

    def parse_file(self, path: str) -> Iterator[LogEntry]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()

        if raw.startswith("["):
            try:
                records = json.loads(raw)
                for rec in records:
                    entry = self._record_to_entry(rec)
                    if entry:
                        yield entry
                return
            except json.JSONDecodeError:
                pass

        # JSON-lines
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = self.parse_line(line)
            if entry is not None:
                yield entry

    def parse_line(self, line: str) -> Optional[LogEntry]:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("JSONLogParser: could not parse line: %.80s", line)
            return None
        return self._record_to_entry(rec)

    # ------------------------------------------------------------------
    def _record_to_entry(self, rec: Dict[str, Any]) -> Optional[LogEntry]:
        if not isinstance(rec, dict):
            return None

        ts = _parse_ts(_first(rec, _TS_KEYS))
        src_ip = _first(rec, _SRC_IP_KEYS)
        dst_ip = _first(rec, _DST_IP_KEYS)
        domain = _first(rec, _DOMAIN_KEYS)
        url = _first(rec, _URL_KEYS)
        ua = _first(rec, _UA_KEYS)
        username = _first(rec, _USER_KEYS)

        hashes: List[str] = []
        for k in _HASH_KEYS:
            v = rec.get(k)
            if v:
                hashes.append(str(v))

        # Also extract from the full JSON text to catch embedded IOCs
        full_text = json.dumps(rec)
        obs = extract_observables(full_text)

        # Merge extracted IPs (avoid duplicates with explicit src/dst)
        extra_ips = [ip for ip in obs["ips"] if ip not in (src_ip, dst_ip)]
        extra_domains = [d for d in obs["domains"] if d != domain]
        emails = obs["emails"]
        if not hashes:
            hashes = obs["hashes"]

        return LogEntry(
            raw=full_text,
            timestamp=ts,
            source_ip=src_ip,
            dest_ip=dst_ip,
            domain=domain,
            url=url,
            user_agent=ua,
            username=username,
            hashes=hashes,
            emails=emails,
            extra_ips=extra_ips,
            extra_domains=extra_domains,
            log_source=self.name,
            metadata=rec,
        )
