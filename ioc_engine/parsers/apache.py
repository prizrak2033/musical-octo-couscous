"""Apache/Nginx Combined Log Format parser."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator, Optional

from ..models import LogEntry
from .base import BaseLogParser, extract_observables

# 1.2.3.4 - user [15/Mar/2026:10:00:01 +0000] "GET /path HTTP/1.1" 200 1234 "ref" "UA"
_RE_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_ts(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(raw, _TS_FMT)
    except ValueError:
        return None


class ApacheLogParser(BaseLogParser):
    """Parse Apache/Nginx Combined Log Format."""

    name = "apache"

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

        m = _RE_COMBINED.match(line)
        if not m:
            # Fallback: still try to extract observables
            obs = extract_observables(line)
            ips = obs["ips"]
            return LogEntry(
                raw=line,
                source_ip=ips[0] if ips else None,
                extra_ips=ips[1:],
                url=obs["urls"][0] if obs["urls"] else None,
                domain=obs["domains"][0] if obs["domains"] else None,
                extra_domains=obs["domains"][1:],
                hashes=obs["hashes"],
                emails=obs["emails"],
                log_source=self.name,
            )

        ip = m.group("ip")
        ts = _parse_ts(m.group("time"))
        path_str = m.group("path")
        referer = m.group("referer") or ""
        ua = m.group("ua") or ""

        # Build a URL from path for domain/url extraction
        context = f"{path_str} {referer} {ua}"
        obs = extract_observables(context)

        return LogEntry(
            raw=line,
            timestamp=ts,
            source_ip=ip if ip != "-" else None,
            url=obs["urls"][0] if obs["urls"] else None,
            domain=obs["domains"][0] if obs["domains"] else None,
            extra_domains=obs["domains"][1:],
            hashes=obs["hashes"],
            emails=obs["emails"],
            user_agent=ua if ua else None,
            log_source=self.name,
            metadata={
                "method": m.group("method"),
                "path": path_str,
                "status": m.group("status"),
                "size": m.group("size"),
                "referer": referer,
            },
        )
